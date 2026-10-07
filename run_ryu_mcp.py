#!/usr/bin/env python3
"""Run the Ryu MCP server, check Ryu, or act on the approval queue."""
import argparse
import asyncio
import json
import sys
import time
import threading
import os

from ryu_mcp.client import RyuClient
from ryu_mcp.config import RyuConfig
from ryu_mcp.gate import WriteGate
from ryu_mcp.server import READ_TOOLS, WRITE_TOOLS, create_server


def start_replay_watch(cfg, gate, interval: int) -> None:
    """Replay applied writes whenever a switch connects (or reconnects).

    A restarted switch or lab comes back with no flows and nothing else in this
    system notices: Ryu holds no state of its own to push back. Watching the
    connected set is enough — a dpid that was absent last time and is present
    now has just connected, and the writes approved for the network are what it
    should hold.
    """
    def loop():
        seen: set = set()
        first = True
        while True:
            try:
                async def once():
                    c = RyuClient(cfg.base_url, cfg.timeout)
                    try:
                        now = set(await c.get("/stats/switches") or [])
                        fresh = now - seen
                        got = None
                        # On the first look every switch is "new"; replaying
                        # then is what makes a restart of this server harmless.
                        if fresh:
                            got = await gate.replay_applied(c)
                        return now, fresh, got
                    finally:
                        await c.close()
                now, fresh, got = asyncio.run(once())
                if fresh and got and (got["replayed"] or got["failed"]):
                    print(f"switch(es) {sorted(fresh)} connected"
                          f"{'' if first else ' again'}: replayed "
                          f"{len(got['replayed'])} write(s), {len(got['failed'])} failed",
                          file=sys.stderr)
                seen, first = now, False
            except Exception as e:  # noqa: BLE001 - Ryu down is a normal state
                seen = set()
                print(f"replay watch: Ryu not answering ({type(e).__name__})",
                      file=sys.stderr) if first else None
            time.sleep(interval)
    threading.Thread(target=loop, name="replay-watch", daemon=True).start()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ryu-url", help="Ryu REST base, e.g. http://127.0.0.1:8080")
    ap.add_argument("--port", type=int, help="this server's port (default 3005)")
    ap.add_argument("--transport", choices=("sse", "stdio"), default="sse")
    ap.add_argument("--check", action="store_true", help="probe Ryu and exit")
    ap.add_argument("--list-pending", action="store_true")
    ap.add_argument("--approve", metavar="ID")
    ap.add_argument("--reject", metavar="ID")
    ap.add_argument("--drain", action="store_true", help="install approved flows and exit")
    ap.add_argument("--watch-interval", type=int,
                    default=int(os.getenv("RYU_REPLAY_WATCH", "30")),
                    help="seconds between checks for a switch that reconnected "
                         "empty, whose applied writes are then replayed; 0 is off")
    ap.add_argument("--replay", action="store_true",
                    help="re-install every applied write, oldest first, after a "
                         "switch or the lab restarted, and exit")
    a = ap.parse_args(argv)
    cfg = RyuConfig.from_env(base_url=a.ryu_url.rstrip("/") if a.ryu_url else None,
                             mcp_port=a.port)
    gate = WriteGate(cfg.state_dir)

    if a.list_pending:
        print(json.dumps(gate.pending(), indent=1)); return 0
    if a.approve or a.reject:
        print(json.dumps(gate.decide(a.approve or a.reject, approve=bool(a.approve))))
        return 0
    if a.drain:
        async def drain():
            c = RyuClient(cfg.base_url, cfg.timeout)
            try:
                return await gate.apply_approved(c)
            finally:
                await c.close()
        print(json.dumps(asyncio.run(drain()))); return 0
    if a.replay:
        async def replay():
            c = RyuClient(cfg.base_url, cfg.timeout)
            try:
                return await gate.replay_applied(c)
            finally:
                await c.close()
        got = asyncio.run(replay())
        print(json.dumps(got)); return 0 if not got["failed"] else 1
    if a.check:
        async def check():
            c = RyuClient(cfg.base_url, cfg.timeout)
            try:
                return await c.get("/stats/switches")
            finally:
                await c.close()
        try:
            sw = asyncio.run(check())
            print(f"Ryu at {cfg.base_url}: reachable, {len(sw or [])} switch(es) connected")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"Ryu at {cfg.base_url}: NOT reachable ({e})"); return 1

    if a.watch_interval > 0 and a.transport != "stdio":
        start_replay_watch(cfg, gate, a.watch_interval)
    server = create_server(cfg, gate=gate)
    print(f"Ryu MCP server: {cfg.base_url}, writes={cfg.write_mode}", file=sys.stderr)
    print(f"  {len(READ_TOOLS)} read tools, {len(WRITE_TOOLS)} write tools", file=sys.stderr)
    if a.transport == "sse":
        print(f"  SSE endpoint: http://{cfg.mcp_host}:{cfg.mcp_port}/sse", file=sys.stderr)
    server.run(transport=a.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
