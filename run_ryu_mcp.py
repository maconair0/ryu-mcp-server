#!/usr/bin/env python3
"""Run the Ryu MCP server, check Ryu, or act on the approval queue."""
import argparse
import asyncio
import json
import sys

from ryu_mcp.client import RyuClient
from ryu_mcp.config import RyuConfig
from ryu_mcp.gate import WriteGate
from ryu_mcp.server import READ_TOOLS, WRITE_TOOLS, create_server


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

    server = create_server(cfg, gate=gate)
    print(f"Ryu MCP server: {cfg.base_url}, writes={cfg.write_mode}", file=sys.stderr)
    print(f"  {len(READ_TOOLS)} read tools, {len(WRITE_TOOLS)} write tools", file=sys.stderr)
    if a.transport == "sse":
        print(f"  SSE endpoint: http://{cfg.mcp_host}:{cfg.mcp_port}/sse", file=sys.stderr)
    server.run(transport=a.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
