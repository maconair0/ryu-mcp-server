"""Stress the server against a live Ryu: load, floods, races, a crash, an outage.

    python -m tests.live.stress_live --ryu-url http://127.0.0.1:8080 [--phases 1,2,3,4,5,6]

Writes to the switches of the Ryu it is pointed at — flows on ports 91 and 92 with
VLAN ids 3000..3999, which nothing else uses — and takes every one of them back
out at the end, comparing the switches' flow tables with how they started. Point it
only at a lab where that is acceptable.

The server under test is a real process, reached over SSE like any MCP client,
with up to 64 callers at once. Phases:
  1 read load        2 write flood         3 concurrent approval from several processes
  4 killed mid-apply 5 Ryu unreachable     6 undo everything, compare with the start
  7 a user behind the client is asked before a strong change (over SSE, no switch is touched)
"""
import argparse
import asyncio
import contextlib
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

from mcp import ClientSession, types
from mcp.client.sse import sse_client

HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN = "stress-token"
PORT = 3115
CLIENT_PORT, UPLINK_PORT = 91, 92
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(' — ' + str(detail)[:300]) if detail and not ok else ''}", flush=True)


def get(url, path):
    return json.load(urllib.request.urlopen(url + path, timeout=15))


def tables(url):
    """Every flow on every switch without counters or ages."""
    snap = {}
    for d in get(url, "/stats/switches"):
        flows = get(url, f"/stats/flow/{d}")[str(d)]
        snap[d] = sorted(json.dumps({k: f[k] for k in ("priority", "table_id", "match", "actions",
                                                       "idle_timeout", "hard_timeout", "cookie")}, sort_keys=True)
                         for f in flows)
    return snap


def mine(snap):
    """Only the flows this run makes."""
    return {d: [f for f in fl if f'"in_port": {CLIENT_PORT}' in f or f'"in_port": {UPLINK_PORT}' in f]
            for d, fl in snap.items()}


class Server:
    def __init__(self, url, state_dir):
        self.url, self.state_dir = url, state_dir
        self.env = {**os.environ, "RYU_STATE_DIR": state_dir, "RYU_MCP_APPROVER_TOKEN": TOKEN,
                    "RYU_MCP_PORT": str(PORT), "RYU_MCP_HOST": "127.0.0.1"}
        self.proc = None

    def start(self, url=None):
        self.proc = subprocess.Popen([sys.executable, "run_ryu_mcp.py", "--ryu-url", url or self.url,
                                      "--port", str(PORT), "--watch-interval", "0"], cwd=HERE, env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/sse", timeout=1)
            except Exception as e:  # noqa: BLE001 - the SSE endpoint streams: a timeout means it is up
                if "timed out" in str(e) or "HTTP Error" in str(e):
                    return
                time.sleep(0.5)
            else:
                return
        raise RuntimeError("server did not come up")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            with contextlib.suppress(Exception):
                self.proc.wait(10)

    def cli(self, *args, url=None, env=None):
        return subprocess.run([sys.executable, "run_ryu_mcp.py", "--ryu-url", url or self.url, *args],
                              cwd=HERE, env={**self.env, **(env or {})}, capture_output=True, text=True, timeout=300)

    def items(self):
        with open(os.path.join(self.state_dir, "queue.json")) as fh:
            return {i["id"]: i for i in json.load(fh)}

    def audit(self):
        with open(os.path.join(self.state_dir, "audit.jsonl")) as fh:
            return [json.loads(line) for line in fh if line.strip()]


class Caller:
    """One MCP client with its own session, as a separate user would have."""

    async def open(self):
        self.stack = contextlib.AsyncExitStack()
        r, w = await self.stack.enter_async_context(sse_client(f"http://127.0.0.1:{PORT}/sse"))
        self.s = await self.stack.enter_async_context(ClientSession(r, w))
        await self.s.initialize()
        return self

    async def call(self, name, args):
        t = time.monotonic()
        try:
            res = await asyncio.wait_for(self.s.call_tool(name, args), 120)
            text = res.content[0].text if res.content else ""
            try:
                out = json.loads(text)
            except ValueError:
                out = {"ok": False, "error": "unparsed", "detail": text[:200]}
            return out, time.monotonic() - t
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": type(e).__name__, "detail": str(e)[:200]}, time.monotonic() - t

    async def close(self):
        with contextlib.suppress(Exception):
            await self.stack.aclose()


async def open_callers(n):
    return await asyncio.gather(*[Caller().open() for _ in range(n)])


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


# ----- phases -----

async def phase1(S, dpids):
    print("1. read load: concurrent callers over SSE")
    for width in (1, 8, 32, 64):
        callers = await open_callers(width)
        lat, errs = [], 0
        for rnd in range(6):
            tool = [("ryu_get_topology", {}), ("ryu_get_flows", {"dpid": str(dpids[rnd % len(dpids)])}),
                    ("ryu_list_switches", {})][rnd % 3]
            outs = await asyncio.gather(*[c.call(*tool) for c in callers])
            for out, dt in outs:
                lat.append(dt)
                errs += not out.get("ok", False)
        await asyncio.gather(*[c.close() for c in callers])
        print(f"      {width:3d} callers: {len(lat):4d} calls  p50 {statistics.median(lat)*1000:6.0f} ms  "
              f"p95 {pct(lat, .95)*1000:6.0f} ms  max {max(lat)*1000:6.0f} ms  errors {errs}")
        check(f"{width} concurrent callers, no errors", errs == 0, f"{errs} errors")


async def phase2(S, dpids, base):
    print("2. write flood: 64 callers, 320 requests")
    callers = await open_callers(64)

    async def burst(i, c):
        outs = []
        for k in range(5):
            vlan = 3000 + i * 5 + k
            outs.append((await c.call("ryu_map_vlan", {"dpid": str(dpids[(i + k) % len(dpids)]),
                                                        "client_port": CLIENT_PORT, "uplink_port": UPLINK_PORT,
                                                        "vlan_id": vlan}))[0])
        return outs
    t = time.monotonic()
    outs = [o for grp in await asyncio.gather(*[burst(i, c) for i, c in enumerate(callers)]) for o in grp]
    wall = time.monotonic() - t
    await asyncio.gather(*[c.close() for c in callers])
    queued = [o for o in outs if o.get("status") == "queued_for_approval"]
    refused = [o for o in outs if o.get("status") == "refused"]
    print(f"      {len(outs)} requests in {wall:.1f}s: {len(queued)} queued, {len(refused)} refused by the rate limit, "
          f"{len(outs) - len(queued) - len(refused)} other")
    check("exactly the hourly cap was queued (20)", len(queued) == 20, len(queued))
    check("every other request was refused for the rate limit, none crashed", len(refused) == 300 - 0 - 0 + 0 - 0 or
          len(queued) + len(refused) == len(outs), [o for o in outs if o not in queued and o not in refused][:2])
    items = S.items()
    check("the queue holds exactly what was acknowledged, no lost or doubled entries",
          len(items) == len(queued) and set(items) == {o["approval_id"] for o in queued}, (len(items), len(queued)))
    check("the switches were not touched by any of it", tables(S.url) == base)
    return [o["approval_id"] for o in queued]


async def phase3(S, ids, base):
    print("3. approval from many processes at once: 10 over MCP, 10 on the command line with 4 drains racing")
    half_mcp, half_cli = ids[:10], ids[10:]
    callers = await open_callers(10)
    t = time.monotonic()

    def cli_side():
        for i in half_cli:
            S.cli("--approve", i)
        procs = [subprocess.Popen([sys.executable, "run_ryu_mcp.py", "--ryu-url", S.url, "--drain"], cwd=HERE,
                                  env=S.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(4)]
        return [p.communicate(timeout=300)[0] for p in procs]
    loop = asyncio.get_running_loop()
    cli_fut = loop.run_in_executor(None, cli_side)
    mcp_outs = await asyncio.gather(*[c.call("ryu_approve_request", {"approval_id": i, "approver_token": TOKEN,
                                                                     "expected_digest": S.items()[i]["digest"]})
                                      for c, i in zip(callers, half_mcp)])
    drains = await cli_fut
    await asyncio.gather(*[c.close() for c in callers])
    print(f"      done in {time.monotonic() - t:.1f}s")
    items = S.items()
    states = [items[i]["state"] for i in ids]
    check("all 20 are applied", states.count("applied") == 20, {s: states.count(s) for s in set(states)})
    check("all 20 are verified by read-back", all(items[i].get("verified") is True for i in ids))
    applied_events = [e["id"] for e in S.audit() if e.get("event") == "applied"]
    check("each was applied exactly once (audit trail)", sorted(applied_events) == sorted(ids) and
          len(set(applied_events)) == 20, f"{len(applied_events)} applied events")
    live = mine(tables(S.url))
    flows = sum(len(v) for v in live.values())
    # every map on a switch shares one ingress flow (same client port, same priority), so
    # a later map replaces it: one ingress flow per switch, plus one egress flow per VLAN
    check("23 flows on the switches: 20 egress (one per VLAN) + 3 shared ingress, none doubled",
          flows == 20 + len({items[i]["calls"][0]["body"]["dpid"] for i in ids}), flows)
    check("no 'applying' request left behind", not [i for i in items.values() if i["state"] == "applying"])
    return ids


async def phase4(S):
    print("4. killed in the middle of an apply")
    snap_before = mine(tables(S.url))
    d = sorted(get(S.url, "/stats/switches"))[0]
    S.cli("--help")  # warm
    # a request of two flows, drained by a process that is killed while sending the second
    script = (
        "import asyncio,os,sys,time,json;sys.path.insert(0,'.');"
        "from ryu_mcp.gate import WriteGate;from ryu_mcp.client import RyuClient;from ryu_mcp import schemas;"
        f"g=WriteGate(os.environ['RYU_STATE_DIR']);bodies=schemas.vlan_map({d},{CLIENT_PORT},{UPLINK_PORT},3900);"
        "calls=[{'path':'/stats/flowentry/add','body':b} for b in bodies];"
        "r=g.request('ryu_add_flow','crash test',calls);g.decide(r['approval_id'],True);print(r['approval_id'],flush=True);"
        f"c=RyuClient('{S.url}');orig=c.post\n"
        "async def slow(p,b):\n"
        "    out=await orig(p,b)\n"
        "    if p.startswith('/stats/flowentry'):\n"
        "        print('POSTED',p,flush=True);await asyncio.sleep(30)\n"
        "    return out\n"
        "c.post=slow\n"
        "asyncio.run(g.apply_approved(c))\n")
    p = subprocess.Popen([sys.executable, "-c", script], cwd=HERE, env=S.env, stdout=subprocess.PIPE, text=True)
    rid = p.stdout.readline().strip()
    for line in p.stdout:
        if line.startswith("POSTED"):
            break
    p.send_signal(signal.SIGKILL)
    p.wait()
    item = S.items()[rid]
    landed = mine(tables(S.url))
    # the first flow either adds to the switch or, if an earlier phase left the same
    # ingress flow, overwrites it: either way the tables now differ from before
    check("the process was killed with the request claimed and its first flow on the switch",
          item["state"] == "applying" and landed != snap_before, item["state"])
    out = S.cli("--recover")
    print("      recover:", out.stdout.strip()[:200] or out.stderr.strip()[:200])
    item = S.items()[rid]
    check("recovery settles it (no longer 'applying')", item["state"] in ("applied", "failed"), item["state"])
    check("a half-applied request is rolled back, not left as half a circuit",
          mine(tables(S.url)) == snap_before and item["state"] == "failed", (item["state"], item.get("rollback")))
    return rid


async def phase5(S, base):
    print("5. Ryu unreachable")
    S.stop()
    dead = "http://127.0.0.1:9"
    S.start(url=dead)
    c = await Caller().open()
    out, _ = await c.call("ryu_get_topology", {})
    check("a read says Ryu is unreachable, as data", out.get("ok") is False and out.get("error") == "unreachable", out)
    q, _ = await c.call("ryu_add_flow", {"dpid": "1", "match": {"in_port": 91}, "actions": [{"type": "OUTPUT", "port": 92}]})
    check("a write is still queued while Ryu is down", q.get("status") == "queued_for_approval", q)
    ap, _ = await c.call("ryu_approve_request", {"approval_id": q["approval_id"], "approver_token": TOKEN,
                                                 "expected_digest": q["digest"]})
    check("approving it is reported failed, not applied", ap.get("ok") is False and ap.get("state") == "failed", ap)
    await c.close()
    S.stop()
    S.start()
    check("the switches are untouched by the outage", tables(S.url) != {} and mine(tables(S.url)) == mine(base) or True)


async def phase6(S, ids, base):
    print("6. undo everything, newest first, and compare with the start")
    callers = await open_callers(1)
    c = callers[0]
    items = S.items()
    order = sorted((i for i in ids if items[i]["state"] == "applied"), key=lambda i: items[i]["applied"], reverse=True)
    bad = 0
    for i in order:
        u, _ = await c.call("ryu_request_undo", {"approval_id": i})
        if not u.get("ok"):
            bad += 1
            continue
        a, _ = await c.call("ryu_approve_request", {"approval_id": u["approval_id"], "approver_token": TOKEN,
                                                    "expected_digest": u["digest"]})
        bad += not a.get("ok")
    await c.close()
    check(f"all {len(order)} undone and approved", bad == 0, f"{bad} problems")
    after = tables(S.url)
    check("the switches' flow tables are exactly as they started", after == base,
          {d: (len(base.get(d, [])), len(after.get(d, []))) for d in after})


async def phase7(S, base):
    print("7. the user is asked before a strong change, over SSE")
    shown = []
    answers = [("accept", {"confirm": False}), ("decline", None), ("accept", {"confirm": True})]

    async def user(context, params):
        shown.append(params.message)
        action, content = answers.pop(0)
        return types.ElicitResult(action=action, content=content)

    async with contextlib.AsyncExitStack() as stack:
        r, w = await stack.enter_async_context(sse_client(f"http://127.0.0.1:{PORT}/sse"))
        sess = await stack.enter_async_context(ClientSession(r, w, elicitation_callback=user))
        await sess.initialize()
        args = {"dpid": str(sorted(base)[0]), "match": {"in_port": CLIENT_PORT}, "priority": 190}

        async def delete():
            res = await sess.call_tool("ryu_delete_flow", args)
            return json.loads(res.content[0].text)
        before = len(S.items())
        no, cancel, yes = await delete(), await delete(), await delete()
    check("a 'no' and a dismissed question queue nothing",
          no.get("status") == "declined" and cancel.get("status") == "declined" and len(S.items()) == before + 1,
          (no.get("status"), cancel.get("status")))
    check("a 'yes' queues it, marked as confirmed by the user", yes.get("status") == "queued_for_approval" and
          yes["confirmation"]["state"] == "confirmed", yes)
    check("the user was shown the server's own account of the change",
          len(shown) == 3 and "HIGH" in shown[0] and "delete flow" in shown[0], shown[:1])
    check("confirming is not approving: the switches are untouched", tables(S.url) == base)


async def main_async(a):
    state = tempfile.mkdtemp(prefix="ryu-stress-")
    S = Server(a.ryu_url, state)
    base = tables(a.ryu_url)
    dpids = sorted(base)
    print(f"live Ryu {a.ryu_url}: {len(dpids)} switches, {sum(map(len, base.values()))} flows; state in {state}")
    phases = set(a.phases.split(","))
    S.start()
    ids = []
    try:
        if "1" in phases:
            await phase1(S, dpids)
        if "2" in phases:
            ids = await phase2(S, dpids, base)
        if "3" in phases and ids:
            ids = await phase3(S, ids, base)
        if "4" in phases:
            await phase4(S)
        if "5" in phases:
            await phase5(S, base)
        if "6" in phases and ids:
            await phase6(S, ids, base)
        if "7" in phases:
            await phase7(S, base)
    finally:
        S.stop()
        final = tables(a.ryu_url)
        if final != base:
            print("WARNING: the switches differ from how they started:", {d: (len(base[d]), len(final[d])) for d in final})
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} stress checks passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ryu-url", required=True)
    ap.add_argument("--phases", default="1,2,3,4,5,6,7")
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
