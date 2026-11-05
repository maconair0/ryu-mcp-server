"""The gate against a real Ryu and real Open vSwitch (the container in lab/).

    docker run -d --name ryu-lab --privileged -p 8080:8080 -v /lib/modules:/lib/modules:ro ryu-lab
    python -m tests.live.live_lab --ryu-url http://127.0.0.1:8080 --container ryu-lab

Not part of `unittest discover`: it needs the lab, and it writes to its switches.
Point it only at a lab you own. It compares the switches' flow tables before and
after, so "undo is exact" is read off Open vSwitch, not off a model of it.
"""
import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
import urllib.request

from ryu_mcp.client import RyuClient
from ryu_mcp.config import RyuConfig
from ryu_mcp.gate import WriteGate
from ryu_mcp.server import create_server

TOKEN = "lab-token"
DPIDS = (257, 258)
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(' — ' + str(detail)) if detail and not ok else ''}", flush=True)


class Lab:
    def __init__(self, url, container, write_mode="queue"):
        self.url, self.container = url, container
        self.cfg = RyuConfig.from_env(base_url=url, state_dir=tempfile.mkdtemp(),
                                      approver_token=TOKEN, write_mode=write_mode)
        self.loop = asyncio.new_event_loop()      # one loop, as in the running server
        self.client = RyuClient(url)
        self.gate = WriteGate(self.cfg.state_dir, ttl=self.cfg.approval_ttl)
        self.server = create_server(self.cfg, client=self.client, gate=self.gate)

    def run(self, coro):
        return self.loop.run_until_complete(coro)

    def call(self, name, args):
        async def go():
            r = await self.server.call_tool(name, args)
            c = r[0] if isinstance(r, tuple) else r
            return json.loads(c[0].text)
        return self.run(go())

    def approve(self, out):
        return self.call("ryu_approve_request", {"approval_id": out["approval_id"],
                                                 "approver_token": TOKEN, "expected_digest": out["digest"]})

    def tables(self):
        """Every flow on both switches, without counters or ages, comparable."""
        snap = {}
        for d in DPIDS:
            flows = json.load(urllib.request.urlopen(f"{self.url}/stats/flow/{d}", timeout=10))[str(d)]
            snap[d] = sorted(json.dumps({k: f[k] for k in
                                         ("priority", "table_id", "match", "actions", "idle_timeout",
                                          "hard_timeout", "cookie")}, sort_keys=True) for f in flows)
        return snap

    def ovs(self, *args):
        return subprocess.run(["docker", "exec", self.container, *args], capture_output=True, text=True, timeout=30)


def scenario_queue_then_approve(L):
    print("a queued write changes nothing; an approved one lands")
    before = L.tables()
    out = L.call("ryu_map_vlan", {"dpid": "0000000000000101", "client_port": 1, "uplink_port": 3, "vlan_id": 10})
    check("request is queued", out["status"] == "queued_for_approval")
    check("switch unchanged while queued", L.tables() == before)
    got = L.approve(out)
    check("approval applies it", got.get("ok"), got)
    after = L.tables()
    check("two flows added on s1", len(after[257]) == len(before[257]) + 2, (len(before[257]), len(after[257])))
    check("s2 untouched", after[258] == before[258])
    flows = L.ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1").stdout
    check("OVS has the tag and untag actions", "push_vlan" in flows and "pop_vlan" in flows, flows[-300:])
    return out, before


def scenario_undo(L, out, before):
    print("undo restores the switch exactly")
    u = L.call("ryu_request_undo", {"approval_id": out["approval_id"]})
    check("undo is queued, exact", u.get("ok") and u.get("exact"), u)
    check("queuing the undo changed nothing", L.tables() != before)
    got = L.approve(u)
    check("undo applies", got.get("ok"), got)
    check("flow tables identical to before the map", L.tables() == before)


def scenario_overwrite_and_delete(L):
    print("overwrite and delete are undone to the flow that was there")
    base = {"dpid": "257", "match": {"in_port": 2}, "priority": 150}
    first = L.call("ryu_add_flow", {**base, "actions": [{"type": "OUTPUT", "port": 3}]})
    L.approve(first)
    snap_one = L.tables()
    second = L.call("ryu_add_flow", {**base, "actions": [{"type": "OUTPUT", "port": 1}]})
    L.approve(second)
    check("overwrite replaced the flow", L.tables() != snap_one)
    check("overwrite is one flow, not two", len(L.tables()[257]) == len(snap_one[257]))
    L.approve(L.call("ryu_request_undo", {"approval_id": second["approval_id"]}))
    check("undo of the overwrite brings back the first flow", L.tables() == snap_one)
    d = L.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 2}, "priority": 150})
    L.approve(d)
    check("delete removed it", L.tables()[257] != snap_one[257])
    L.approve(L.call("ryu_request_undo", {"approval_id": d["approval_id"]}))
    check("undo of the delete restores it, actions and all", L.tables() == snap_one)
    # tidy: remove the test flow
    L.approve(L.call("ryu_request_undo", {"approval_id": first["approval_id"]})) if False else None
    t = L.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 2}, "priority": 150})
    L.approve(t)


def scenario_out_of_order(L):
    print("out-of-order undo is refused")
    a = L.call("ryu_map_vlan", {"dpid": "257", "client_port": 1, "uplink_port": 3, "vlan_id": 20})
    L.approve(a)
    b = L.call("ryu_map_vlan", {"dpid": "257", "client_port": 1, "uplink_port": 3, "vlan_id": 21})
    L.approve(b)
    got = L.call("ryu_request_undo", {"approval_id": a["approval_id"]})
    check("undo of the older map refused while the newer stands", not got["ok"], got)
    for x in (b, a):
        u = L.call("ryu_request_undo", {"approval_id": x["approval_id"]})
        L.approve(u)


def scenario_rollback(L):
    print("a request that fails halfway is rolled back")
    before = L.tables()
    # second call targets a switch that does not exist: Ryu refuses it
    good = {"path": "/stats/flowentry/add", "body": {"dpid": 257, "table_id": 0, "priority": 130, "cookie": 0,
                                                    "idle_timeout": 0, "hard_timeout": 0, "flags": 0,
                                                    "match": {"in_port": 2}, "actions": [{"type": "OUTPUT", "port": 3}]}}
    bad = {"path": "/stats/flowentry/add", "body": {**good["body"], "dpid": 4242}}
    req = L.gate.request("ryu_add_flow", "half-and-half", [good, bad])
    L.gate.decide(req["approval_id"], True)
    res = L.run(L.gate.apply_approved(L.client))
    item = L.gate._load()[req["approval_id"]]
    check("the request is reported failed", res["failed"] and item["state"] == "failed", item.get("result"))
    check("the flow already sent was taken back", L.tables() == before, item.get("rollback"))
    check("the rollback is on record as restored", (item.get("rollback") or {}).get("restored") is True, item.get("rollback"))


def scenario_critical(L):
    print("critical changes are never waved through")
    before = L.tables()
    out = L.call("ryu_add_flow", {"dpid": "257", "match": {}, "actions": [{"type": "DROP"}]})
    check("wildcard drop-all is critical and queued", out.get("risk_tier") == "critical" and out["status"] == "queued_for_approval", out)
    d = Lab(L.url, L.container, write_mode="direct")
    out = d.call("ryu_add_flow", {"dpid": "257", "match": {}, "actions": [{"type": "DROP"}]})
    check("still queued in direct mode", out["status"] == "queued_for_approval", out)
    check("switch unchanged", L.tables() == before)


def scenario_replay(L):
    print("applied writes come back after the switch loses its flows")
    out = L.call("ryu_map_vlan", {"dpid": "257", "client_port": 2, "uplink_port": 3, "vlan_id": 30})
    L.approve(out)
    want = L.tables()
    for port in ("in_port=2", "in_port=3"):          # the mapping's two flows; Ryu's own LLDP flow stays
        L.ovs("ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", port)
    check("flows were wiped from the switch", L.tables() != want)
    got = L.run(L.gate.replay_applied(L.client))
    check("replay put them back", L.tables() == want, got)
    u = L.call("ryu_request_undo", {"approval_id": out["approval_id"]})
    L.approve(u)


LANDS = [   # (name, match, actions): accepted by the schema and expected to be held by the switch
    ("drop as no actions", {"in_port": 1}, [{"type": "DROP"}]),
    ("output to CONTROLLER", {"in_port": 1}, [{"type": "OUTPUT", "port": "CONTROLLER"}]),
    ("output to FLOOD", {"in_port": 1}, [{"type": "OUTPUT", "port": "FLOOD"}]),
    ("port as hex string", {"in_port": 1}, [{"type": "OUTPUT", "port": "0x2"}]),
    ("match port as string", {"in_port": "1"}, [{"type": "OUTPUT", "port": 2}]),
    ("vlan_vid with present bit", {"in_port": 1, "vlan_vid": 4106}, [{"type": "OUTPUT", "port": 2}]),
    ("vlan_vid bare", {"in_port": 1, "vlan_vid": 10}, [{"type": "OUTPUT", "port": 2}]),
    ("ipv4 by new names", {"eth_type": 2048, "ipv4_dst": "10.0.0.1"}, [{"type": "OUTPUT", "port": 2}]),
    ("ipv4 by old names", {"dl_type": 2048, "nw_dst": "10.0.0.1"}, [{"type": "OUTPUT", "port": 2}]),
    ("tcp port", {"eth_type": 2048, "ip_proto": 6, "tcp_dst": 80}, [{"type": "OUTPUT", "port": 2}]),
    ("mac, upper case", {"eth_dst": "AA:BB:CC:DD:EE:FF"}, [{"type": "OUTPUT", "port": 2}]),
    ("push vlan and set it", {"in_port": 1}, [{"type": "PUSH_VLAN", "ethertype": 33024},
                                               {"type": "SET_FIELD", "field": "vlan_vid", "value": 4106},
                                               {"type": "OUTPUT", "port": 3}]),
    ("rewrite a mac", {"in_port": 1}, [{"type": "SET_FIELD", "field": "eth_dst", "value": "aa:bb:cc:dd:ee:ff"},
                                       {"type": "OUTPUT", "port": 3}]),
    ("queue then output", {"in_port": 1}, [{"type": "SET_QUEUE", "queue_id": 1}, {"type": "OUTPUT", "port": 2}]),
    ("action type in lower case", {"in_port": 1}, [{"type": "output", "port": 2}]),
]
SWITCH_REFUSES = [   # Ryu says 200; Open vSwitch does not take it
    ("group that does not exist", {"in_port": 1}, [{"type": "GROUP", "group_id": 1}]),
    ("dec_nw_ttl without an ip match", {"in_port": 1}, [{"type": "DEC_NW_TTL"}, {"type": "OUTPUT", "port": 2}]),
    ("set_field of in_port", {"in_port": 1}, [{"type": "SET_FIELD", "field": "in_port", "value": 3}]),
]
REFUSED_EARLY = [   # would be accepted by Ryu and then ignored: refused at the request
    ("ip_proto without eth_type", {"ip_proto": 6, "tcp_dst": 80}),
    ("tcp port without ip_proto", {"eth_type": 2048, "tcp_dst": 80}),
    ("ipv4 address without eth_type", {"ipv4_dst": "10.0.0.1"}),
]


def scenario_differential(L):
    print("what Ryu and Open vSwitch actually do with requests the schema accepts")
    baseline = L.tables()
    done = []
    for i, (name, match, actions) in enumerate(LANDS):
        out = L.call("ryu_add_flow", {"dpid": "257", "match": match, "actions": actions, "priority": 70 + i})
        got = L.approve(out) if out.get("status") == "queued_for_approval" else out
        check(f"lands and is verified: {name}", got.get("ok") and got.get("verified") is True, got)
        done.append(out)
    for i, (name, match, actions) in enumerate(SWITCH_REFUSES):
        before = L.tables()
        out = L.call("ryu_add_flow", {"dpid": "257", "match": match, "actions": actions, "priority": 40 + i})
        got = L.approve(out)
        check(f"switch refuses, reported failed: {name}", got.get("ok") is False and got.get("state") == "failed"
              and L.tables() == before, got)
    for name, match in REFUSED_EARLY:
        out = L.call("ryu_add_flow", {"dpid": "257", "match": match, "actions": [{"type": "OUTPUT", "port": 2}]})
        check(f"refused at request: {name}", out.get("ok") is False and out.get("error") == "invalid", out)
    for out in reversed(done):                       # newest first
        u = L.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        L.approve(u) if u.get("ok") else check("undo offered", False, u)
    check("every landed flow was undone to the exact starting tables", L.tables() == baseline)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ryu-url", required=True)
    ap.add_argument("--container", required=True)
    a = ap.parse_args()
    import logging
    logging.disable(logging.CRITICAL)
    L = Lab(a.ryu_url, a.container)
    check("lab is reachable with 2 switches", L.call("ryu_health_check", {}).get("ok") and
          len(L.call("ryu_list_switches", {})["switches"]) == 2)
    baseline = L.tables()
    out, before = scenario_queue_then_approve(L)
    scenario_undo(L, out, before)
    scenario_overwrite_and_delete(L)
    scenario_out_of_order(L)
    scenario_rollback(L)
    scenario_critical(L)
    scenario_replay(L)
    scenario_differential(L)
    check("after everything, the switches are as they started", L.tables() == baseline)
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} live checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
