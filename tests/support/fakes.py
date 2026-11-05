"""A switch behind Ryu's REST API, stateful enough to check what a write did.

`ofctl_rest` semantics this reproduces, from reading a live Ryu:

* `flowentry/add` with the same table, priority and match *overwrites* the flow
  already there — it does not add a second one;
* `flowentry/delete_strict` removes only the flow with that exact match and
  priority;
* `/stats/flow/<dpid>` is a POST, filters loosely by match, and reports actions
  as strings ("OUTPUT:3", "SET_FIELD: {vlan_vid:4198}"), while `flowentry/add`
  takes them as dicts.

Every request is logged, and `writes` is the subset that can change a switch.
"""
import json
from typing import Any, Dict, List

import httpx


# What a live Ryu 4.34 reports a match as, whichever way it was asked: written
# out here on its own, not borrowed from the code under test.
REPORTED = {"eth_type": "dl_type", "eth_src": "dl_src", "eth_dst": "dl_dst", "ipv4_src": "nw_src",
            "ipv4_dst": "nw_dst", "ip_proto": "nw_proto", "tcp_src": "tp_src", "tcp_dst": "tp_dst",
            "udp_src": "tp_src", "udp_dst": "tp_dst", "vlan_vid": "dl_vlan"}


def reported_match(match: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in (match or {}).items():
        name = REPORTED.get(k, k)
        if isinstance(v, str) and v.lower().startswith("0x"):
            v = int(v, 16)
        elif isinstance(v, str) and v.isdigit():
            v = int(v)
        if name == "dl_vlan":
            out[name] = str(int(v) & 0xFFF)          # Ryu prints the VLAN id as a string
        else:
            out[name] = v
    return out


def action_text(a: Dict[str, Any]) -> str:
    kind = str(a["type"]).upper()
    if kind == "OUTPUT":
        return f"OUTPUT:{a['port']}"
    if kind == "PUSH_VLAN":
        return f"PUSH_VLAN:{a['ethertype']}"
    if kind == "SET_FIELD":
        return f"SET_FIELD: {{{a['field']}:{a['value']}}}"
    if kind == "GROUP":
        return f"GROUP:{a['group_id']}"
    return kind


def flow_key(body: Dict[str, Any]):
    return (int(body.get("table_id", 0)), int(body.get("priority", 0)),
            json.dumps(reported_match(body.get("match")), sort_keys=True))


class FakeRyu:
    def __init__(self, dpids=(257, 258), down: bool = False):
        self.flows: Dict[int, Dict[Any, Dict[str, Any]]] = {d: {} for d in dpids}
        self.log: List[tuple] = []        # requests the switch accepted
        self.attempts: List[tuple] = []   # every request, including ones that failed
        self._seen_writes = 0
        self.down = down
        self.fail_paths: set = set()
        self.fail_write_at = 0         # the nth write answers 500 (1-based); 0 never
        self.fail_writes_from = 0      # the nth write and every one after it answers 500
        self.write_bodies: List[Dict[str, Any]] = []
        # Answer 200 to an add the switch then refuses, as Ryu does: nothing is stored.
        self.refuse_adds_where = None
        self.transport = httpx.MockTransport(self._handle)

    # ----- what the tests look at -----

    @property
    def writes(self) -> List[tuple]:
        return [(m, p) for m, p in self.log if m == "POST" and p.startswith("/stats/flowentry")]

    def snapshot(self):
        """Every flow on every switch, comparable across time."""
        return {d: {k: json.dumps(v, sort_keys=True) for k, v in fl.items()}
                for d, fl in self.flows.items()}

    def seed(self, dpid: int, match, actions, priority=100, table_id=0, **extra):
        body = {"dpid": dpid, "match": match, "actions": actions,
                "priority": priority, "table_id": table_id, **extra}
        self._add(body)

    # ----- the REST surface -----

    def _add(self, body):
        if self.refuse_adds_where and self.refuse_adds_where(body):
            return
        d = int(body["dpid"])
        self.flows.setdefault(d, {})[flow_key(body)] = {
            "priority": int(body.get("priority", 0)), "table_id": int(body.get("table_id", 0)),
            "cookie": int(body.get("cookie", 0)), "idle_timeout": int(body.get("idle_timeout", 0)),
            "hard_timeout": int(body.get("hard_timeout", 0)), "flags": int(body.get("flags", 0)),
            "match": reported_match(body.get("match")),
            "actions": [action_text(a) for a in body.get("actions") or []],
            "packet_count": 0, "byte_count": 0}

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.attempts.append((request.method, path))
        if self.down:
            raise httpx.ConnectError("connection refused")
        if path in self.fail_paths:
            return httpx.Response(500, text="boom")
        body = json.loads(request.content) if request.content else None
        if path.startswith("/stats/flowentry/"):
            self._seen_writes += 1
            if self._seen_writes == self.fail_write_at or (
                    self.fail_writes_from and self._seen_writes >= self.fail_writes_from):
                return httpx.Response(500, text="boom")
            self.write_bodies.append({"path": path, "body": body})
        self.log.append((request.method, path))        # only what the switch took
        if path == "/stats/switches":
            return httpx.Response(200, json=sorted(self.flows))
        if path.startswith("/v1.0/topology/"):
            return httpx.Response(200, json=[])
        if path.startswith("/stats/flow/"):
            d = int(path.rsplit("/", 1)[1])
            want = reported_match((body or {}).get("match"))
            out = [f for f in self.flows.get(d, {}).values()
                   if all(str(f["match"].get(k)) == str(v) for k, v in want.items())]
            return httpx.Response(200, json={str(d): out})
        if path == "/stats/flowentry/add":
            self._add(body)
            return httpx.Response(200)
        if path == "/stats/flowentry/delete_strict":
            if not (self.refuse_adds_where and self.refuse_adds_where(body)):
                self.flows.get(int(body["dpid"]), {}).pop(flow_key(body), None)
            return httpx.Response(200)
        return httpx.Response(404, text="not found")
