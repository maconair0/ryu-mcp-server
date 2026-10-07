"""No Ryu and no network: the REST API is faked with httpx's MockTransport."""
import asyncio
import json
import tempfile
import unittest

import httpx

from ryu_mcp import schemas, summarise
from ryu_mcp.client import RyuClient, RyuUnreachable, dpid_hex, dpid_int
from ryu_mcp.config import RyuConfig
from ryu_mcp.gate import WriteGate
from ryu_mcp.server import create_server


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


class DpidTests(unittest.TestCase):
    """The topology app says "0000000000000101"; the stats app wants 257."""

    def test_hex_and_decimal_name_the_same_switch(self):
        self.assertEqual(dpid_int("0000000000000101"), 257)
        self.assertEqual(dpid_int("257"), 257)
        self.assertEqual(dpid_int("0x101"), 257)
        self.assertEqual(dpid_int(257), 257)
        self.assertEqual(dpid_hex(257), "0000000000000101")


class SchemaTests(unittest.TestCase):

    def test_a_misspelt_match_field_is_refused(self):
        # Ryu drops unknown fields silently, so the flow would match everything.
        with self.assertRaises(schemas.SchemaError):
            schemas.flow_entry(257, {"in_prt": 1}, [{"type": "OUTPUT", "port": 2}])

    def test_an_unknown_action_is_refused(self):
        with self.assertRaises(schemas.SchemaError):
            schemas.flow_entry(257, {"in_port": 1}, [{"type": "FORWARD", "port": 2}])

    def test_vlan_map_is_two_flows_one_per_direction(self):
        up, down = schemas.vlan_map("0000000000000101", 1, 3, 10)
        self.assertEqual(up["match"], {"in_port": 1})
        self.assertEqual(down["match"]["in_port"], 3)
        self.assertEqual(up["dpid"], 257)

    def test_vlan_id_carries_the_present_bit(self):
        # Without OFPVID_PRESENT the match is on an untagged VID and never fires.
        _, down = schemas.vlan_map(257, 1, 3, 10)
        self.assertEqual(down["match"]["vlan_vid"], 10 | 0x1000)

    def test_vlan_map_rejects_bad_input(self):
        for args in ((257, 1, 1, 10), (257, 1, 3, 0), (257, 1, 3, 4095)):
            with self.assertRaises(schemas.SchemaError):
                schemas.vlan_map(*args)


class SummariseTests(unittest.TestCase):

    def test_both_directions_of_a_link_fold_to_one(self):
        links = [{"src": {"dpid": "a", "port_no": "1"}, "dst": {"dpid": "b", "port_no": "2"}},
                 {"src": {"dpid": "b", "port_no": "2"}, "dst": {"dpid": "a", "port_no": "1"}}]
        out = summarise.topology([], links, [])
        self.assertEqual(out["links"], 2)
        self.assertEqual(len(out["link_detail"]), 1)
        self.assertTrue(out["link_detail"][0]["bidirectional"])

    def test_controller_punt_flows_are_hidden_by_default(self):
        payload = {"257": [{"actions": ["OUTPUT:CONTROLLER"], "priority": 65535},
                           {"actions": ["OUTPUT:3"], "priority": 200, "packet_count": 5}]}
        self.assertEqual(summarise.flows(257, payload)["flows"], 1)
        self.assertEqual(summarise.flows(257, payload, True)["flows"], 2)


def fake_ryu(log):
    def handler(request):
        log.append((request.method, request.url.path))
        if request.url.path == "/stats/switches":
            return httpx.Response(200, json=[257, 258])
        if request.url.path.startswith("/v1.0/topology/"):
            return httpx.Response(200, json=[])
        if request.url.path.startswith("/stats/flowentry/"):
            return httpx.Response(200)
        return httpx.Response(404, text="not found")
    return httpx.MockTransport(handler)


class GateTests(unittest.TestCase):
    """A write tool must leave Ryu untouched until an operator approves."""

    def setUp(self):
        self.log = []
        self.cfg = RyuConfig.from_env(state_dir=tempfile.mkdtemp())
        self.client = RyuClient("http://ryu", transport=fake_ryu(self.log))
        self.gate = WriteGate(self.cfg.state_dir)
        self.server = create_server(self.cfg, client=self.client, gate=self.gate)

    def call(self, name, args):
        async def go():
            result = await self.server.call_tool(name, args)
            content = result[0] if isinstance(result, tuple) else result
            return json.loads(content[0].text)
        return asyncio.run(go())

    def posts(self):
        return [p for m, p in self.log if m == "POST"]

    def test_a_queued_write_sends_nothing(self):
        out = self.call("ryu_map_vlan", {"dpid": "257", "client_port": 1,
                                         "uplink_port": 3, "vlan_id": 10})
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(self.posts(), [])

    def test_approval_then_drain_installs_both_flows(self):
        out = self.call("ryu_map_vlan", {"dpid": "257", "client_port": 1,
                                         "uplink_port": 3, "vlan_id": 10})
        self.gate.decide(out["approval_id"], approve=True)
        result = asyncio.run(self.gate.apply_approved(self.client))
        self.assertEqual(result["applied"], [out["approval_id"]])
        self.assertEqual(self.posts(), ["/stats/flowentry/add"] * 2)

    def test_a_rejected_write_is_never_installed(self):
        out = self.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1},
                                         "actions": [{"type": "OUTPUT", "port": 2}]})
        self.gate.decide(out["approval_id"], approve=False)
        asyncio.run(self.gate.apply_approved(self.client))
        self.assertEqual(self.posts(), [])

    def test_an_invalid_flow_is_refused_before_queueing(self):
        out = self.call("ryu_add_flow", {"dpid": "257", "match": {"in_prt": 1},
                                         "actions": [{"type": "OUTPUT", "port": 2}]})
        self.assertFalse(out["ok"])
        self.assertEqual(self.gate.pending(), [])

    def test_direct_mode_applies_immediately(self):
        self.cfg.write_mode = "direct"
        server = create_server(self.cfg, client=self.client, gate=self.gate)
        async def go():
            r = await server.call_tool("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1},
                                                        "actions": [{"type": "OUTPUT", "port": 2}]})
            c = r[0] if isinstance(r, tuple) else r
            return json.loads(c[0].text)
        self.assertEqual(asyncio.run(go())["status"], "applied")
        self.assertEqual(self.posts(), ["/stats/flowentry/add"])


class FailureTests(unittest.TestCase):

    def test_an_unreachable_ryu_is_reported_as_data(self):
        def boom(request):
            raise httpx.ConnectError("refused")
        cfg = RyuConfig.from_env(state_dir=tempfile.mkdtemp())
        server = create_server(cfg, client=RyuClient("http://ryu", transport=httpx.MockTransport(boom)))
        async def go():
            r = await server.call_tool("ryu_list_switches", {})
            c = r[0] if isinstance(r, tuple) else r
            return json.loads(c[0].text)
        out = asyncio.run(go())
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "unreachable")


if __name__ == "__main__":
    unittest.main()


class ShortestPath(unittest.TestCase):
    SW = [{"dpid": "0000000000000001"}, {"dpid": "0000000000000002"},
          {"dpid": "0000000000000003"}]

    @staticmethod
    def link(a, ap, z, zp):
        return {"src": {"dpid": a, "port_no": ap}, "dst": {"dpid": z, "port_no": zp}}

    def test_same_switch_is_zero_hops(self):
        got = summarise.shortest_path(self.SW, [], "0000000000000001", "0000000000000001")
        self.assertEqual((got["found"], got["hops"]), (True, 0))

    def test_two_hops_with_ports(self):
        a, b, c = (s["dpid"] for s in self.SW)
        links = [self.link(a, "2", b, "1"), self.link(b, "1", a, "2"),
                 self.link(b, "3", c, "1"), self.link(c, "1", b, "3")]
        got = summarise.shortest_path(self.SW, links, a, c)
        self.assertEqual(got["path"], [a, b, c])
        self.assertEqual(got["ports"][0]["out_port"], "2")

    def test_one_way_link_is_not_a_path(self):
        a, b, _ = (s["dpid"] for s in self.SW)
        got = summarise.shortest_path(self.SW, [self.link(a, "2", b, "1")], a, b)
        self.assertFalse(got["found"])

    def test_unknown_switch(self):
        got = summarise.shortest_path(self.SW, [], "0000000000000001", "00000000000000ff")
        self.assertIn("unknown", got["reason"])


class Replay(unittest.TestCase):
    def test_applied_writes_replay_in_order(self):
        sent = []

        class Client:
            async def post(self, path, body):
                sent.append((path, body["n"]))

        with tempfile.TemporaryDirectory() as d:
            gate = WriteGate(d)
            first = gate.request("ryu_add_flow", "a", [{"path": "/add", "body": {"n": 1}}])
            second = gate.request("ryu_delete_flow", "b", [{"path": "/del", "body": {"n": 2}}])
            ignored = gate.request("ryu_add_flow", "c", [{"path": "/add", "body": {"n": 3}}])
            for item in (first, second):
                gate.decide(item["approval_id"], True)
                asyncio.run(gate.apply_approved(Client()))
            sent.clear()
            got = asyncio.run(gate.replay_applied(Client()))
        self.assertEqual(sent, [("/add", 1), ("/del", 2)])
        self.assertEqual(len(got["replayed"]), 2)
        self.assertTrue(ignored["approval_id"])


class Unmap(unittest.TestCase):
    def test_unmap_is_the_exact_inverse_of_map(self):
        made = schemas.vlan_map("0000000000000101", 1, 3, 10)
        undone = schemas.vlan_unmap("0000000000000101", 1, 3, 10)
        self.assertEqual([(b["match"], b["priority"]) for b in made],
                         [(b["match"], b["priority"]) for b in undone])
        self.assertTrue(all(b["actions"] == [] for b in undone))
