"""The gate's promises, one at a time, against a switch that remembers what it was sent."""
import asyncio
import json
import threading
import time
import unittest

from ryu_mcp import gate as gatemod
from ryu_mcp.client import RyuClient
from ryu_mcp.gate import WriteGate, assess, _action_from_stats
from tests.support.rig import FWD, MAP, Rig


class Assessment(unittest.TestCase):
    def call(self, path, **body):
        return {"path": path, "body": {"dpid": 1, "priority": 100, "match": {}, "actions": [], **body}}

    def test_a_wildcard_drop_is_critical(self):
        r = assess("ryu_add_flow", [self.call("/stats/flowentry/add")])
        self.assertEqual(r["risk_tier"], "critical")
        self.assertIn("drops every packet", r["risk_reasons"][0])

    def test_deleting_the_table_miss_flow_is_critical(self):
        r = assess("ryu_delete_flow", [self.call("/stats/flowentry/delete_strict", priority=0)])
        self.assertEqual(r["risk_tier"], "critical")

    def test_dropping_one_port_is_high_not_critical(self):
        r = assess("ryu_add_flow", [self.call("/stats/flowentry/add", match={"in_port": 3})])
        self.assertEqual(r["risk_tier"], "high")

    def test_an_ordinary_forwarding_flow_stays_at_its_policy_tier(self):
        r = assess("ryu_add_flow", [self.call("/stats/flowentry/add", match={"in_port": 1},
                                              actions=FWD)])
        self.assertEqual((r["risk_tier"], r["risk_reasons"]), ("medium", []))

    def test_a_tier_never_goes_below_its_policy(self):
        r = assess("ryu_delete_flow", [self.call("/stats/flowentry/delete_strict",
                                                 match={"in_port": 1}, priority=5)])
        self.assertEqual(r["risk_tier"], "high")

    def test_a_bulk_request_is_high(self):
        calls = [self.call("/stats/flowentry/add", match={"in_port": i}, actions=FWD)
                 for i in range(1, 13)]
        self.assertEqual(assess("ryu_add_flow", calls)["risk_tier"], "high")

    def test_unknown_actions_default_to_high(self):
        self.assertEqual(assess("something_new", [])["risk_tier"], "high")

    def test_the_queued_reply_tells_the_approver_why(self):
        rig = Rig()
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {}, "actions": [{"type": "DROP"}]})
        self.assertEqual(out["risk_tier"], "critical")
        self.assertTrue(out["risk_reasons"])
        self.assertEqual(rig.fake.writes, [])


class DirectMode(unittest.TestCase):
    def test_critical_is_queued_even_in_direct_mode(self):
        rig = Rig(write_mode="direct")
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {}, "actions": [{"type": "DROP"}]})
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(rig.fake.writes, [])

    def test_ordinary_writes_still_apply_in_direct_mode(self):
        rig = Rig(write_mode="direct")
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1}, "actions": FWD})
        self.assertEqual(out["status"], "applied")
        self.assertEqual(len(rig.fake.writes), 1)


class Digest(unittest.TestCase):
    def test_an_entry_edited_after_the_request_is_not_sent(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        path = rig.gate.queue_path
        items = json.load(open(path))
        items[0]["calls"][0]["body"]["match"] = {}      # widen it behind the gate's back
        json.dump(items, open(path, "w"))
        got = rig.approve_apply(out["approval_id"])
        self.assertEqual(got["applied"], [])
        self.assertEqual(rig.fake.writes, [])
        self.assertIn("digest mismatch", got["failed"][0]["error"])
        self.assertIn("tamper_detected", open(rig.gate.audit_path).read())

    def test_the_request_reply_carries_the_digest(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        self.assertEqual(len(out["digest"]), 16)


class Expiry(unittest.TestCase):
    def test_a_stale_request_cannot_be_approved(self):
        rig = Rig(approval_ttl=60)
        out = rig.call("ryu_map_vlan", MAP)
        items = json.load(open(rig.gate.queue_path))
        items[0]["created_ts"] -= 61
        json.dump(items, open(rig.gate.queue_path, "w"))
        self.assertFalse(rig.gate.decide(out["approval_id"], True)["ok"])
        self.assertEqual(rig.fake.writes, [])

    def test_approved_but_not_yet_applied_also_expires(self):
        rig = Rig(approval_ttl=60)
        out = rig.call("ryu_map_vlan", MAP)
        rig.gate.decide(out["approval_id"], True)
        items = json.load(open(rig.gate.queue_path))
        items[0]["created_ts"] -= 61
        json.dump(items, open(rig.gate.queue_path, "w"))
        self.assertEqual(asyncio.run(rig.gate.apply_approved(rig.client))["applied"], [])
        self.assertEqual(rig.fake.writes, [])

    def test_ttl_zero_never_expires(self):
        rig = Rig(approval_ttl=0)
        out = rig.call("ryu_map_vlan", MAP)
        items = json.load(open(rig.gate.queue_path))
        items[0]["created_ts"] -= 10 ** 7
        json.dump(items, open(rig.gate.queue_path, "w"))
        self.assertTrue(rig.gate.decide(out["approval_id"], True)["ok"])


class Claim(unittest.TestCase):
    def test_two_drains_apply_an_approved_request_once(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.gate.decide(out["approval_id"], True)
        # a second process: its own gate object, the same state directory
        other = WriteGate(rig.dir, ttl=rig.cfg.approval_ttl)
        results = []

        def drain(g):
            results.append(asyncio.run(g.apply_approved(RyuClient("http://ryu", transport=rig.fake.transport))))
        ts = [threading.Thread(target=drain, args=(g,)) for g in (rig.gate, other, rig.gate, other)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(len(r["applied"]) for r in results), 1)
        self.assertEqual(len(rig.fake.writes), 2)        # one map = two flows, once

    def test_approving_twice_over_mcp_applies_once(self):
        rig = Rig(approver_token="s3cret")
        out = rig.call("ryu_map_vlan", MAP)
        args = {"approval_id": out["approval_id"], "approver_token": "s3cret"}
        first, second = rig.call("ryu_approve_request", args), rig.call("ryu_approve_request", args)
        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertEqual(len(rig.fake.writes), 2)


class ApproverToken(unittest.TestCase):
    def test_no_token_configured_means_no_approval_over_mcp(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        got = rig.call("ryu_approve_request", {"approval_id": out["approval_id"], "approver_token": ""})
        self.assertEqual(got["error"], "disabled")
        self.assertEqual(rig.fake.writes, [])

    def test_a_non_ascii_token_is_refused_not_an_exception(self):
        rig = Rig(approver_token="s3cret")
        out = rig.call("ryu_map_vlan", MAP)
        got = rig.call("ryu_approve_request", {"approval_id": out["approval_id"],
                                               "approver_token": "sécret✓"})
        self.assertEqual(got["error"], "refused")

    def test_repeated_wrong_tokens_lock_approval_even_for_the_right_one(self):
        rig = Rig(approver_token="s3cret")
        out = rig.call("ryu_map_vlan", MAP)
        for guess in ("a", "b", "c", "d", "e"):
            rig.call("ryu_approve_request", {"approval_id": out["approval_id"], "approver_token": guess})
        got = rig.call("ryu_approve_request", {"approval_id": out["approval_id"],
                                               "approver_token": "s3cret"})
        self.assertEqual(got["error"], "locked")
        self.assertEqual(rig.fake.writes, [])

    def test_the_right_token_resets_the_count(self):
        rig = Rig(approver_token="s3cret")
        for _ in range(3):
            rig.call("ryu_approve_request", {"approval_id": "x", "approver_token": "no"})
        rig.call("ryu_approve_request", {"approval_id": "x", "approver_token": "s3cret"})
        for _ in range(3):
            rig.call("ryu_approve_request", {"approval_id": "x", "approver_token": "no"})
        out = rig.call("ryu_map_vlan", MAP)
        got = rig.call("ryu_approve_request", {"approval_id": out["approval_id"],
                                               "approver_token": "s3cret"})
        self.assertTrue(got["ok"])

    def test_approval_bound_to_a_digest_refuses_a_different_request(self):
        rig = Rig(approver_token="s3cret")
        seen = rig.call("ryu_map_vlan", MAP)
        swapped = rig.call("ryu_unmap_vlan", MAP)
        got = rig.call("ryu_approve_request", {"approval_id": swapped["approval_id"],
                                               "approver_token": "s3cret",
                                               "expected_digest": seen["digest"]})
        self.assertFalse(got["ok"])
        self.assertEqual(rig.fake.writes, [])


class Undo(unittest.TestCase):
    def test_undoing_a_map_removes_exactly_what_it_added(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 2}, FWD, priority=100)        # someone else's flow
        before = rig.fake.snapshot()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        self.assertNotEqual(rig.fake.snapshot(), before)
        undo = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertEqual(undo["status"], "queued_for_approval")
        self.assertTrue(undo["exact"])
        rig.approve_apply(undo["approval_id"])
        self.assertEqual(rig.fake.snapshot(), before)

    def test_undoing_an_add_that_overwrote_a_flow_puts_the_old_one_back(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 1}, [{"type": "OUTPUT", "port": 9}], priority=100)
        before = rig.fake.snapshot()
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1},
                                        "actions": [{"type": "OUTPUT", "port": 2}], "priority": 100})
        rig.approve_apply(out["approval_id"])
        self.assertNotEqual(rig.fake.snapshot(), before)
        undo = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        rig.approve_apply(undo["approval_id"])
        self.assertEqual(rig.fake.snapshot(), before)

    def test_undoing_a_delete_restores_the_flow_with_its_actions(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 1}, [
            {"type": "PUSH_VLAN", "ethertype": 33024},
            {"type": "SET_FIELD", "field": "vlan_vid", "value": 4106},
            {"type": "OUTPUT", "port": 3}], priority=200, idle_timeout=30)
        before = rig.fake.snapshot()
        out = rig.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 1}, "priority": 200})
        rig.approve_apply(out["approval_id"])
        self.assertEqual(rig.fake.flows[257], {})
        undo = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        rig.approve_apply(undo["approval_id"])
        self.assertEqual(rig.fake.snapshot(), before)

    def test_deleting_the_wrong_priority_changes_nothing_and_has_no_undo(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 1}, FWD, priority=100)
        out = rig.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 1}, "priority": 7})
        rig.approve_apply(out["approval_id"])
        got = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertFalse(got["ok"])
        self.assertIn("changed nothing", got["error"])

    def test_the_undo_is_a_request_not_an_action(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        n = len(rig.fake.writes)
        undo = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertEqual(undo["status"], "queued_for_approval")
        self.assertEqual(len(rig.fake.writes), n)

    def test_a_request_that_was_never_applied_has_nothing_to_undo(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        self.assertFalse(rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})["ok"])

    def test_one_applied_change_is_undone_once(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        first = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        second = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])

    def test_undoing_out_of_order_is_refused_rather_than_resurrecting_old_state(self):
        rig = Rig()
        a = rig.call("ryu_map_vlan", {**MAP, "vlan_id": 10})
        rig.approve_apply(a["approval_id"])
        b = rig.call("ryu_map_vlan", {**MAP, "vlan_id": 11})     # same client port: overwrites a's ingress flow
        rig.approve_apply(b["approval_id"])
        got = rig.call("ryu_request_undo", {"approval_id": a["approval_id"]})
        self.assertFalse(got["ok"])
        self.assertIn(b["approval_id"], got["error"])
        # newest first works, and then the older one is free to be undone
        ub = rig.call("ryu_request_undo", {"approval_id": b["approval_id"]})
        rig.approve_apply(ub["approval_id"])
        ua = rig.call("ryu_request_undo", {"approval_id": a["approval_id"]})
        self.assertTrue(ua["ok"])
        rig.approve_apply(ua["approval_id"])
        self.assertEqual(rig.fake.flows[257], {})

    def test_an_unreadable_prior_state_is_not_offered_as_an_exact_undo(self):
        rig = Rig()
        rig.fake.fail_paths.add("/stats/flow/257")           # Ryu refuses the read
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        got = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertFalse(got["ok"])
        self.assertIn("could not be read", got["error"])

    def test_an_unknown_action_in_the_old_flow_is_not_guessed_at(self):
        rig = Rig()
        rig.fake.flows[257][(0, 100, json.dumps({"in_port": 1}, sort_keys=True))] = {
            "priority": 100, "table_id": 0, "match": {"in_port": 1},
            "actions": ["SET_QUEUE:4"], "cookie": 0}
        out = rig.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 1}, "priority": 100})
        rig.approve_apply(out["approval_id"])
        got = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        self.assertFalse(got["ok"])


class RealFormat(unittest.TestCase):
    """Action strings exactly as a live Ryu reported them."""

    def test_live_action_strings_parse(self):
        self.assertEqual(_action_from_stats("OUTPUT:2"), {"type": "OUTPUT", "port": 2})
        self.assertEqual(_action_from_stats("OUTPUT:CONTROLLER"), {"type": "OUTPUT", "port": "CONTROLLER"})
        self.assertEqual(_action_from_stats("PUSH_VLAN:33024"), {"type": "PUSH_VLAN", "ethertype": 33024})
        self.assertEqual(_action_from_stats("SET_FIELD: {vlan_vid:4198}"),
                         {"type": "SET_FIELD", "field": "vlan_vid", "value": 4198})
        self.assertEqual(_action_from_stats("POP_VLAN"), {"type": "POP_VLAN"})

    def test_every_action_a_live_ryu_reported_is_understood(self):
        # Read from a running Ryu (3 switches, 34 flows) on 2026-11-05: these nine strings
        # were every distinct action it reported. A flow built from them restores whole.
        seen = ["OUTPUT:1", "OUTPUT:2", "OUTPUT:3", "OUTPUT:CONTROLLER", "POP_VLAN", "PUSH_VLAN:33024",
                "SET_FIELD: {vlan_vid:4198}", "SET_FIELD: {vlan_vid:4203}", "SET_FIELD: {vlan_vid:4207}"]
        self.assertTrue(all(_action_from_stats(a) for a in seen))
        flow = {"priority": 260, "table_id": 0, "match": {"in_port": 1, "dl_type": 35020, "dl_vlan": 7},
                "actions": ["PUSH_VLAN:33024", "SET_FIELD: {vlan_vid:4198}", "OUTPUT:3", "OUTPUT:CONTROLLER"]}
        from ryu_mcp.gate import _restore
        self.assertIsNotNone(_restore(257, flow))

    def test_what_is_not_understood_is_none(self):
        for text in ("SET_QUEUE:4", "SET_FIELD: {eth_dst:aa:bb}", "", "nonsense"):
            self.assertIsNone(_action_from_stats(text), text)


class Rollback(unittest.TestCase):
    def test_a_map_that_fails_halfway_leaves_no_half_circuit(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 2}, FWD, priority=100)
        before = rig.fake.snapshot()
        out = rig.call("ryu_map_vlan", MAP)
        rig.fake.fail_write_at = 2           # the second flow is refused, once
        got = rig.approve_apply(out["approval_id"])
        self.assertEqual(got["applied"], [])
        self.assertEqual(rig.fake.snapshot(), before)
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual(item["state"], "failed")
        self.assertEqual(item["rollback"], {"sent": 1, "of": 2, "restored": True})

    def test_a_rollback_that_cannot_complete_says_so(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.fake.fail_writes_from = 2        # Ryu goes away after the first flow
        rig.approve_apply(out["approval_id"])
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual(item["state"], "failed")
        self.assertFalse(item["rollback"]["restored"])
        self.assertIn("rolled_back", open(rig.gate.audit_path).read())

    def test_a_failure_before_anything_was_sent_needs_no_rollback(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.fake.fail_write_at = 1
        rig.approve_apply(out["approval_id"])
        self.assertNotIn("rollback", json.load(open(rig.gate.queue_path))[0])


class Validation(unittest.TestCase):
    """Refused when requested, not when Ryu chokes on it after someone approved it."""

    def refused(self, **args):
        """Refused by the MCP framework's own typing, or by the gate's schema: either way, not queued."""
        rig = Rig()
        base = {"dpid": "257", "match": {"in_port": 1}, "actions": FWD}
        try:
            out = rig.call("ryu_add_flow", {**base, **args})
        except Exception:  # noqa: BLE001  ToolError from argument validation
            out = {"ok": False}
        self.assertFalse(out["ok"], args)
        self.assertEqual(rig.gate.pending(), [])

    def test_actions_missing_what_they_cannot_work_without(self):
        for acts in ([{"type": "OUTPUT"}], [{"type": "PUSH_VLAN"}], [{"type": "SET_FIELD", "field": "vlan_vid"}],
                     [{"type": "GROUP"}], [{"type": "GOTO_TABLE"}], [{"type": "SET_QUEUE"}]):
            self.refused(actions=acts)

    def test_action_arguments_of_the_wrong_kind(self):
        for acts in ([{"type": "OUTPUT", "port": -1}], [{"type": "OUTPUT", "port": "left"}],
                     [{"type": "OUTPUT", "port": 2 ** 40}], [{"type": "PUSH_VLAN", "ethertype": "x"}],
                     [{"type": "SET_FIELD", "field": "nonsense", "value": 1}], ["OUTPUT:3"], [None], [[]]):
            self.refused(actions=acts)

    def test_actions_that_are_not_a_list(self):
        for acts in ("OUTPUT:3", {"type": "OUTPUT", "port": 1}, 7):
            self.refused(actions=acts)

    def test_match_values_of_the_wrong_kind(self):
        for m in ({"in_port": "x"}, {"in_port": {"a": 1}}, {"in_port": [1]}, {"in_port": None},
                  {"in_port": True}, {"dl_type": "ipv4"}, {"in_port": -3}):
            self.refused(match=m)

    def test_a_match_that_is_not_an_object(self):
        for m in ([], "in_port", 5):
            self.refused(match=m)

    def test_numbers_that_are_not_integers(self):
        for key in ("priority",):
            for v in (None, 1.5, "x", float("inf"), [], -1, 65536, 2 ** 70):
                self.refused(**{key: v})

    def test_a_port_name_and_hex_are_still_fine(self):
        rig = Rig()
        ok = rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": "0x2", "dl_type": 2048},
                                       "actions": [{"type": "OUTPUT", "port": "CONTROLLER"}]})
        self.assertEqual(ok["status"], "queued_for_approval")

    def test_datapath_ids_out_of_range(self):
        for d in ("-1", -5, 2 ** 64, "9" * 30, True, "", "zz", 1.5, None):
            rig = Rig()
            try:
                out = rig.call("ryu_add_flow", {"dpid": d, "match": {"in_port": 1}, "actions": FWD})
            except Exception:  # noqa: BLE001
                out = {"ok": False}
            self.assertFalse(out["ok"], d)
            self.assertEqual(rig.gate.pending(), [])

    def test_vlan_maps_with_bad_numbers(self):
        for bad in ({"vlan_id": None}, {"vlan_id": "10; DROP"}, {"vlan_id": 4095},
                    {"client_port": 0}, {"uplink_port": "x"}, {"client_port": 3}):
            rig = Rig()
            try:
                out = rig.call("ryu_map_vlan", {**MAP, **bad})
            except Exception:  # noqa: BLE001
                out = {"ok": False}
            self.assertFalse(out["ok"], bad)
            self.assertEqual(rig.gate.pending(), [])

    def test_a_bool_is_not_a_number_to_the_schema(self):
        from ryu_mcp import schemas
        for call in (lambda: schemas.flow_entry(257, {"in_port": 1}, FWD, priority=True),
                     lambda: schemas.vlan_map(257, 1, 3, True),
                     lambda: schemas.vlan_map(257, True, 3, 10)):
            with self.assertRaises(schemas.SchemaError):
                call()


class Races(unittest.TestCase):
    def test_a_second_process_cannot_claim_what_the_first_is_claiming(self):
        class Slow(WriteGate):
            def _load(self):
                got = super()._load()
                time.sleep(0.08)          # widen the window between read and claim
                return got

        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.gate.decide(out["approval_id"], True)
        gates = [Slow(rig.dir, ttl=rig.cfg.approval_ttl) for _ in range(3)]
        results, errors = [], []

        def drain(g):
            try:
                results.append(asyncio.run(g.apply_approved(
                    RyuClient("http://ryu", transport=rig.fake.transport))))
            except Exception as e:  # noqa: BLE001 - a drain that crashes is a lock that failed
                errors.append(e)
        ts = [threading.Thread(target=drain, args=(g,)) for g in gates]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 3)
        self.assertEqual(sum(len(r["applied"]) for r in results), 1)
        self.assertEqual(len(rig.fake.writes), 2)


class RateLimit(unittest.TestCase):
    def test_the_hour_cap_holds_and_names_itself(self):
        rig = Rig()
        outs = [rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1, "dl_vlan": i},
                                          "actions": FWD}) for i in range(35)]
        self.assertEqual(sum(o["status"] == "queued_for_approval" for o in outs), 30)
        self.assertIn("rate limit", outs[-1]["reason"])
        self.assertEqual(rig.fake.writes, [])


class AgainstRealRyu(unittest.TestCase):
    """Behaviour read off a live Ryu 4.34 and Open vSwitch, kept as regressions."""

    def test_action_types_are_written_in_the_case_ryu_reads(self):
        from ryu_mcp import schemas
        body = schemas.flow_entry(257, {"in_port": 1}, [{"type": "output", "port": 2}])
        self.assertEqual(body["actions"][0]["type"], "OUTPUT")

    def test_match_prerequisites_are_enforced(self):
        from ryu_mcp import schemas
        for bad in ({"ip_proto": 6}, {"tcp_dst": 80}, {"eth_type": 2048, "tcp_dst": 80},
                    {"ipv4_dst": "10.0.0.1"}, {"eth_type": 0x86DD, "ipv4_dst": "10.0.0.1"},
                    {"vlan_pcp": 3}, {"eth_type": 0x0806, "ip_proto": 6}):
            with self.assertRaises(schemas.SchemaError, msg=bad):
                schemas.flow_entry(257, bad, FWD)
        for good in ({"eth_type": 2048, "ip_proto": 6, "tcp_dst": 80}, {"dl_type": 2048, "nw_dst": "10.0.0.1"},
                     {"eth_type": 2048, "ipv4_dst": "10.0.0.1"}, {"vlan_vid": 4106, "vlan_pcp": 3},
                     {"eth_type": 0x86DD, "ip_proto": 17, "udp_dst": 53}):
            schemas.flow_entry(257, good, FWD)

    def test_a_match_is_compared_under_ryus_names_not_the_requests(self):
        from ryu_mcp.gate import canon_match
        same = [({"vlan_vid": 4106}, {"dl_vlan": "10"}), ({"vlan_vid": 10}, {"dl_vlan": "10"}),
                ({"eth_dst": "AA:BB:CC:DD:EE:FF"}, {"dl_dst": "aa:bb:cc:dd:ee:ff"}),
                ({"in_port": "0x1"}, {"in_port": 1}), ({"ipv4_dst": "10.0.0.1"}, {"nw_dst": "10.0.0.1"}),
                ({"tcp_dst": 80, "ip_proto": 6, "eth_type": 2048}, {"tp_dst": 80, "nw_proto": 6, "dl_type": 2048})]
        for a, b in same:
            self.assertEqual(canon_match(a), canon_match(b), (a, b))
        self.assertNotEqual(canon_match({"vlan_vid": 4107}), canon_match({"vlan_vid": 4106}))

    def test_undo_of_an_overwrite_finds_a_flow_ryu_reports_under_another_name(self):
        rig = Rig()
        match = {"in_port": 1, "vlan_vid": 4106, "eth_dst": "aa:bb:cc:dd:ee:ff"}
        rig.fake.seed(257, match, [{"type": "OUTPUT", "port": 9}], priority=120)
        before = rig.fake.snapshot()
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": match, "actions": FWD, "priority": 120})
        rig.approve_apply(out["approval_id"])
        undo = rig.call("ryu_request_undo", {"approval_id": out["approval_id"]})
        rig.approve_apply(undo["approval_id"])
        self.assertEqual(rig.fake.snapshot(), before)


class ReadBack(unittest.TestCase):
    """Ryu says 200 to flows the switch refuses; applied has to mean the switch holds it."""

    def test_a_flow_the_switch_refused_is_reported_failed_not_applied(self):
        rig = Rig()
        rig.fake.refuse_adds_where = lambda b: any(a.get("type") == "GROUP" for a in b.get("actions", []))
        before = rig.fake.snapshot()
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1},
                                        "actions": [{"type": "GROUP", "group_id": 7}]})
        got = rig.approve_apply(out["approval_id"])
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual(got["applied"], [])
        self.assertEqual(item["state"], "failed")
        self.assertIn("does not hold the flow", item["result"])
        self.assertEqual(rig.fake.snapshot(), before)

    def test_one_flow_of_two_refused_takes_the_other_back_out(self):
        rig = Rig()
        rig.fake.refuse_adds_where = lambda b: b["match"].get("vlan_vid") is not None   # the egress flow
        before = rig.fake.snapshot()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual(item["state"], "failed")
        self.assertEqual(rig.fake.snapshot(), before)
        self.assertTrue(item["rollback"]["restored"])

    def test_a_delete_that_did_not_take_is_reported(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 1}, FWD, priority=100)
        rig.fake.refuse_adds_where = lambda b: True        # the switch ignores the delete too
        out = rig.call("ryu_delete_flow", {"dpid": "257", "match": {"in_port": 1}, "priority": 100})
        rig.approve_apply(out["approval_id"])
        self.assertIn("still present", json.load(open(rig.gate.queue_path))[0]["result"])

    def test_wrong_actions_on_the_switch_are_caught(self):
        rig = Rig()
        orig = rig.fake._add

        def strip_actions(body):                      # a switch that kept the match, lost the actions
            orig({**body, "actions": []})
        rig.fake._add = strip_actions
        out = rig.call("ryu_add_flow", {"dpid": "257", "match": {"in_port": 1}, "actions": FWD})
        rig.approve_apply(out["approval_id"])
        self.assertIn("different actions", json.load(open(rig.gate.queue_path))[0]["result"])

    def test_a_good_write_is_marked_verified(self):
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual((item["state"], item["verified"]), ("applied", True))

    def test_a_flow_table_that_cannot_be_read_back_is_applied_but_not_called_verified(self):
        rig = Rig()
        rig.fake.fail_paths.add("/stats/flow/257")
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        item = json.load(open(rig.gate.queue_path))[0]
        self.assertEqual((item["state"], item["verified"]), ("applied", False))


class Recovery(unittest.TestCase):
    """A process that dies after claiming a request must not leave it 'applying' forever."""

    DEAD = 2 ** 22 + 12345          # no such process

    def stuck(self, rig, land):
        """A map claimed by a dead process, with the first `land` of its flows on the switch."""
        out = rig.call("ryu_map_vlan", MAP)
        rig.gate.decide(out["approval_id"], True)
        items = json.load(open(rig.gate.queue_path))
        item = items[0]
        item["state"] = "applying"
        item["claimed_by"] = {"pid": self.DEAD, "host": __import__("socket").gethostname(), "ts": 0}
        item["pre"] = [[], []]
        json.dump(items, open(rig.gate.queue_path, "w"))
        for call in item["calls"][:land]:
            rig.fake._add(call["body"])
        return out["approval_id"]

    def recover(self, rig):
        return asyncio.run(rig.gate.recover(rig.client))

    def test_half_landed_is_taken_back(self):
        rig = Rig()
        before = rig.fake.snapshot()
        rid = self.stuck(rig, land=1)
        got = self.recover(rig)
        item = {i["id"]: i for i in json.load(open(rig.gate.queue_path))}[rid]
        self.assertEqual(got["settled"], [{"id": rid, "state": "failed"}])
        self.assertEqual(rig.fake.snapshot(), before)
        self.assertTrue(item["rollback"]["restored"])

    def test_nothing_landed_is_failed_not_retried(self):
        rig = Rig()
        rid = self.stuck(rig, land=0)
        self.recover(rig)
        item = {i["id"]: i for i in json.load(open(rig.gate.queue_path))}[rid]
        self.assertEqual(item["state"], "failed")
        self.assertIn("nothing landed", item["result"])
        self.assertEqual(rig.fake.writes, [])

    def test_everything_landed_is_recorded_as_applied_with_an_undo(self):
        rig = Rig()
        rid = self.stuck(rig, land=2)
        self.recover(rig)
        item = {i["id"]: i for i in json.load(open(rig.gate.queue_path))}[rid]
        self.assertEqual((item["state"], item["verified"], item["recovered"]), ("applied", True, True))
        u = rig.call("ryu_request_undo", {"approval_id": rid})
        self.assertTrue(u["ok"])

    def test_a_request_held_by_a_live_process_is_left_alone(self):
        rig = Rig()
        rid = self.stuck(rig, land=1)
        items = json.load(open(rig.gate.queue_path))
        items[0]["claimed_by"]["pid"] = __import__("os").getpid()
        json.dump(items, open(rig.gate.queue_path, "w"))
        self.assertEqual(self.recover(rig), {"settled": [], "left": []})
        self.assertEqual({i["id"]: i for i in json.load(open(rig.gate.queue_path))}[rid]["state"], "applying")

    def test_an_unreadable_switch_leaves_it_for_later(self):
        rig = Rig()
        rid = self.stuck(rig, land=1)
        rig.fake.fail_paths.add("/stats/flow/257")
        got = self.recover(rig)
        self.assertEqual([x["id"] for x in got["left"]], [rid])

    def test_the_flow_table_is_saved_before_anything_is_sent(self):
        rig = Rig()
        rig.fake.seed(257, {"in_port": 2}, FWD, priority=100)
        out = rig.call("ryu_map_vlan", MAP)
        rig.fake.fail_write_at = 1
        rig.approve_apply(out["approval_id"])
        self.assertEqual(json.load(open(rig.gate.queue_path))[0]["pre"], [[], []])


class UndoCap(unittest.TestCase):
    def test_recovery_cannot_run_out_before_the_changes_do(self):
        forward = sum(v["max_changes_per_hour"] for k, v in gatemod.POLICIES.items() if k != "ryu_undo")
        self.assertGreaterEqual(gatemod.POLICIES["ryu_undo"]["max_changes_per_hour"], forward)


class Cli(unittest.TestCase):
    def test_undo_flag_queues_but_does_not_apply(self):
        import run_ryu_mcp
        rig = Rig()
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        import os
        os.environ["RYU_STATE_DIR"] = rig.dir
        try:
            rc = run_ryu_mcp.main(["--undo", out["approval_id"]])
        finally:
            del os.environ["RYU_STATE_DIR"]
        self.assertEqual(rc, 0)
        self.assertEqual(len(rig.gate.pending()), 1)


if __name__ == "__main__":
    unittest.main()
