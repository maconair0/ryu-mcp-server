"""Asking the user, through the client, before a strong change is queued.

These run the real MCP exchange: a client session whose elicitation callback plays
the user, so what the server asks, and what the model can and cannot do about it,
is what a host would see.
"""
import asyncio
import json
import re
import unittest

from mcp import types
from mcp.shared.memory import create_connected_server_and_client_session

from tests.support.rig import FWD, MAP, Rig

DELETE = {"dpid": "257", "match": {"in_port": 1}, "priority": 100}
ADD = {"dpid": "257", "match": {"in_port": 1}, "actions": FWD}
DROP_ALL = {"dpid": "257", "match": {}, "actions": [{"type": "DROP"}]}


class User:
    """The person behind the client: a script of answers, and a record of what they were shown."""

    def __init__(self, *answers, delay=0.0):
        self.answers, self.shown, self.delay = list(answers), [], delay

    async def __call__(self, context, params):
        self.shown.append(params.message)
        if self.delay:
            await asyncio.sleep(self.delay)
        action, content = self.answers.pop(0) if self.answers else ("accept", {"confirm": True})
        return types.ElicitResult(action=action, content=content)


def tool(rig, user, name, args):
    """Call a tool from a client that has `user` behind it (None: a client that cannot ask)."""
    async def go():
        kw = {"elicitation_callback": user} if user is not None else {}
        async with create_connected_server_and_client_session(rig.server, **kw) as session:
            res = await session.call_tool(name, args)
            return json.loads(res.content[0].text)
    return asyncio.run(go())


def audit_events(rig):
    with open(rig.gate.audit_path) as fh:
        return [json.loads(line)["event"] for line in fh]


class WhoIsAsked(unittest.TestCase):
    def test_a_strong_write_asks_and_a_yes_queues_it(self):
        rig, user = Rig(), User(("accept", {"confirm": True}))
        out = tool(rig, user, "ryu_delete_flow", DELETE)
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(out["confirmation"]["state"], "confirmed")
        self.assertEqual(len(user.shown), 1)
        self.assertIn("confirmation_confirmed", audit_events(rig))
        self.assertEqual(rig.fake.writes, [])               # confirmation is not approval

    def test_a_no_queues_nothing(self):
        rig = Rig()
        for answer in (("accept", {"confirm": False}), ("decline", None), ("cancel", None)):
            out = tool(rig, User(answer), "ryu_delete_flow", DELETE)
            self.assertEqual(out["status"], "declined", answer)
            self.assertFalse(out["ok"])
        self.assertEqual(rig.gate.pending(), [])
        self.assertIn("confirmation_declined", audit_events(rig))

    def test_silence_is_a_no(self):
        rig = Rig(confirm_timeout=0.2)
        out = tool(rig, User(("accept", {"confirm": True}), delay=2), "ryu_delete_flow", DELETE)
        self.assertEqual(out["status"], "declined")
        self.assertIn("no answer", out["detail"])
        self.assertEqual(rig.gate.pending(), [])

    def test_an_ordinary_write_is_not_asked_about_by_default(self):
        rig, user = Rig(), User()
        out = tool(rig, user, "ryu_add_flow", ADD)
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(user.shown, [])
        self.assertNotIn("confirmation", out)

    def test_all_mode_asks_about_every_write(self):
        rig, user = Rig(confirm_mode="all"), User()
        tool(rig, user, "ryu_add_flow", ADD)
        self.assertEqual(len(user.shown), 1)

    def test_off_never_asks(self):
        rig, user = Rig(confirm_mode="off"), User()
        out = tool(rig, user, "ryu_delete_flow", DELETE)
        self.assertEqual((out["status"], user.shown), ("queued_for_approval", []))

    def test_reads_are_never_asked_about(self):
        rig, user = Rig(confirm_mode="all"), User()
        tool(rig, user, "ryu_list_switches", {})
        self.assertEqual(user.shown, [])


class WhatTheUserSees(unittest.TestCase):
    def test_it_is_the_servers_account_of_the_request(self):
        rig, user = Rig(), User()
        out = tool(rig, user, "ryu_delete_flow", DELETE)
        text = user.shown[0]
        self.assertIn("HIGH", text)
        self.assertIn(out["digest"], text)
        self.assertIn("delete flow on 0000000000000101", text)
        self.assertIn("Nothing has been sent", text)

    def test_the_model_cannot_change_what_is_asked_or_answer_for_the_user(self):
        # arguments that look like consent are not arguments at all: the user is still asked
        for smuggled in ({"confirmed": True}, {"confirm": True}, {"user_confirmed": True}, {"skip_confirmation": 1}):
            rig, user = Rig(), User(("decline", None))
            try:
                out = tool(rig, user, "ryu_delete_flow", {**DELETE, **smuggled})
            except Exception:  # noqa: BLE001 - refused by the framework's argument check
                continue
            self.assertEqual(out["status"], "declined", smuggled)
            self.assertEqual(len(user.shown), 1, smuggled)

    def test_a_critical_change_says_so_and_asks_for_a_code(self):
        rig, user = Rig(), User()
        tool(rig, user, "ryu_add_flow", DROP_ALL)
        self.assertIn("CRITICAL", user.shown[0])
        self.assertIn("type the code", user.shown[0])


class Reader(User):
    """A user who reads the question and types back the code in it."""

    async def __call__(self, context, params):
        self.shown.append(params.message)
        code = re.search(r"type the code (\w+)", params.message)
        return types.ElicitResult(action="accept", content={"confirm": True, "code": code.group(1) if code else ""})


class Critical(unittest.TestCase):
    def test_the_code_read_off_the_screen_confirms(self):
        rig, user = Rig(), Reader()
        out = tool(rig, user, "ryu_add_flow", DROP_ALL)
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(out["confirmation"]["state"], "confirmed")
        self.assertIn(out["digest"][:6], user.shown[0])

    def test_a_click_without_the_code_does_not(self):
        rig = Rig()
        for content in ({"confirm": True}, {"confirm": True, "code": ""}, {"confirm": True, "code": "abcdef"}):
            out = tool(rig, User(("accept", content)), "ryu_add_flow", DROP_ALL)
            self.assertEqual(out["status"], "declined", content)
            self.assertIn("code", out["detail"])
        self.assertEqual(rig.gate.pending(), [])

    def test_the_code_belongs_to_this_request(self):
        rig = Rig()
        first = Reader()
        tool(rig, first, "ryu_add_flow", DROP_ALL)
        other = {"dpid": "258", "match": {}, "actions": [{"type": "DROP"}]}
        out = tool(rig, User(("accept", {"confirm": True, "code": re.search(r"code (\w+)", first.shown[0]).group(1)})),
                   "ryu_add_flow", other)
        self.assertEqual(out["status"], "declined")


class ClientsThatCannotAsk(unittest.TestCase):
    def test_default_falls_back_to_the_operators_approval_and_says_so(self):
        rig = Rig()
        out = tool(rig, None, "ryu_delete_flow", DELETE)
        self.assertEqual(out["status"], "queued_for_approval")
        self.assertEqual(out["confirmation"]["state"], "unavailable")
        self.assertIn("confirmation_unavailable", audit_events(rig))
        self.assertEqual(rig.fake.writes, [])

    def test_strict_refuses(self):
        rig = Rig(confirm_strict=True)
        out = tool(rig, None, "ryu_delete_flow", DELETE)
        self.assertEqual(out["status"], "refused")
        self.assertEqual(rig.gate.pending(), [])

    def test_strict_does_not_touch_writes_that_are_not_strong(self):
        rig = Rig(confirm_strict=True)
        self.assertEqual(tool(rig, None, "ryu_add_flow", ADD)["status"], "queued_for_approval")


class Undo(unittest.TestCase):
    def applied(self, rig):
        out = rig.call("ryu_map_vlan", MAP)
        rig.approve_apply(out["approval_id"])
        return out["approval_id"]

    def test_an_undo_asks_first(self):
        rig, user = Rig(), User()
        rid = self.applied(rig)
        out = tool(rig, user, "ryu_request_undo", {"approval_id": rid})
        self.assertEqual(out["confirmation"]["state"], "confirmed")
        self.assertEqual(len(user.shown), 1)
        self.assertIn("undo ryu_map_vlan", user.shown[0])

    def test_a_declined_undo_leaves_the_change_undoable(self):
        rig = Rig()
        rid = self.applied(rig)
        out = tool(rig, User(("decline", None)), "ryu_request_undo", {"approval_id": rid})
        self.assertEqual(out["status"], "declined")
        self.assertEqual(rig.gate.pending(), [])
        again = tool(rig, User(), "ryu_request_undo", {"approval_id": rid})
        self.assertEqual(again["status"], "queued_for_approval")

    def test_an_undo_that_cannot_happen_does_not_bother_the_user(self):
        rig, user = Rig(), User()
        out = tool(rig, user, "ryu_request_undo", {"approval_id": "nope"})
        self.assertFalse(out["ok"])
        self.assertEqual(user.shown, [])


class DirectMode(unittest.TestCase):
    def test_a_strong_change_is_confirmed_before_a_direct_apply(self):
        rig = Rig(write_mode="direct")
        rig.fake.seed(257, {"in_port": 1}, FWD, priority=100)
        declined = tool(rig, User(("decline", None)), "ryu_delete_flow", DELETE)
        self.assertEqual((declined["status"], rig.fake.writes), ("declined", []))
        yes = tool(rig, User(), "ryu_delete_flow", DELETE)
        self.assertEqual(yes["status"], "applied")
        self.assertEqual(rig.fake.flows[257], {})


if __name__ == "__main__":
    unittest.main()
