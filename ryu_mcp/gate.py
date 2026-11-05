"""Writes are requested by a tool and performed by an operator decision.

A write tool validates the flow, checks the rate limit, appends to an approval
queue on disk, and returns the queue id. Nothing reaches Ryu until an operator
runs `--approve <id>` and the drain loop issues it.

There is no tool argument that skips this: no `force`, no `approved=True`. A
flag the model can set is a flag the model will set. The one bypass is
`RYU_MCP_WRITE_MODE=direct`, chosen by whoever starts the server — for a host
system that already puts a person in front of every change and would otherwise
ask twice. A change assessed as *critical* is queued even then.

What the gate adds around that rule, because approval alone does not make a
change safe to apply:

* every request is assessed, so the person approving sees a risk tier and the
  reasons for it (`assess`);
* every request carries a digest of what will be sent, checked again when it is
  applied, so an entry edited after it was requested is refused (`_digest`);
* a request expires, so an approval is not applied to a network that has moved
  on since it was asked for (`ttl`);
* an approved request is claimed under a lock before anything is sent, so two
  drains, or a drain and an MCP approval, cannot apply it twice;
* the state a change replaces is read before it is sent and kept, so a change
  can be undone exactly — and the undo is itself a request that waits for
  approval (`request_undo`).
"""
import contextlib
import fcntl
import hashlib
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

POLICIES: Dict[str, Dict[str, Any]] = {
    "ryu_add_flow": {"risk_tier": "medium", "max_changes_per_hour": 30},
    "ryu_delete_flow": {"risk_tier": "high", "max_changes_per_hour": 20},
    "ryu_map_vlan": {"risk_tier": "medium", "max_changes_per_hour": 20},
    # Removing a mapping cuts a service off: high, like deleting a flow.
    "ryu_unmap_vlan": {"risk_tier": "high", "max_changes_per_hour": 20},
    # An undo is a change like any other and waits for approval like one. Its cap
    # is the sum of the others': recovery must not run out before the changes do.
    "ryu_undo": {"risk_tier": "high", "max_changes_per_hour": 100},
}
TIERS = ("low", "medium", "high", "critical")
DEFAULT_TTL = 3600  # seconds a request stays approvable; 0 means it never expires


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(action: str, calls: List[Dict[str, Any]]) -> str:
    """What will be sent, fingerprinted: the action and every call, canonically."""
    blob = json.dumps({"action": action, "calls": calls}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _worse(a: str, b: str) -> str:
    return a if TIERS.index(a) >= TIERS.index(b) else b


FORWARDING = {"OUTPUT", "GROUP", "GOTO_TABLE"}


def assess(action: str, calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The risk tier of a request and why, from what it would do to the switch.

    The tier an action starts at is its policy; it only goes up. What raises it
    is blast radius, not wording: a wildcard flow with no forwarding action
    drops every packet on the switch, and deleting the priority-0 flow stops the
    switch asking the controller what to do with anything new.
    """
    tier = POLICIES.get(action, {"risk_tier": "high"})["risk_tier"]
    reasons: List[str] = []
    for call in calls:
        body = call.get("body") or {}
        match, acts = body.get("match") or {}, body.get("actions") or []
        priority = int(body.get("priority", 0))
        deleting = "delete" in str(call.get("path", ""))
        forwards = any(str(a.get("type", "")).upper() in FORWARDING for a in acts)
        if deleting and not match:
            if priority == 0:
                tier = _worse(tier, "critical")
                reasons.append("removes the table-miss flow: the switch stops asking "
                               "the controller about any new traffic")
            else:
                tier = _worse(tier, "high")
                reasons.append(f"removes a wildcard flow at priority {priority}")
        elif not deleting and not match and not forwards:
            tier = _worse(tier, "critical")
            reasons.append("a wildcard flow with no forwarding action drops every "
                           "packet on the switch")
        elif not deleting and not match:
            tier = _worse(tier, "high")
            reasons.append(f"a wildcard forwarding flow at priority {priority} "
                           "overrides every lower-priority flow")
        elif not deleting and set(match) == {"in_port"} and not forwards:
            tier = _worse(tier, "high")
            reasons.append(f"drops all traffic from port {match['in_port']}")
        if not deleting and priority >= 60000:
            tier = _worse(tier, "high")
            reasons.append(f"priority {priority} can shadow every other flow")
    if len(calls) > 10:
        tier = _worse(tier, "high")
        reasons.append(f"bulk change: {len(calls)} flow operations in one request")
    return {"risk_tier": tier, "risk_reasons": reasons}


# ----- exact undo: read what a change replaces, before sending it -----

def _keys(calls: List[Dict[str, Any]]) -> set:
    """The flows a request touches, by what identifies one: switch, table, priority, match."""
    return {(c["body"]["dpid"], c["body"].get("table_id", 0), c["body"].get("priority", 0),
             json.dumps(canon_match(c["body"].get("match")), sort_keys=True)) for c in calls}


# Ryu reports a match under the names of the older OpenFlow 1.0 API, whichever
# it was asked in: the same field has two spellings and the request's is not
# the one that comes back. Read off a live Ryu 4.34.
MATCH_ALIASES = {"eth_type": "dl_type", "eth_src": "dl_src", "eth_dst": "dl_dst",
                 "ipv4_src": "nw_src", "ipv4_dst": "nw_dst", "ip_proto": "nw_proto",
                 "tcp_src": "tp_src", "tcp_dst": "tp_dst", "udp_src": "tp_src", "udp_dst": "tp_dst",
                 "vlan_vid": "dl_vlan"}


def canon_match(match: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """A match in one spelling, so a request's and a switch's can be compared.

    Names are mapped to the ones Ryu reports; numbers written as "0x1", "1" or 1
    compare equal; a VLAN id compares without the OFPVID_PRESENT bit (4106 and 10
    are both VLAN 10, as Ryu 4.34 and Open vSwitch treat them); MACs ignore case.
    """
    out: Dict[str, str] = {}
    for key, value in (match or {}).items():
        name = MATCH_ALIASES.get(key, key)
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                value = value.lower()
        if name == "dl_vlan" and isinstance(value, int):
            value &= 0x0FFF
        out[name] = str(value)
    return out


def _same_flow(flow: Dict[str, Any], body: Dict[str, Any]) -> bool:
    return (int(flow.get("priority", -1)) == int(body.get("priority", 0))
            and int(flow.get("table_id", 0)) == int(body.get("table_id", 0))
            and canon_match(flow.get("match")) == canon_match(body.get("match")))


async def _pre_image(client, call: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Flows the call would replace or remove, read first. None: could not read.

    `/stats/flow` filters loosely, so the exact flow (same match, priority and
    table) is picked out here. Reads only: nothing is sent that changes state.
    """
    body = call.get("body") or {}
    try:
        got = await client.post(f"/stats/flow/{body['dpid']}",
                                {"table_id": body.get("table_id", 0),
                                 "match": body.get("match", {})})
        flows = (got or {}).get(str(body["dpid"]))
    except Exception:  # noqa: BLE001
        return None
    if flows is None:
        return None
    return [f for f in flows if _same_flow(f, body)]


def _action_kinds(actions: List[Any]) -> List[str]:
    """The types of a flow's actions, from a request (dicts) or from stats (strings).

    "DROP" is this server's word for no actions; Ryu has no such action.
    """
    kinds = [str(a.get("type", "")).upper() if isinstance(a, dict) else str(a).split(":")[0].strip().upper()
             for a in actions]
    return [k for k in kinds if k != "DROP"]


async def _verify(client, call: Dict[str, Any]) -> Tuple[str, str]:
    """Is the switch now as the call says? ("ok" | "unread" | "bad", why).

    `ofctl_rest` answers 200 to a flow Open vSwitch then refuses — a missing
    prerequisite, a group that does not exist, an action the switch lacks — so a
    successful reply proves nothing. The flow table is read back and the answer
    is a reason, not a guess. "unread": the table could not be read, so nothing
    is claimed either way.
    """
    body = call["body"]
    found = await _pre_image(client, call)
    if found is None:
        return "unread", "could not read the flow table back"
    if "delete" in call["path"]:
        if found:
            return "bad", (f"flow still present after delete: match {body.get('match')} "
                           f"priority {body.get('priority')}")
        return "ok", ""
    if not found:
        return "bad", (f"the switch does not hold the flow Ryu accepted: match {body.get('match')} "
                       f"priority {body.get('priority')} (Ryu answers 200 to flows the switch refuses)")
    if _action_kinds(found[0].get("actions", [])) != _action_kinds(body.get("actions") or []):
        return "bad", (f"the switch holds different actions than requested: {found[0].get('actions')} "
                       f"for {[a.get('type') for a in body.get('actions') or []]}")
    return "ok", ""


def _action_from_stats(text: str) -> Optional[Dict[str, Any]]:
    """`ofctl_rest` reports actions as strings and takes them as dicts.

    "OUTPUT:3", "PUSH_VLAN:33024", "POP_VLAN", "SET_FIELD: {vlan_vid:4198}",
    "GROUP:1". Anything else is not guessed at: the caller then knows the undo
    would not be exact.
    """
    text = str(text).strip()
    try:
        if text == "POP_VLAN":
            return {"type": "POP_VLAN"}
        kind, _, rest = text.partition(":")
        rest = rest.strip()
        if kind == "OUTPUT":
            return {"type": "OUTPUT", "port": int(rest) if rest.isdigit() else rest}
        if kind == "GROUP":
            return {"type": "GROUP", "group_id": int(rest)}
        if kind == "PUSH_VLAN":
            return {"type": "PUSH_VLAN", "ethertype": int(rest)}
        if kind == "SET_FIELD":
            field, _, value = rest.strip("{} ").partition(":")
            return {"type": "SET_FIELD", "field": field.strip(), "value": int(value)}
    except ValueError:
        return None
    return None


def _restore(dpid: Any, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    acts = [_action_from_stats(a) for a in flow.get("actions", [])]
    if any(a is None for a in acts):
        return None
    return {"path": "/stats/flowentry/add", "body": {
        "dpid": dpid, "cookie": int(flow.get("cookie", 0)),
        "table_id": int(flow.get("table_id", 0)),
        "idle_timeout": int(flow.get("idle_timeout", 0)),
        "hard_timeout": int(flow.get("hard_timeout", 0)),
        "priority": int(flow.get("priority", 0)), "flags": int(flow.get("flags", 0)),
        "match": dict(flow.get("match") or {}), "actions": acts}}


def build_undo(calls: List[Dict[str, Any]],
               pre: List[Optional[List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """The calls that put back what `calls` replaced, newest first, and whether exact.

    An add over nothing is undone by deleting it; an add over an existing flow,
    or a delete of one, by adding the old flow back as it was read. If the old
    state could not be read, or has an action this does not know, the undo is
    not offered as exact — a delete that removes a flow it should have restored
    is worse than no undo.
    """
    undo: List[Dict[str, Any]] = []
    exact = True
    for call, before in reversed(list(zip(calls, pre))):
        body = call["body"]
        adding = "add" in call["path"] and "delete" not in call["path"]
        if before is None:
            exact = False
            continue
        if not before:
            if adding:
                undo.append({"path": "/stats/flowentry/delete_strict",
                             "body": {**body, "actions": []}})
            continue  # deleting what was not there changed nothing
        for flow in before:
            restored = _restore(body["dpid"], flow)
            if restored is None:
                exact = False
            else:
                undo.append(restored)
    return {"calls": undo, "exact": exact}


class WriteGate:
    def __init__(self, state_dir: str, ttl: int = DEFAULT_TTL):
        self.state_dir = state_dir
        self.ttl = ttl
        os.makedirs(state_dir, exist_ok=True)
        self.queue_path = os.path.join(state_dir, "queue.json")
        self.audit_path = os.path.join(state_dir, "audit.jsonl")
        self.lock_path = os.path.join(state_dir, ".lock")
        self._lock = threading.RLock()

    # ----- storage -----

    @contextlib.contextmanager
    def _txn(self):
        """One writer at a time, across threads and across processes.

        The CLI (`--approve`, `--drain`) and the running server are separate
        processes sharing one queue file; a thread lock alone would let both
        read an approved request and both apply it.
        """
        with self._lock:
            with open(self.lock_path, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.queue_path) as fh:
                return {i["id"]: i for i in json.load(fh)}
        except (OSError, ValueError):
            return {}

    def _save(self, items: Dict[str, Dict[str, Any]]) -> None:
        tmp = f"{self.queue_path}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w") as fh:
            json.dump(list(items.values()), fh, indent=1)
        os.replace(tmp, self.queue_path)

    def audit(self, event: Dict[str, Any]) -> None:
        with open(self.audit_path, "a") as fh:
            fh.write(json.dumps({"at": _now(), **event}) + "\n")

    def _used_last_hour(self, items, action: str) -> int:
        cutoff = time.time() - 3600
        return sum(1 for i in items.values()
                   if i["action"] == action and i.get("created_ts", 0) > cutoff)

    def _expired(self, item: Dict[str, Any]) -> bool:
        return bool(self.ttl) and time.time() - item.get("created_ts", 0) > self.ttl

    def assess(self, action: str, calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        return assess(action, calls)

    # ----- requesting -----

    def request(self, action: str, summary: str, calls: List[Dict[str, Any]],
                undoes: Optional[str] = None,
                confirmation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        policy = POLICIES.get(action, {"risk_tier": "high", "max_changes_per_hour": 0})
        risk = assess(action, calls)
        with self._txn():
            items = self._load()
            used = self._used_last_hour(items, action)
            if used >= policy["max_changes_per_hour"]:
                self.audit({"event": "rate_limited", "action": action})
                return {"status": "refused",
                        "reason": f"rate limit for {action}: {used}/"
                                  f"{policy['max_changes_per_hour']} in the last hour"}
            now = time.time()
            item = {"id": uuid.uuid4().hex[:12], "action": action, "summary": summary,
                    "calls": calls, "state": "pending", "created": _now(),
                    "created_ts": now, "digest": _digest(action, calls), **risk}
            if undoes:
                item["undoes"] = undoes
            if confirmation:
                item["confirmation"] = confirmation
            items[item["id"]] = item
            self._save(items)
        self.audit({"event": "queued", "id": item["id"], "action": action,
                    "risk_tier": risk["risk_tier"], "digest": item["digest"],
                    **({"confirmation": confirmation["state"]} if confirmation else {})})
        return {"status": "queued_for_approval", "approval_id": item["id"],
                "action": action, "summary": summary, "calls": len(calls),
                "digest": item["digest"], **risk,
                **({"confirmation": confirmation} if confirmation else {}),
                "expires_in_s": self.ttl or None,
                "what_happens_next": ("Nothing was sent to Ryu. An operator approves "
                                      f"with `run_ryu_mcp.py --approve {item['id']}`; "
                                      "only then are the flows installed. Once applied, "
                                      "`ryu_request_undo` queues the exact inverse.")}

    def _undo_candidate(self, items: Dict[str, Dict[str, Any]], item_id: str):
        """(item, undo, error): what undoing `item_id` would be, or why it cannot be."""
        item = items.get(item_id)
        if item is None:
            return None, None, f"no request {item_id}"
        if item["state"] != "applied":
            return None, None, f"{item_id} is {item['state']}, not applied: there is nothing to undo"
        undo = item.get("undo") or {}
        if item.get("undo_requested"):
            return None, None, f"an undo of {item_id} is already queued as {item['undo_requested']}"
        later = [i for i in items.values()
                 if i["state"] == "applied" and not i.get("undone")
                 and i["id"] != item.get("undo_requested")
                 # an undo that reversed its target nets out with it
                 and not (i.get("undoes") and (items.get(i["undoes"]) or {}).get("undone") == i["id"])
                 and (i.get("applied") or "") > (item.get("applied") or "")
                 and _keys(i["calls"]) & _keys(item["calls"])]
        if later:
            return None, None, (f"{later[0]['id']} ({later[0]['action']}) changed the same flow(s) after "
                                f"this one; undo that first, or this would bring back state that is "
                                f"no longer current")
        if not undo.get("calls"):
            return None, None, ("no undo is recorded for this change: "
                                + ("the state it replaced could not be read"
                                   if not undo.get("exact", False) else "it changed nothing"))
        return item, undo, ""

    def preview_undo(self, item_id: str) -> Dict[str, Any]:
        """What `request_undo` would queue, without queueing it: so a person can be asked first."""
        with self._txn():
            item, undo, err = self._undo_candidate(self._load(), item_id)
        if err:
            return {"ok": False, "error": err}
        action, summary = "ryu_undo", f"undo {item['action']}: {item['summary']}"
        return {"ok": True, "action": action, "summary": summary, "calls": undo["calls"],
                "exact": bool(undo.get("exact")), **assess(action, undo["calls"]),
                "digest": _digest(action, undo["calls"])}

    def request_undo(self, item_id: str,
                     confirmation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Queue the inverse of an applied write. It waits for approval like any write."""
        with self._txn():
            item, undo, err = self._undo_candidate(self._load(), item_id)
        if err:
            return {"ok": False, "error": err}
        out = self.request("ryu_undo", f"undo {item['action']}: {item['summary']}",
                           undo["calls"], undoes=item_id, confirmation=confirmation)
        if out.get("status") != "queued_for_approval":
            return {"ok": False, **out}
        with self._txn():
            items = self._load()
            if item_id in items:
                items[item_id]["undo_requested"] = out["approval_id"]
                self._save(items)
        return {"ok": True, **out, "exact": bool(undo.get("exact"))}

    # ----- operator side, never exposed as a tool -----

    def pending(self) -> List[Dict[str, Any]]:
        return [i for i in self._load().values()
                if i["state"] == "pending" and not self._expired(i)]

    def decide(self, item_id: str, approve: bool) -> Dict[str, Any]:
        with self._txn():
            items = self._load()
            item = items.get(item_id)
            if item is None or item["state"] != "pending":
                return {"ok": False, "reason": f"no pending item {item_id}"}
            if self._expired(item):
                item["state"] = "expired"
                self._save(items)
                self.audit({"event": "expired", "id": item_id})
                return {"ok": False, "reason": f"{item_id} expired after {self.ttl}s; "
                                               "ask for it again"}
            item["state"] = "approved" if approve else "rejected"
            item["decided"] = _now()
            self._save(items)
        self.audit({"event": item["state"], "id": item_id})
        return {"ok": True, "id": item_id, "state": item["state"]}

    async def _perform(self, item: Dict[str, Any], client) -> None:
        """Send one claimed request. Raises if it must not be sent."""
        if item.get("digest") != _digest(item["action"], item["calls"]):
            self.audit({"event": "tamper_detected", "id": item["id"]})
            raise ValueError("queue entry no longer matches what was requested "
                             "(digest mismatch); nothing was sent")
        # Read every call's pre-image first, then send: so an undo of the whole
        # request is built from the state before any of it was applied.
        pre = [await _pre_image(client, c) for c in item["calls"]]
        # Kept on disk before anything is sent: if this process dies partway,
        # recovery needs the state before the change to put it back.
        item["pre"] = pre
        with self._txn():
            current = self._load()
            if item["id"] in current:
                current[item["id"]]["pre"] = pre
                self._save(current)
        sent = 0
        try:
            for call in item["calls"]:
                await client.post(call["path"], call["body"])
                sent += 1
            # Sent is not done: read it back, and treat a flow the switch did
            # not take like a flow Ryu refused.
            checks = [await _verify(client, call) for call in item["calls"]]
            bad = [why for status, why in checks if status == "bad"]
            if bad:
                raise RuntimeError(bad[0])
            item["verified"] = all(status == "ok" for status, _ in checks)
        except Exception:
            # A request is one change, not a list of them: half a VLAN mapping
            # carries traffic out and none back. What was already sent is put
            # back from the pre-image, then the failure is raised as usual.
            if sent:
                back = build_undo(item["calls"][:sent], pre[:sent])
                restored = True
                for call in back["calls"]:
                    try:
                        await client.post(call["path"], call["body"])
                    except Exception:  # noqa: BLE001
                        restored = False
                item["rollback"] = {"sent": sent, "of": len(item["calls"]),
                                    "restored": restored and back["exact"]}
                self.audit({"event": "rolled_back", "id": item["id"], **item["rollback"]})
            raise
        item["undo"] = build_undo(item["calls"], pre)

    def _claim(self, items, item) -> None:
        item["state"], item["claimed"] = "applying", _now()
        item["claimed_by"] = {"pid": os.getpid(), "host": socket.gethostname(), "ts": time.time()}

    def _finish(self, item: Dict[str, Any], error: Optional[Exception]) -> None:
        if error is None:
            item["state"], item["result"] = "applied", "ok"
        else:
            item["state"], item["result"] = "failed", f"{type(error).__name__}: {error}"
        item["applied"] = _now()
        with self._txn():
            current = self._load()
            if item["id"] in current:
                current[item["id"]] = item
                target = current.get(item.get("undoes") or "")
                if target is not None and item["state"] == "applied":
                    target["undone"] = item["id"]
                self._save(current)
        self.audit({"event": item["state"], "id": item["id"], "result": item["result"]})

    CLAIM_STALE_S = 600

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _abandoned(self, item: Dict[str, Any]) -> bool:
        """Claimed by a process that is gone — or, from another host, long ago."""
        by = item.get("claimed_by") or {}
        if by.get("host") == socket.gethostname() and by.get("pid"):
            return not self._alive(int(by["pid"]))
        return time.time() - by.get("ts", 0) > self.CLAIM_STALE_S

    async def recover(self, client) -> Dict[str, Any]:
        """Settle requests whose process died after claiming them.

        A request is claimed ("applying") before anything is sent. If the process
        is killed from then on, nothing else would ever touch it, and the switch
        may hold none, some or all of it. The flow table says which: all of it
        means it was applied; none, that it was not; some, and what landed is
        taken back from the state saved before sending, so a half-built circuit
        is not left behind. A switch that cannot be read is left alone.
        """
        with self._txn():
            stuck = [i for i in self._load().values() if i["state"] == "applying" and self._abandoned(i)]
        report = {"settled": [], "left": []}
        for item in stuck:
            calls = item["calls"]
            pre = item.get("pre") or [None] * len(calls)
            checks = [await _verify(client, c) for c in calls]
            if any(st == "unread" for st, _ in checks):
                report["left"].append({"id": item["id"], "why": "the flow table could not be read"})
                continue
            landed = [k for k, (st, _) in enumerate(checks) if st == "ok"]
            item["recovered"] = True
            if len(landed) == len(calls):
                item["verified"] = True
                item["undo"] = build_undo(calls, pre)
                outcome, why = None, "ok"
            elif not landed:
                outcome, why = RuntimeError("interrupted before anything was applied; nothing landed"), None
            else:
                back = build_undo([calls[k] for k in landed], [pre[k] for k in landed])
                restored = True
                for call in back["calls"]:
                    try:
                        await client.post(call["path"], call["body"])
                    except Exception:  # noqa: BLE001
                        restored = False
                item["rollback"] = {"sent": len(landed), "of": len(calls),
                                    "restored": restored and back["exact"], "after": "interruption"}
                self.audit({"event": "rolled_back", "id": item["id"], **item["rollback"]})
                outcome = RuntimeError(f"interrupted after {len(landed)} of {len(calls)} flows landed; "
                                       f"what landed was taken back")
            self._finish(item, outcome)
            report["settled"].append({"id": item["id"], "state": item["state"]})
        return report

    async def apply_approved(self, client) -> Dict[str, Any]:
        applied, failed = [], []
        with self._txn():
            items = self._load()
            claimed = []
            for item in [i for i in items.values() if i["state"] == "approved"]:
                if self._expired(item):
                    item["state"] = "expired"
                    self.audit({"event": "expired", "id": item["id"]})
                    continue
                self._claim(items, item)
                claimed.append(item)
            self._save(items)
        for item in claimed:
            try:
                await self._perform(item, client)
                self._finish(item, None)
                applied.append(item["id"])
            except Exception as e:  # noqa: BLE001
                self._finish(item, e)
                failed.append({"id": item["id"], "error": str(e)})
        return {"applied": applied, "failed": failed}

    async def replay_applied(self, client) -> Dict[str, Any]:
        """Re-send every write that was approved and applied, oldest first.

        Ryu keeps no flows of its own: they live in the switches, and a switch
        that restarts comes back empty. Approval was given once for the state
        these writes describe, so putting that state back is not a new change;
        replaying in the order they were applied keeps a later delete after the
        add it removes.
        """
        with self._lock:
            items = self._load()
        done = sorted((i for i in items.values() if i["state"] == "applied"),
                      key=lambda i: i.get("applied") or "")
        replayed, failed = [], []
        for item in done:
            try:
                if item.get("digest") != _digest(item["action"], item["calls"]):
                    self.audit({"event": "tamper_detected", "id": item["id"]})
                    raise ValueError("digest mismatch; not replayed")
                for call in item["calls"]:
                    await client.post(call["path"], call["body"])
                replayed.append(item["id"])
            except Exception as e:  # noqa: BLE001
                failed.append({"id": item["id"], "error": str(e)})
        self.audit({"event": "replayed", "ids": replayed, "failed": failed})
        return {"replayed": replayed, "failed": failed}

    async def approve_and_apply(self, item_id: str, client, by: str,
                                expected_digest: str = "") -> Dict[str, Any]:
        """Approve one pending write and apply it now — that one only.

        For a host that has already had a person confirm this exact change;
        `by` names who, for the audit trail. A host that shows the person a
        digest can hand it back as `expected_digest`: the approval then holds
        only for the request that person saw.
        """
        with self._txn():
            items = self._load()
            item = items.get(item_id)
            if item is None:
                return {"ok": False, "error": f"no queued request {item_id}"}
            if item["state"] != "pending":
                return {"ok": False, "error": f"{item_id} is already {item['state']}"}
            if self._expired(item):
                item["state"] = "expired"
                self._save(items)
                self.audit({"event": "expired", "id": item_id})
                return {"ok": False, "error": f"{item_id} expired after {self.ttl}s; "
                                              "ask for it again"}
            if expected_digest and expected_digest != item.get("digest"):
                self.audit({"event": "approval_refused_digest", "id": item_id, "by": by})
                return {"ok": False, "error": "digest does not match the request that "
                                              "was queued; not approved"}
            item["state"], item["decided"] = "approved", _now()
            self._claim(items, item)
            self._save(items)
        self.audit({"event": "approved", "id": item_id, "by": by})
        error: Optional[Exception] = None
        try:
            await self._perform(item, client)
        except Exception as e:  # noqa: BLE001
            error = e
        self._finish(item, error)
        return {"ok": item["state"] == "applied", "id": item_id, "state": item["state"],
                "action": item.get("action"), "summary": item.get("summary"),
                "verified": item.get("verified"),
                **({"error": item["result"]} if item["state"] == "failed" else {})}
