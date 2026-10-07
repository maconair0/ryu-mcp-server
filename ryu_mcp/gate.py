"""Writes are requested by a tool and performed by an operator decision.

A write tool validates the flow, checks the rate limit, appends to an approval
queue on disk, and returns the queue id. Nothing reaches Ryu until an operator
runs `--approve <id>` and the drain loop issues it.

There is no tool argument that skips this: no `force`, no `approved=True`. A
flag the model can set is a flag the model will set. The one bypass is
`RYU_MCP_WRITE_MODE=direct`, chosen by whoever starts the server — for a host
system that already puts a person in front of every change and would otherwise
ask twice.
"""
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

POLICIES: Dict[str, Dict[str, Any]] = {
    "ryu_add_flow": {"risk_tier": "medium", "max_changes_per_hour": 30},
    "ryu_delete_flow": {"risk_tier": "high", "max_changes_per_hour": 20},
    "ryu_map_vlan": {"risk_tier": "medium", "max_changes_per_hour": 20},
    # Removing a mapping cuts a service off: high, like deleting a flow.
    "ryu_unmap_vlan": {"risk_tier": "high", "max_changes_per_hour": 20},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WriteGate:
    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.queue_path = os.path.join(state_dir, "queue.json")
        self.audit_path = os.path.join(state_dir, "audit.jsonl")
        self._lock = threading.RLock()

    # ----- storage -----

    def _load(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.queue_path) as fh:
                return {i["id"]: i for i in json.load(fh)}
        except (OSError, ValueError):
            return {}

    def _save(self, items: Dict[str, Dict[str, Any]]) -> None:
        tmp = self.queue_path + ".tmp"
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

    # ----- requesting -----

    def request(self, action: str, summary: str, calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        policy = POLICIES.get(action, {"risk_tier": "high", "max_changes_per_hour": 0})
        with self._lock:
            items = self._load()
            used = self._used_last_hour(items, action)
            if used >= policy["max_changes_per_hour"]:
                self.audit({"event": "rate_limited", "action": action})
                return {"status": "refused",
                        "reason": f"rate limit for {action}: {used}/"
                                  f"{policy['max_changes_per_hour']} in the last hour"}
            item = {"id": uuid.uuid4().hex[:12], "action": action, "summary": summary,
                    "calls": calls, "state": "pending", "created": _now(),
                    "created_ts": time.time(), "risk_tier": policy["risk_tier"]}
            items[item["id"]] = item
            self._save(items)
        self.audit({"event": "queued", "id": item["id"], "action": action})
        return {"status": "queued_for_approval", "approval_id": item["id"],
                "action": action, "summary": summary, "risk_tier": policy["risk_tier"],
                "calls": len(calls),
                "what_happens_next": ("Nothing was sent to Ryu. An operator approves "
                                      f"with `run_ryu_mcp.py --approve {item['id']}`; "
                                      "only then are the flows installed.")}

    # ----- operator side, never exposed as a tool -----

    def pending(self) -> List[Dict[str, Any]]:
        return [i for i in self._load().values() if i["state"] == "pending"]

    def decide(self, item_id: str, approve: bool) -> Dict[str, Any]:
        with self._lock:
            items = self._load()
            item = items.get(item_id)
            if item is None or item["state"] != "pending":
                return {"ok": False, "reason": f"no pending item {item_id}"}
            item["state"] = "approved" if approve else "rejected"
            item["decided"] = _now()
            self._save(items)
        self.audit({"event": item["state"], "id": item_id})
        return {"ok": True, "id": item_id, "state": item["state"]}

    async def apply_approved(self, client) -> Dict[str, Any]:
        applied, failed = [], []
        with self._lock:
            items = self._load()
        for item in [i for i in items.values() if i["state"] == "approved"]:
            try:
                for call in item["calls"]:
                    await client.post(call["path"], call["body"])
                item["state"], item["result"] = "applied", "ok"
                applied.append(item["id"])
            except Exception as e:  # noqa: BLE001
                item["state"], item["result"] = "failed", f"{type(e).__name__}: {e}"
                failed.append({"id": item["id"], "error": str(e)})
            item["applied"] = _now()
            self.audit({"event": item["state"], "id": item["id"],
                        "result": item.get("result")})
        with self._lock:
            current = self._load()
            for item in items.values():
                if item["id"] in current and item["state"] in ("applied", "failed"):
                    current[item["id"]] = item
            self._save(current)
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
                for call in item["calls"]:
                    await client.post(call["path"], call["body"])
                replayed.append(item["id"])
            except Exception as e:  # noqa: BLE001
                failed.append({"id": item["id"], "error": str(e)})
        self.audit({"event": "replayed", "ids": replayed, "failed": failed})
        return {"replayed": replayed, "failed": failed}
