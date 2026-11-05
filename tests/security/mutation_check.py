"""Break each safety guard on purpose and confirm something notices.

    python -m tests.security.mutation_check

Each mutant is a scratch copy of the package with one guard disabled. It is
*killed* if the unit tests or the adversarial run then fail. A surviving mutant
is a guard nothing tests — the thing this exists to find.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# (name, file, old, new)
MUTANTS = [
    ("writes apply without approval", "ryu_mcp/server.py",
     'if cfg.write_mode == "direct" and not critical:', "if True:"),
    ("critical changes obey direct mode", "ryu_mcp/server.py",
     'if cfg.write_mode == "direct" and not critical:', 'if cfg.write_mode == "direct":'),
    ("no approver token configured still approves", "ryu_mcp/server.py",
     "if not cfg.approver_token:", "if False:"),
    ("wrong approver token accepted", "ryu_mcp/server.py",
     "if not hmac.compare_digest(str(approver_token).encode(), cfg.approver_token.encode()):", "if False:"),
    ("token guessing never locks out", "ryu_mcp/server.py",
     "TOKEN_STRIKES, TOKEN_LOCKOUT_S = 5, 300", "TOKEN_STRIKES, TOKEN_LOCKOUT_S = 5, 0"),
    ("approval not bound to a digest", "ryu_mcp/gate.py",
     'if expected_digest and expected_digest != item.get("digest"):', "if False:"),
    ("queue tampering goes unnoticed", "ryu_mcp/gate.py",
     'if item.get("digest") != _digest(item["action"], item["calls"]):\n            self.audit({"event": "tamper_detected", "id": item["id"]})\n            raise',
     'if False:\n            self.audit({"event": "tamper_detected", "id": item["id"]})\n            raise'),
    ("approvals never expire", "ryu_mcp/gate.py",
     "return bool(self.ttl) and time.time() - item.get(\"created_ts\", 0) > self.ttl", "return False"),
    ("no cross-process lock", "ryu_mcp/gate.py",
     "fcntl.flock(fh, fcntl.LOCK_EX)", "pass"),
    ("rate limit off", "ryu_mcp/gate.py",
     'if used >= policy["max_changes_per_hour"]:', "if False:"),
    ("risk never reaches critical", "ryu_mcp/gate.py",
     '_worse(tier, "critical")', '_worse(tier, "high")'),
    ("undo ignores the state it replaced", "ryu_mcp/gate.py",
     "return [f for f in flows if _same_flow(f, body)]", "return []"),
    ("failed request not rolled back", "ryu_mcp/gate.py",
     "            if sent:\n                back =", "            if False:\n                back ="),
    ("out-of-order undo allowed", "ryu_mcp/gate.py",
     "        if later:\n            return None, None,", "        if False:\n            return None, None,"),
    ("action arguments unchecked", "ryu_mcp/schemas.py",
     'if action.get(need) in (None, ""):', "if False:"),
    ("match values unchecked", "ryu_mcp/schemas.py",
     "if key in INT_MATCH:", "if False:"),
    ("a flow the switch refused is called applied", "ryu_mcp/gate.py",
     "            if bad:\n                raise RuntimeError(bad[0])", "            if False:\n                raise RuntimeError(bad[0])"),
    ("flows compared under the request's names, not Ryu's", "ryu_mcp/gate.py",
     "name = MATCH_ALIASES.get(key, key)", "name = key"),
    ("match prerequisites unchecked", "ryu_mcp/schemas.py",
     "    _check_prerequisites(match)\n    return dict(match)", "    return dict(match)"),
    ("action type left in the caller's case", "ryu_mcp/schemas.py",
     'return {**action, "type": kind}', "return dict(action)"),
    ("a killed apply stays 'applying' forever", "ryu_mcp/gate.py",
     'stuck = [i for i in self._load().values() if i["state"] == "applying" and self._abandoned(i)]',
     "stuck = []"),
    ("recovery trusts a live process's claim as dead", "ryu_mcp/gate.py",
     "return not self._alive(int(by[\"pid\"]))", "return True"),
    ("a strong write is queued without asking", "ryu_mcp/confirm.py",
     'return mode == "all" or (mode == "strong" and tier in ("high", "critical"))', "return False"),
    ("a declined confirmation still queues", "ryu_mcp/server.py",
     '        if got["state"] == "declined":', '        if False:'),
    ("silence counts as yes", "ryu_mcp/confirm.py",
     'return {"state": "declined", "reason": f"no answer within {timeout:g} s"}',
     'return {"state": "confirmed", "by": "timeout"}'),
    ("a click is enough for a critical change", "ryu_mcp/confirm.py",
     'if critical and str(getattr(res.data, "code", "")).strip().lower() != code_of(digest):', "if False:"),
    ("strict mode lets an unaskable client through", "ryu_mcp/server.py",
     'if got["state"] == "unavailable" and cfg.confirm_strict:', "if False:"),
    ("an undo is queued without asking", "ryu_mcp/server.py",
     '            confirmation, refusal = await _confirmed("ryu_undo", preview["summary"], preview["calls"], ctx)\n            if refusal:\n                return refusal\n',
     "            confirmation = None\n"),
    ("datapath id range unchecked", "ryu_mcp/client.py",
     "if not 0 <= n < 2 ** 64:", "if False:"),
]


def run(cwd: str, *args: str) -> int:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-W", "ignore", *args], cwd=cwd, env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600).returncode


def main() -> int:
    if run(ROOT, "-m", "unittest", "discover", "-s", "tests/unit", "-t", ".") or \
       run(ROOT, "-m", "tests.security.adversarial", "--fuzz", "600", "--runs", "1"):
        print("the unmodified code does not pass; fix that first")
        return 2
    rows, survived = [], 0
    for name, rel, old, new in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            for part in ("ryu_mcp", "tests", "run_ryu_mcp.py"):
                src = os.path.join(ROOT, part)
                (shutil.copytree if os.path.isdir(src) else shutil.copy)(
                    src, os.path.join(tmp, part),
                    **({"ignore": shutil.ignore_patterns("__pycache__", "state")} if os.path.isdir(src) else {}))
            path = os.path.join(tmp, rel)
            text = open(path).read()
            if text.count(old) < 1 or (text.count(old) > 1 and name != "risk never reaches critical"):
                print(f"cannot place mutant {name!r}: found {text.count(old)} times in {rel}")
                return 2
            open(path, "w").write(text.replace(old, new))
            by_unit = run(tmp, "-m", "unittest", "discover", "-s", "tests/unit", "-t", ".") != 0
            by_adv = run(tmp, "-m", "tests.security.adversarial", "--fuzz", "600", "--runs", "1") != 0
        killed = by_unit or by_adv
        survived += not killed
        rows.append((name, by_unit, by_adv, killed))
    print("| guard disabled | unit tests | adversarial run | caught |")
    print("|---|:---:|:---:|:---:|")
    for name, u, a, k in rows:
        print(f"| {name} | {'fail' if u else 'pass'} | {'fail' if a else 'pass'} | {'yes' if k else '**NO**'} |")
    print(f"\n{len(rows) - survived}/{len(rows)} mutants caught")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
