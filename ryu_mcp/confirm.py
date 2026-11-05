"""Asking the person, through the client, before a strong change is queued.

A flag the model can set is a flag the model will set, so the confirmation is not
an argument of any tool. The server puts the question to the user itself, over
MCP's elicitation, in words it writes from the request it validated: the model
cannot soften what the person is shown, and cannot answer for them. The answer
comes back from the client, not through the model.

  confirmed    the person said yes
  declined     said no, dismissed the question, gave the wrong code, or did not
               answer in time (silence is a no): the change is not queued
  unavailable  the client cannot ask (no elicitation): by default the operator's
               approval alone stands; with RYU_MCP_CONFIRM_STRICT the change is refused

Which changes: "strong" is a high or critical risk (a delete, an unmap, an undo, a
wildcard flow, a bulk change); "all" asks for every write; "off" never asks. A
critical change also asks the person to type a short code taken from the request's
digest, which a click cannot supply — it shows the request was read.
"""
import asyncio
from typing import Any, Dict

from pydantic import Field, create_model


def needed(mode: str, tier: str) -> bool:
    return mode == "all" or (mode == "strong" and tier in ("high", "critical"))


def code_of(digest: str) -> str:
    return digest[:6]


def question(action: str, summary: str, risk: Dict[str, Any], digest: str, calls: int) -> str:
    """What the person is shown. Built here, from the validated request."""
    tier = risk["risk_tier"]
    lines = [f"Confirm a change to the network (Ryu): {summary}",
             f"Risk: {tier.upper()}" + (" — " + "; ".join(risk["risk_reasons"]) if risk["risk_reasons"] else ""),
             f"It would send {calls} flow operation(s). Nothing has been sent; if you confirm, "
             f"it is queued for the operator's approval. Request fingerprint: {digest}."]
    if tier == "critical":
        lines.append(f"This change is critical. To confirm, type the code {code_of(digest)}.")
    return "\n".join(lines)


async def ask(ctx: Any, timeout: float, action: str, summary: str, risk: Dict[str, Any],
              digest: str, calls: int) -> Dict[str, Any]:
    critical = risk["risk_tier"] == "critical"
    fields = {"confirm": (bool, Field(default=False, description="Yes — queue this change for approval"))}
    if critical:
        fields["code"] = (str, Field(default="", description=f"Type {code_of(digest)} to confirm"))
    schema = create_model("Confirm", **fields)
    try:
        res = await asyncio.wait_for(ctx.elicit(message=question(action, summary, risk, digest, calls),
                                                schema=schema), timeout)
    except asyncio.TimeoutError:
        return {"state": "declined", "reason": f"no answer within {timeout:g} s"}
    except Exception as e:  # noqa: BLE001 - outside a request, or a client with no elicitation
        return {"state": "unavailable", "reason": f"the client cannot ask its user ({type(e).__name__})"}
    if res.action != "accept":
        return {"state": "declined", "reason": f"the user chose to {res.action}"}
    if not getattr(res.data, "confirm", False):
        return {"state": "declined", "reason": "the user did not confirm"}
    if critical and str(getattr(res.data, "code", "")).strip().lower() != code_of(digest):
        return {"state": "declined", "reason": "the code typed did not match"}
    return {"state": "confirmed", "by": "the user, through the MCP client"}
