"""Where Ryu lives and how this server behaves. Nothing is hardcoded."""
import os
from dataclasses import dataclass


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value not in (None, ""):
            return value
    return default


@dataclass
class RyuConfig:
    base_url: str
    timeout: float
    write_mode: str          # "queue" (default) or "direct"
    state_dir: str
    mcp_host: str
    mcp_port: int
    # A secret an authenticated host system presents to approve one queued
    # write after a person has confirmed it there (ryu_approve_request).
    # Unset: no approval over MCP at all, only the CLI.
    approver_token: str = ""
    # Seconds a queued request stays approvable; 0 never expires.
    approval_ttl: int = 3600
    # Asking the user, through the client, before a strong write is even queued:
    # "strong" (high and critical risk, the default), "all" writes, or "off".
    confirm_mode: str = "strong"
    # A client that cannot ask its user (no MCP elicitation): refuse the write
    # (strict) or fall back to the operator's approval alone (the default).
    confirm_strict: bool = False
    # Seconds the user has to answer; silence is a no.
    confirm_timeout: float = 300.0

    @classmethod
    def from_env(cls, **overrides) -> "RyuConfig":
        host = _env("RYU_HOST", default="127.0.0.1")
        port = _env("RYU_PORT", default="8080")
        base = _env("RYU_BASE_URL", default=f"http://{host}:{port}")
        mode = _env("RYU_MCP_WRITE_MODE", default="queue").strip().lower()
        if mode not in ("queue", "direct"):
            raise ValueError(f"RYU_MCP_WRITE_MODE must be 'queue' or 'direct', not {mode!r}")
        confirm = _env("RYU_MCP_CONFIRM", default="strong").strip().lower()
        if confirm not in ("strong", "all", "off"):
            raise ValueError(f"RYU_MCP_CONFIRM must be 'strong', 'all' or 'off', not {confirm!r}")
        cfg = cls(
            base_url=base.rstrip("/"),
            timeout=float(_env("RYU_TIMEOUT", default="20")),
            write_mode=mode,
            state_dir=_env("RYU_STATE_DIR", default=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "state")),
            mcp_host=_env("RYU_MCP_HOST", default="127.0.0.1"),
            mcp_port=int(_env("RYU_MCP_PORT", default="3005")),
            approver_token=_env("RYU_MCP_APPROVER_TOKEN", default=""),
            approval_ttl=int(_env("RYU_MCP_APPROVAL_TTL", default="3600")),
            confirm_mode=confirm,
            confirm_strict=_env("RYU_MCP_CONFIRM_STRICT", default="0").lower() in ("1", "true", "yes"),
            confirm_timeout=float(_env("RYU_MCP_CONFIRM_TIMEOUT", default="300")),
        )
        for key, value in overrides.items():
            if value is not None:
                setattr(cfg, key, value)
        return cfg
