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

    @classmethod
    def from_env(cls, **overrides) -> "RyuConfig":
        host = _env("RYU_HOST", default="127.0.0.1")
        port = _env("RYU_PORT", default="8080")
        base = _env("RYU_BASE_URL", default=f"http://{host}:{port}")
        mode = _env("RYU_MCP_WRITE_MODE", default="queue").strip().lower()
        if mode not in ("queue", "direct"):
            raise ValueError(f"RYU_MCP_WRITE_MODE must be 'queue' or 'direct', not {mode!r}")
        cfg = cls(
            base_url=base.rstrip("/"),
            timeout=float(_env("RYU_TIMEOUT", default="20")),
            write_mode=mode,
            state_dir=_env("RYU_STATE_DIR", default=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "state")),
            mcp_host=_env("RYU_MCP_HOST", default="127.0.0.1"),
            mcp_port=int(_env("RYU_MCP_PORT", default="3005")),
        )
        for key, value in overrides.items():
            if value is not None:
                setattr(cfg, key, value)
        return cfg
