"""Ryu's REST API: `ryu.app.ofctl_rest` and `ryu.app.rest_topology`."""
from typing import Any, Dict, Optional

import httpx


class RyuError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class RyuUnreachable(RyuError):
    """Nothing answered. Different from Ryu answering with an error."""


def dpid_int(dpid: Any) -> int:
    """A datapath id as Ryu's stats API wants it: an integer.

    The topology app reports dpids as 16-digit hex strings ("0000000000000101")
    and the stats app takes them as decimal path segments ("257"). The same
    switch has two spellings depending on which app is asked, so every tool
    accepts either and converts here, once.
    """
    if isinstance(dpid, int):
        return dpid
    text = str(dpid).strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    if len(text) == 16 or any(c in "abcdef" for c in text):
        return int(text, 16)
    return int(text)


def dpid_hex(dpid: Any) -> str:
    return format(dpid_int(dpid), "016x")


class RyuClient:
    def __init__(self, base_url: str, timeout: float = 20.0,
                 transport: Optional[httpx.AsyncBaseTransport] = None):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout,
                                         transport=transport)

    async def close(self) -> None:
        await self._client.aclose()

    async def _send(self, method: str, path: str, body: Any = None) -> Any:
        try:
            response = await self._client.request(method, path, json=body)
        except httpx.HTTPError as e:
            raise RyuUnreachable(f"{self.base_url}{path}: {type(e).__name__}: {e}") from e
        if response.status_code >= 400:
            raise RyuError(f"HTTP {response.status_code} from {path}",
                           response.status_code, response.text[:500])
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    async def get(self, path: str) -> Any:
        return await self._send("GET", path)

    async def post(self, path: str, body: Dict[str, Any]) -> Any:
        return await self._send("POST", path, body)
