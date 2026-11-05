"""A server, its gate and one fake switch, sharing a state directory."""
import asyncio
import json
import tempfile

from ryu_mcp.client import RyuClient
from ryu_mcp.config import RyuConfig
from ryu_mcp.gate import WriteGate
from ryu_mcp.server import create_server
from tests.support.fakes import FakeRyu

MAP = {"dpid": "257", "client_port": 1, "uplink_port": 3, "vlan_id": 10}
FWD = [{"type": "OUTPUT", "port": 2}]


class Rig:
    """A server, its gate and one fake switch, sharing a state directory."""

    def __init__(self, **cfg):
        self.fake = FakeRyu()
        self.dir = tempfile.mkdtemp()
        self.cfg = RyuConfig.from_env(state_dir=self.dir, **cfg)
        self.client = RyuClient("http://ryu", transport=self.fake.transport)
        self.gate = WriteGate(self.dir, ttl=self.cfg.approval_ttl)
        self.server = create_server(self.cfg, client=self.client, gate=self.gate)

    def call(self, name, args):
        async def go():
            r = await self.server.call_tool(name, args)
            c = r[0] if isinstance(r, tuple) else r
            return json.loads(c[0].text)
        return asyncio.run(go())

    def approve_apply(self, approval_id):
        self.gate.decide(approval_id, True)
        return asyncio.run(self.gate.apply_approved(self.client))
