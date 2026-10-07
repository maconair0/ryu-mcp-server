"""The MCP tools. Reads answer; writes request."""
import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from . import schemas, summarise
from .client import RyuClient, RyuError, RyuUnreachable, dpid_hex, dpid_int
from .config import RyuConfig
from .gate import WriteGate

READ_TOOLS = ["ryu_health_check", "ryu_get_topology", "ryu_list_switches",
              "ryu_get_switch", "ryu_get_flows", "ryu_get_port_stats"]
WRITE_TOOLS = ["ryu_add_flow", "ryu_delete_flow", "ryu_map_vlan", "ryu_unmap_vlan"]


def _reply(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, indent=1, default=str)


def _failure(op: str, e: Exception) -> str:
    """A controller that refuses is data, not an exception."""
    kind = ("unreachable" if isinstance(e, RyuUnreachable)
            else "refused" if isinstance(e, RyuError) else "error")
    out = {"ok": False, "error": kind, "operation": op, "detail": str(e)}
    if isinstance(e, RyuError):
        out["http_status"] = e.status
        if e.body:
            out["body"] = e.body
    return _reply(out)


def create_server(cfg: RyuConfig, client: Optional[RyuClient] = None,
                  gate: Optional[WriteGate] = None) -> FastMCP:
    client = client or RyuClient(cfg.base_url, cfg.timeout)
    gate = gate or WriteGate(cfg.state_dir)
    mcp = FastMCP("ryu", host=cfg.mcp_host, port=cfg.mcp_port)

    async def _write(action: str, summary: str, calls: List[Dict[str, Any]]) -> str:
        if cfg.write_mode == "direct":
            for call in calls:
                await client.post(call["path"], call["body"])
            gate.audit({"event": "applied_direct", "action": action, "summary": summary})
            return _reply({"ok": True, "status": "applied", "action": action,
                           "summary": summary, "calls": len(calls),
                           "note": "RYU_MCP_WRITE_MODE=direct: applied without queueing"})
        return _reply({"ok": True, **gate.request(action, summary, calls)})

    # ----- reads -----

    @mcp.tool()
    async def ryu_health_check() -> str:
        """Is Ryu reachable, and are the REST apps this server needs loaded."""
        out = {"ok": True, "base_url": cfg.base_url, "write_mode": cfg.write_mode}
        for app, path in (("ofctl_rest", "/stats/switches"),
                          ("rest_topology", "/v1.0/topology/switches")):
            try:
                await client.get(path)
                out[app] = True
            except RyuUnreachable as e:
                return _reply({"ok": False, "reachable": False, "detail": str(e)})
            except RyuError:
                out[app] = False
        out["reachable"] = True
        if not (out["ofctl_rest"] and out["rest_topology"]):
            out["ok"] = False
            out["detail"] = ("start ryu-manager with ryu.app.ofctl_rest and "
                             "ryu.app.rest_topology (and --observe-links for links)")
        return _reply(out)

    @mcp.tool()
    async def ryu_get_topology(raw: bool = False) -> str:
        """Switches, links between them, and discovered hosts."""
        try:
            sw = await client.get("/v1.0/topology/switches")
            ln = await client.get("/v1.0/topology/links")
            ho = await client.get("/v1.0/topology/hosts")
            data = {"switches": sw, "links": ln, "hosts": ho} if raw \
                else summarise.topology(sw, ln, ho)
            return _reply({"ok": True, "data": data})
        except Exception as e:  # noqa: BLE001
            return _failure("get_topology", e)

    @mcp.tool()
    async def ryu_compute_path(src_dpid: str, dst_dpid: str) -> str:
        """Shortest path between two switches over Ryu's discovered links. Read only.

        Accepts either dpid spelling. Same switch in and out is a zero-hop path,
        which is the normal case for an edge site that meets the rest of the
        network only through its uplink.
        """
        try:
            sw = await client.get("/v1.0/topology/switches")
            ln = await client.get("/v1.0/topology/links")
            got = summarise.shortest_path(sw, ln, dpid_hex(src_dpid), dpid_hex(dst_dpid))
            return _reply({"ok": True, "data": got})
        except Exception as e:  # noqa: BLE001
            return _failure("compute_path", e)

    @mcp.tool()
    async def ryu_list_switches() -> str:
        """Connected datapaths, by id in both spellings Ryu uses."""
        try:
            got = await client.get("/stats/switches") or []
            return _reply({"ok": True, "switches": [
                {"dpid": dpid_hex(d), "dpid_int": dpid_int(d)} for d in got]})
        except Exception as e:  # noqa: BLE001
            return _failure("list_switches", e)

    @mcp.tool()
    async def ryu_get_switch(dpid: str) -> str:
        """One switch: description and its ports with their state."""
        try:
            n = dpid_int(dpid)
            desc = await client.get(f"/stats/desc/{n}")
            ports = await client.get(f"/stats/portdesc/{n}")
            plist = next((v for v in (ports or {}).values() if isinstance(v, list)), [])
            return _reply({"ok": True, "dpid": dpid_hex(n),
                           "description": next(iter((desc or {}).values()), {}),
                           "ports": [{"port_no": p.get("port_no"), "name": p.get("name"),
                                      "state": p.get("state"), "config": p.get("config"),
                                      "hw_addr": p.get("hw_addr")} for p in plist]})
        except Exception as e:  # noqa: BLE001
            return _failure("get_switch", e)

    @mcp.tool()
    async def ryu_get_flows(dpid: str, include_controller_defaults: bool = False) -> str:
        """Installed flows, with packet counters. Ryu's own punt flows hidden by default."""
        try:
            n = dpid_int(dpid)
            got = await client.get(f"/stats/flow/{n}")
            return _reply({"ok": True, **summarise.flows(n, got, include_controller_defaults)})
        except Exception as e:  # noqa: BLE001
            return _failure("get_flows", e)

    @mcp.tool()
    async def ryu_get_port_stats(dpid: str) -> str:
        """Per-port packet, error and drop counters — evidence that traffic flows."""
        try:
            n = dpid_int(dpid)
            return _reply({"ok": True, **summarise.port_stats(n, await client.get(f"/stats/port/{n}"))})
        except Exception as e:  # noqa: BLE001
            return _failure("get_port_stats", e)

    # ----- writes: requested, not performed -----

    @mcp.tool()
    async def ryu_add_flow(dpid: str, match: Dict[str, Any], actions: List[Dict[str, Any]],
                           priority: int = 100) -> str:
        """Request a flow. Queued for operator approval; installs nothing by itself.

        actions use ofctl_rest form, e.g. [{"type": "OUTPUT", "port": 3}].
        """
        try:
            body = schemas.flow_entry(dpid, match, actions, priority)
        except (schemas.SchemaError, ValueError) as e:
            return _reply({"ok": False, "error": "invalid", "detail": str(e)})
        try:
            return await _write("ryu_add_flow", f"add flow on {dpid_hex(dpid)} match={match}",
                                [{"path": "/stats/flowentry/add", "body": body}])
        except Exception as e:  # noqa: BLE001
            return _failure("add_flow", e)

    @mcp.tool()
    async def ryu_delete_flow(dpid: str, match: Dict[str, Any], priority: int = 100) -> str:
        """Request removal of exactly the flow with this match and priority."""
        try:
            body = schemas.flow_entry(dpid, match, [], priority)
        except (schemas.SchemaError, ValueError) as e:
            return _reply({"ok": False, "error": "invalid", "detail": str(e)})
        try:
            return await _write("ryu_delete_flow", f"delete flow on {dpid_hex(dpid)} match={match}",
                                [{"path": "/stats/flowentry/delete_strict", "body": body}])
        except Exception as e:  # noqa: BLE001
            return _failure("delete_flow", e)

    @mcp.tool()
    async def ryu_map_vlan(dpid: str, client_port: int, uplink_port: int, vlan_id: int) -> str:
        """Map a client port onto a VLAN on the uplink toward the core, both directions.

        The edge domain's handover: untagged client traffic is tagged and sent up;
        tagged traffic from the core is untagged and delivered. Two flows.
        """
        try:
            bodies = schemas.vlan_map(dpid, client_port, uplink_port, vlan_id)
        except (schemas.SchemaError, ValueError) as e:
            return _reply({"ok": False, "error": "invalid", "detail": str(e)})
        try:
            return await _write(
                "ryu_map_vlan",
                f"map {dpid_hex(dpid)} port {client_port} <-> uplink {uplink_port} vlan {vlan_id}",
                [{"path": "/stats/flowentry/add", "body": b} for b in bodies])
        except Exception as e:  # noqa: BLE001
            return _failure("map_vlan", e)

    @mcp.tool()
    async def ryu_unmap_vlan(dpid: str, client_port: int, uplink_port: int, vlan_id: int) -> str:
        """Remove a VLAN mapping: the exact inverse of ryu_map_vlan, both directions.

        Takes the same four arguments the mapping was made with. Only those two
        flows are removed (strict match on match and priority), so other
        mappings on the switch are untouched. Queued for approval like any write.
        """
        try:
            bodies = schemas.vlan_unmap(dpid, client_port, uplink_port, vlan_id)
        except (schemas.SchemaError, ValueError) as e:
            return _reply({"ok": False, "error": "invalid", "detail": str(e)})
        try:
            return await _write(
                "ryu_unmap_vlan",
                f"unmap {dpid_hex(dpid)} port {client_port} <-> uplink {uplink_port} vlan {vlan_id}",
                [{"path": "/stats/flowentry/delete_strict", "body": b} for b in bodies])
        except Exception as e:  # noqa: BLE001
            return _failure("unmap_vlan", e)

    return mcp
