"""Flow bodies for `ofctl_rest`, validated before anything is queued.

Ryu's REST app accepts almost anything and reports problems late: a typo in a
match field is silently dropped, and a flow that matches more than intended is
installed without complaint. So the fields are checked here, against the names
`ofctl_v1_3` actually understands.
"""
from typing import Any, Dict, List

from .client import dpid_int

MATCH_FIELDS = {
    "in_port", "dl_src", "dl_dst", "dl_type", "dl_vlan", "vlan_pcp",
    "nw_src", "nw_dst", "nw_proto", "tp_src", "tp_dst",
    "eth_src", "eth_dst", "eth_type", "vlan_vid", "ip_proto",
    "ipv4_src", "ipv4_dst", "tcp_src", "tcp_dst", "udp_src", "udp_dst",
    "metadata", "tunnel_id",
}
ACTION_TYPES = {
    "OUTPUT", "PUSH_VLAN", "POP_VLAN", "SET_FIELD", "GROUP", "SET_QUEUE",
    "DROP", "GOTO_TABLE", "WRITE_METADATA", "COPY_TTL_OUT", "COPY_TTL_IN",
    "DEC_NW_TTL", "SET_NW_TTL", "DEC_MPLS_TTL", "PUSH_MPLS", "POP_MPLS",
}
# OpenFlow 1.3 marks a tagged VLAN by setting OFPVID_PRESENT. Ryu's REST app
# takes the VID with the bit set; a bare "10" matches untagged frames' VID 10,
# which never occurs, so the flow installs and never matches anything.
OFPVID_PRESENT = 0x1000


class SchemaError(ValueError):
    pass


def flow_entry(dpid: Any, match: Dict[str, Any], actions: List[Dict[str, Any]],
               priority: int = 100, table_id: int = 0, idle_timeout: int = 0,
               hard_timeout: int = 0, cookie: int = 0) -> Dict[str, Any]:
    problems = []
    unknown = sorted(set(match or {}) - MATCH_FIELDS)
    if unknown:
        problems.append(f"unknown match field(s) {unknown}; Ryu would ignore them "
                        f"and the flow would match more than intended")
    for action in actions or []:
        if str(action.get("type", "")).upper() not in ACTION_TYPES:
            problems.append(f"unknown action type {action.get('type')!r}")
    if not (0 <= int(priority) <= 65535):
        problems.append("priority must be 0..65535")
    if problems:
        raise SchemaError("; ".join(problems))
    return {
        "dpid": dpid_int(dpid), "cookie": int(cookie), "table_id": int(table_id),
        "idle_timeout": int(idle_timeout), "hard_timeout": int(hard_timeout),
        "priority": int(priority), "flags": 0,
        "match": dict(match or {}), "actions": list(actions or []),
    }


def vlan_map(dpid: Any, client_port: int, uplink_port: int, vlan_id: int,
             priority: int = 200) -> List[Dict[str, Any]]:
    """The edge domain's job: put a client port's traffic onto a tagged uplink.

    Two flows, one per direction. Ingress tags untagged client traffic with the
    VLAN and sends it up; egress matches that VLAN on the uplink, strips it, and
    delivers to the client. One flow without the other gives a circuit that
    carries traffic out and nothing back.
    """
    if not (1 <= int(vlan_id) <= 4094):
        raise SchemaError("vlan_id must be 1..4094")
    if int(client_port) == int(uplink_port):
        raise SchemaError("client_port and uplink_port are the same port")
    vid = int(vlan_id) | OFPVID_PRESENT
    return [
        flow_entry(dpid, {"in_port": int(client_port)}, [
            {"type": "PUSH_VLAN", "ethertype": 0x8100},
            {"type": "SET_FIELD", "field": "vlan_vid", "value": vid},
            {"type": "OUTPUT", "port": int(uplink_port)},
        ], priority=priority),
        flow_entry(dpid, {"in_port": int(uplink_port), "vlan_vid": vid}, [
            {"type": "POP_VLAN"},
            {"type": "OUTPUT", "port": int(client_port)},
        ], priority=priority),
    ]
