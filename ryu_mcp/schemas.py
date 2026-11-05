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


# Match fields Ryu parses as integers: a word where a number belongs is rejected
# by Ryu only when the flow is installed, after a person has approved it.
INT_MATCH = {"in_port", "dl_type", "dl_vlan", "vlan_pcp", "nw_proto", "tp_src", "tp_dst",
             "eth_type", "vlan_vid", "ip_proto", "tcp_src", "tcp_dst", "udp_src", "udp_dst",
             "metadata", "tunnel_id"}
PORT_NAMES = {"CONTROLLER", "IN_PORT", "FLOOD", "ALL", "NORMAL", "LOCAL", "TABLE", "ANY"}
# What each action type cannot do without.
ACTION_NEEDS = {"OUTPUT": ("port",), "PUSH_VLAN": ("ethertype",), "SET_FIELD": ("field", "value"),
                "GROUP": ("group_id",), "GOTO_TABLE": ("table_id",), "SET_QUEUE": ("queue_id",)}


def _int(name: str, value: Any, lo: int, hi: int) -> int:
    """An integer in range. Not a bool, a float, a string of words or None."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise SchemaError(f"{name} must be an integer, not {value!r}")
    try:
        n = int(value, 0) if isinstance(value, str) else value
    except ValueError:
        raise SchemaError(f"{name} must be an integer, not {value!r}") from None
    if not lo <= n <= hi:
        raise SchemaError(f"{name} must be {lo}..{hi}, not {n}")
    return n


def _check_match(match: Any) -> Dict[str, Any]:
    if match is None:
        return {}
    if not isinstance(match, dict):
        raise SchemaError(f"match must be an object, not {type(match).__name__}")
    for key, value in match.items():
        if isinstance(value, (dict, list)) or value is None or isinstance(value, bool):
            raise SchemaError(f"match field {key!r} must be a number or a string")
        if key in INT_MATCH:
            _int(f"match field {key}", value, 0, 2 ** 64 - 1)
    _check_prerequisites(match)
    return dict(match)


ETH_TYPE = ("eth_type", "dl_type")
IP_PROTO = ("ip_proto", "nw_proto")


def _have(match: Dict[str, Any], names, values=None) -> bool:
    for name in names:
        if name in match:
            return values is None or _int(name, match[name], 0, 2 ** 64 - 1) in values
    return False


def _check_prerequisites(match: Dict[str, Any]) -> None:
    """OpenFlow's rules for what a field needs matched before it.

    Ryu answers 200 to a flow that breaks them and Open vSwitch quietly refuses
    it, so the request would be approved, reported applied, and do nothing.
    """
    ipv4 = {k for k in match if k.startswith(("ipv4_", "nw_src", "nw_dst"))}
    if ipv4 and not _have(match, ETH_TYPE, {0x0800}):
        raise SchemaError(f"{sorted(ipv4)} need eth_type 0x0800 (2048) in the match")
    if any(k in match for k in IP_PROTO) and not _have(match, ETH_TYPE, {0x0800, 0x86DD}):
        raise SchemaError("ip_proto needs eth_type 0x0800 (IPv4) or 0x86dd (IPv6) in the match")
    ports = {k for k in match if k.startswith(("tcp_", "udp_", "tp_"))}
    if ports and not any(k in match for k in IP_PROTO):
        raise SchemaError(f"{sorted(ports)} need ip_proto (6 for tcp, 17 for udp) in the match")
    if "vlan_pcp" in match and not any(k in match for k in ("vlan_vid", "dl_vlan")):
        raise SchemaError("vlan_pcp needs vlan_vid in the match")


def _check_action(action: Any) -> Dict[str, Any]:
    if not isinstance(action, dict):
        raise SchemaError(f"each action must be an object, not {action!r}")
    kind = str(action.get("type", "")).upper()
    if kind not in ACTION_TYPES:
        raise SchemaError(f"unknown action type {action.get('type')!r}")
    for need in ACTION_NEEDS.get(kind, ()):
        if action.get(need) in (None, ""):
            raise SchemaError(f"{kind} needs {need!r}")
    if kind == "OUTPUT":
        port = action["port"]
        if not (isinstance(port, str) and port.upper() in PORT_NAMES):
            _int("OUTPUT port", port, 0, 2 ** 32 - 1)
    elif kind == "SET_FIELD" and action["field"] not in MATCH_FIELDS:
        raise SchemaError(f"SET_FIELD of unknown field {action['field']!r}")
    for key in ("ethertype", "group_id", "table_id", "queue_id"):
        if key in action and kind in ACTION_NEEDS:
            _int(f"{kind} {key}", action[key], 0, 2 ** 32 - 1)
    # Ryu matches the type case-sensitively and, for one it does not know,
    # installs the flow with no actions at all: "output" would drop the traffic.
    return {**action, "type": kind}


def flow_entry(dpid: Any, match: Dict[str, Any], actions: List[Dict[str, Any]],
               priority: int = 100, table_id: int = 0, idle_timeout: int = 0,
               hard_timeout: int = 0, cookie: int = 0) -> Dict[str, Any]:
    match = _check_match(match)
    unknown = sorted(set(match) - MATCH_FIELDS)
    if unknown:
        raise SchemaError(f"unknown match field(s) {unknown}; Ryu would ignore them "
                          f"and the flow would match more than intended")
    if actions is None:
        actions = []
    if not isinstance(actions, list):
        raise SchemaError(f"actions must be a list, not {type(actions).__name__}")
    actions = [_check_action(a) for a in actions]
    priority = _int("priority", priority, 0, 65535)
    table_id = _int("table_id", table_id, 0, 254)
    idle_timeout = _int("idle_timeout", idle_timeout, 0, 65535)
    hard_timeout = _int("hard_timeout", hard_timeout, 0, 65535)
    cookie = _int("cookie", cookie, 0, 2 ** 64 - 1)
    return {
        "dpid": dpid_int(dpid), "cookie": cookie, "table_id": table_id,
        "idle_timeout": idle_timeout, "hard_timeout": hard_timeout,
        "priority": priority, "flags": 0,
        "match": match, "actions": actions,
    }


def vlan_map(dpid: Any, client_port: int, uplink_port: int, vlan_id: int,
             priority: int = 200) -> List[Dict[str, Any]]:
    """The edge domain's job: put a client port's traffic onto a tagged uplink.

    Two flows, one per direction. Ingress tags untagged client traffic with the
    VLAN and sends it up; egress matches that VLAN on the uplink, strips it, and
    delivers to the client. One flow without the other gives a circuit that
    carries traffic out and nothing back.
    """
    vlan_id = _int("vlan_id", vlan_id, 1, 4094)
    client_port = _int("client_port", client_port, 1, 2 ** 32 - 1)
    uplink_port = _int("uplink_port", uplink_port, 1, 2 ** 32 - 1)
    priority = _int("priority", priority, 0, 65535)
    if client_port == uplink_port:
        raise SchemaError("client_port and uplink_port are the same port")
    vid = vlan_id | OFPVID_PRESENT
    return [
        flow_entry(dpid, {"in_port": client_port}, [
            {"type": "PUSH_VLAN", "ethertype": 0x8100},
            {"type": "SET_FIELD", "field": "vlan_vid", "value": vid},
            {"type": "OUTPUT", "port": uplink_port},
        ], priority=priority),
        flow_entry(dpid, {"in_port": uplink_port, "vlan_vid": vid}, [
            {"type": "POP_VLAN"},
            {"type": "OUTPUT", "port": client_port},
        ], priority=priority),
    ]


def vlan_unmap(dpid: Any, client_port: int, uplink_port: int, vlan_id: int,
               priority: int = 200) -> List[Dict[str, Any]]:
    """The exact inverse of `vlan_map`: both of its flows, matched strictly.

    `delete_strict` removes only a flow with this match *and* priority, so a
    mapping another circuit made on the same switch is left alone. Built from
    `vlan_map` itself, so the two cannot drift apart.
    """
    return [{**body, "actions": []}
            for body in vlan_map(dpid, client_port, uplink_port, vlan_id, priority)]
