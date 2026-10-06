"""Compact, agent-sized answers from Ryu's verbose replies."""
from typing import Any, Dict, List

from .client import dpid_hex

DETAIL = 64


def topology(switches: Any, links: Any, hosts: Any) -> Dict[str, Any]:
    switches = switches if isinstance(switches, list) else []
    links = links if isinstance(links, list) else []
    hosts = hosts if isinstance(hosts, list) else []
    # rest_topology reports each direction of a link separately.
    pairs = {}
    for l in links:
        s, d = l.get("src", {}), l.get("dst", {})
        a = (s.get("dpid"), s.get("port_no")); z = (d.get("dpid"), d.get("port_no"))
        key = tuple(sorted((a, z)))
        pairs.setdefault(key, 0); pairs[key] += 1
    return {
        "switches": len(switches),
        "links": len(links),
        "links_note": "rest_topology lists each direction separately",
        "hosts": len(hosts),
        "switch_detail": [{
            "dpid": s.get("dpid"),
            "ports": [{"port_no": p.get("port_no"), "name": p.get("name"),
                       "hw_addr": p.get("hw_addr")} for p in s.get("ports", [])],
        } for s in switches[:DETAIL]],
        "link_detail": [{
            "a": f"{a[0]}/{a[1]}", "z": f"{z[0]}/{z[1]}",
            "bidirectional": n >= 2,
        } for (a, z), n in list(pairs.items())[:DETAIL]],
        "host_detail": [{
            "mac": h.get("mac"), "ipv4": h.get("ipv4"),
            "attached": f"{h.get('port', {}).get('dpid')}/{h.get('port', {}).get('port_no')}",
        } for h in hosts[:DETAIL]],
    }


def flows(dpid: Any, payload: Any, include_controller_defaults: bool = False) -> Dict[str, Any]:
    entries = []
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list):
                entries = value
                break
    out = []
    for f in entries:
        actions = f.get("actions") or []
        # Ryu installs table-miss / LLDP punts itself; they are not anybody's
        # configuration and would drown the flows an operator asked for.
        if not include_controller_defaults and actions == ["OUTPUT:CONTROLLER"]:
            continue
        out.append({"priority": f.get("priority"), "match": f.get("match"),
                    "actions": actions, "packets": f.get("packet_count"),
                    "bytes": f.get("byte_count"), "table": f.get("table_id"),
                    "cookie": f.get("cookie")})
    return {"dpid": dpid_hex(dpid), "flows": len(out), "detail": out[:DETAIL]}


def port_stats(dpid: Any, payload: Any) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list):
                entries = value
                break
    return {"dpid": dpid_hex(dpid), "ports": [{
        "port_no": p.get("port_no"),
        "rx_packets": p.get("rx_packets"), "tx_packets": p.get("tx_packets"),
        "rx_errors": p.get("rx_errors"), "tx_errors": p.get("tx_errors"),
        "rx_dropped": p.get("rx_dropped"), "tx_dropped": p.get("tx_dropped"),
    } for p in entries]}
