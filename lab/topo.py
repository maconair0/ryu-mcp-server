#!/usr/bin/env python3
"""Two enterprise edge switches under Ryu, each with an uplink to the ONOS core.

    h1 (VLAN 10) ─┐                                  ┌─ h3 (VLAN 10)
                  s1 edge-1 ── uplink → ONOS IP1 ... ONOS IP2 ← uplink ── s2 edge-2
    h2 (VLAN 20) ─┘                                  └─ h4 (VLAN 20)

The ONOS routers live in another domain, so each uplink ends on a stand-in host
(`core1`, `core2`) that marks the handover. The edge switches are not linked to
each other: traffic between the two sites has to cross the core.
"""
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def build():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController("ryu", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", dpid="0000000000000101", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", dpid="0000000000000102", protocols="OpenFlow13")
    for name, sw, ip in (("h1", s1, "10.10.0.1/24"), ("h2", s1, "10.20.0.1/24"),
                         ("h3", s2, "10.10.0.2/24"), ("h4", s2, "10.20.0.2/24")):
        net.addLink(net.addHost(name, ip=ip), sw)
    # Uplinks: port 3 on each edge switch faces the core.
    net.addLink(net.addHost("core1", ip="192.0.2.1/30"), s1)
    net.addLink(net.addHost("core2", ip="192.0.2.5/30"), s2)
    return net

if __name__ == "__main__":
    setLogLevel("info")
    net = build()
    net.start()
    info("*** edge topology up; Ryu REST on :8080\n")
    while True:
        time.sleep(3600)
