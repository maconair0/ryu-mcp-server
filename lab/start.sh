#!/bin/bash
# Start OVS, Ryu with its REST apps, then the edge topology.
set -e
service openvswitch-switch start >/dev/null
ryu-manager --observe-links --ofp-tcp-listen-port 6653 --wsapi-port 8080 \
    ryu.app.ofctl_rest ryu.app.rest_topology > /var/log/ryu.log 2>&1 &
until curl -sf http://127.0.0.1:8080/v1.0/topology/switches >/dev/null; do sleep 1; done
exec python3 /lab/topo.py
