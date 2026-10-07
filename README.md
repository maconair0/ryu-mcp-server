# Ryu MCP server

An MCP server for the [Ryu](https://github.com/faucetsdn/ryu) OpenFlow controller.

It lets an AI agent read an OpenFlow network — switches, links, hosts, flows,
port counters — and request flow changes, while keeping every change behind a
human approval gate. It was built as the **client-access edge** of a multi-domain
setup, where Ryu maps enterprise VLAN traffic onto the uplinks that hand off to
the packet core.

## Why the write tools do not write

The write tools validate a flow, put it on an approval queue on disk, and return
an `approval_id`. Nothing reaches Ryu until an operator approves it and the drain
step installs it:

```bash
python run_ryu_mcp.py --list-pending
python run_ryu_mcp.py --approve <id>     # or --reject <id>
python run_ryu_mcp.py --drain            # install approved flows
```

No tool takes an argument that skips this. A flag the model can set is a flag
the model will set. The single bypass, `RYU_MCP_WRITE_MODE=direct`, is chosen by
whoever starts the server — for a host system that already puts a person in
front of every change and would otherwise ask twice.

**Surviving a restart.** Ryu holds no flows of its own; a switch that restarts
comes back empty. The server watches the connected switches (every 30 s,
`--watch-interval` or `RYU_REPLAY_WATCH`, 0 to turn off) and, when one connects,
re-installs every write that was approved and applied, oldest first, so a later
delete still follows the add it removed. `--replay` does the same once, by hand.
Nothing new is approved by this: it puts back the state approval was given for.

## Tools

| read tool | answers |
|---|---|
| `ryu_health_check` | is Ryu reachable, and are `ofctl_rest` and `rest_topology` loaded |
| `ryu_get_topology` | switches with their ports, links between them, discovered hosts |
| `ryu_list_switches` | connected datapaths |
| `ryu_get_switch` | one switch's description and port states |
| `ryu_get_flows` | installed flows with packet counters |
| `ryu_get_port_stats` | per-port packet, error and drop counters |
| `ryu_compute_path` | hop-count shortest path between two switches over discovered links; same switch is a zero-hop path |

| write tool | queues |
|---|---|
| `ryu_add_flow` | one flow (`/stats/flowentry/add`) |
| `ryu_delete_flow` | removal of one exact flow (`/stats/flowentry/delete_strict`) |
| `ryu_map_vlan` | a client port onto a VLAN on an uplink, both directions |

Every tool returns JSON with `ok`. A refusal or an unreachable Ryu comes back as
data, not as an exception.

## Install

```bash
git clone https://github.com/maconair0/ryu-mcp-server.git
cd ryu-mcp-server
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10+. Ryu itself does not need to be installed alongside this server;
it is reached over REST.

## Configuration

| variable | default | notes |
|---|---|---|
| `RYU_BASE_URL` | — | e.g. `http://127.0.0.1:8080`; overrides host/port |
| `RYU_HOST` / `RYU_PORT` | `127.0.0.1` / `8080` | Ryu's `--wsapi-port` |
| `RYU_TIMEOUT` | `20` | seconds |
| `RYU_MCP_WRITE_MODE` | `queue` | `queue` or `direct` |
| `RYU_STATE_DIR` | `ryu_mcp/state/` | approval queue and audit log |
| `RYU_MCP_HOST` / `RYU_MCP_PORT` | `127.0.0.1` / `3005` | this server's endpoint |

## Running

```bash
python run_ryu_mcp.py --check                         # is Ryu there?
python run_ryu_mcp.py --ryu-url http://127.0.0.1:8080 # serve over SSE
python run_ryu_mcp.py --transport stdio
```

Ryu must run with the REST apps this server uses:

```bash
ryu-manager --observe-links ryu.app.ofctl_rest ryu.app.rest_topology
```

`--observe-links` is what makes `rest_topology` report links; without it the
link list is always empty.

## A lab to test against

`lab/` builds one container with Ryu and Mininet. Ryu does not install on
Python 3.12, and Mininet needs root and Open vSwitch, so a container is the
clean way to run both:

```bash
docker build -t ryu-lab lab/
docker run -d --name ryu-lab --privileged --restart unless-stopped \
  -p 8080:8080 -p 6653:6653 -v /lib/modules:/lib/modules:ro ryu-lab
```

It starts two edge switches, each with two enterprise hosts and an uplink:

```
h1 (10.10.0.1) ─┐                         ┌─ h3 (10.10.0.2)
                s1 ── port 3 → core1      s2 ── port 3 → core2
h2 (10.20.0.1) ─┘    (0x101)              (0x102)  └─ h4 (10.20.0.2)
```

The edge switches are not linked to each other: traffic between the sites has to
cross the core, which is another controller's domain. `core1` and `core2` stand
in for that handover. No forwarding app runs, so nothing passes until flows are
installed — which is what makes a provisioning request observable.

Mapping a site's client port onto the core uplink:

```
ryu_map_vlan(dpid="0000000000000101", client_port=1, uplink_port=3, vlan_id=10)
```

## Notes

- **A switch has two names.** `rest_topology` reports dpids as 16-digit hex
  (`0000000000000101`); `ofctl_rest` takes them as decimal (`257`). Every tool
  accepts either.
- **A VLAN match needs the present bit.** Under OpenFlow 1.3 a tagged VID is
  matched as `vid | 0x1000`. A bare `10` matches nothing and installs without
  complaint. `ryu_map_vlan` sets it.
- **Ryu ignores match fields it does not know.** A typo like `in_prt` is dropped
  and the flow matches more than intended, so match fields and action types are
  validated before anything is queued.
- **Ryu's own flows are hidden.** The table-miss and LLDP punt flows it installs
  are not anybody's configuration; `include_controller_defaults=true` shows them.

## Tests

```bash
python -m unittest discover -s tests -t .
```

No Ryu or network needed; the REST API is dummy. Includes tests that a queued or
rejected write leaves Ryu untouched.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
