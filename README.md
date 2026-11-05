# Ryu MCP server

An MCP server for the [Ryu](https://github.com/faucetsdn/ryu) OpenFlow controller.

It lets an AI agent read an OpenFlow network — switches, links, hosts, flows,
port counters — and request flow changes, while keeping every change behind a
human approval gate. It was built as the **client-access edge** of a multi-domain
setup, where Ryu maps enterprise VLAN traffic onto the uplinks that hand off to
the packet core.

Paper: [Operator-Controlled MCP: A Security Layer for AI Agent Operations on Networks](paper/ryu-mcp-paper.pdf) (source in [`paper/`](paper/)).

## Why the write tools do not write

The write tools validate a flow, put it on an approval queue on disk, and return
an `approval_id`. Nothing reaches Ryu until an operator approves it and the drain
step installs it:

```bash
python run_ryu_mcp.py --list-pending
python run_ryu_mcp.py --approve <id>     # or --reject <id>
python run_ryu_mcp.py --drain            # install approved flows
python run_ryu_mcp.py --undo <id>        # queue the inverse of an applied write
python run_ryu_mcp.py --recover          # settle a request whose process died mid-apply
```

No tool takes an argument that skips this. A flag the model can set is a flag
the model will set. The single bypass, `RYU_MCP_WRITE_MODE=direct`, is chosen by
whoever starts the server — for a host system that already puts a person in
front of every change and would otherwise ask twice.

**Approval by a host system.** A host that puts its own person in front of each
change (edgeLM confirms as root, for instance) can approve that one request over
MCP with `ryu_approve_request(approval_id, approver_token)`. The token is set by
the operator in `RYU_MCP_APPROVER_TOKEN` on this server and held by the host;
it is not a model's argument to choose. Unset, the tool always refuses and
approval stays on the command line. Every use is in the audit log.

**Confirming a strong change with the user, through the agent.** Before a *strong*
write is even queued — a delete, an unmap, an undo, a wildcard flow, a bulk change
(anything assessed `high` or `critical`) — the server asks the person behind the
client, over MCP's elicitation. It is not an argument of any tool, so a model cannot
supply it; the question is written by the server from the request it validated, so
a model cannot soften what the person reads; and the answer comes back from the
client, not through the model. A *no*, a dismissed question, or no answer within
`RYU_MCP_CONFIRM_TIMEOUT` seconds queues nothing. A *critical* change also asks the
person to type a short code from the request's digest, which a click cannot supply.
Confirming is not approving: a confirmed request still waits for the operator.

| `RYU_MCP_CONFIRM` | asks about |
|---|---|
| `strong` (default) | high and critical changes |
| `all` | every write |
| `off` | nothing |

A client that cannot ask its user (no elicitation) gets the operator's approval alone
and the reply says `confirmation.state: unavailable`; with `RYU_MCP_CONFIRM_STRICT=1`
such a write is refused instead. In `direct` mode a strong change is confirmed before
it is applied. The command line (`--approve`, `--undo`) has a person at it already
and is not asked.

**What the person approving is shown.** Each request comes back with a risk tier
(`medium`, `high`, `critical`) and the reasons for it, from what the change would
do to the switch rather than from how it is worded: a wildcard flow with no
forwarding action drops every packet on the switch, and deleting the priority-0
flow stops the switch asking the controller about anything new. A *critical*
change is queued even when the server is started in `direct` mode.

**What keeps an approval honest.**

- *A digest.* Every request carries a fingerprint of what will be sent, checked
  again when it is applied; an entry edited after it was requested is refused.
  A host that shows its person the digest can pass it back as `expected_digest`,
  so its approval holds only for the request that person saw.
- *Expiry.* A request stays approvable for `RYU_MCP_APPROVAL_TTL` seconds
  (default 3600), so an approval is not applied to a network that has moved on.
- *One application.* An approved request is claimed under a lock shared by the
  server and the command line before anything is sent, so it cannot be applied twice.
- *Guessing.* Five wrong approver tokens in a row pause approval over MCP for five
  minutes. The command line is unaffected.

**Undoing, and not half-doing.** Before a request is sent, the flows it would
replace or remove are read from the switch and kept. `ryu_request_undo` (or
`run_ryu_mcp.py --undo <id>`) then queues the exact inverse: it deletes what was
added, or puts back what was overwritten or removed. It is a request like any
other and waits for approval. It is refused if a later change touched the same
flows (undo that first), and no undo is offered if the earlier state could not be
read or has an action this server does not know — better none than a wrong one.
A request that fails partway (the second flow of a VLAN map) is rolled back from
the same record, so it never leaves a circuit that carries traffic out and none back.

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
| `ryu_unmap_vlan` | removes a mapping: the exact inverse of `ryu_map_vlan`, same four arguments |
| `ryu_request_undo` | queues the exact inverse of an applied write; still needs approval |
| `ryu_approve_request` | approves and applies one queued write — only with the operator's `RYU_MCP_APPROVER_TOKEN`; optional `expected_digest` |

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
| `RYU_MCP_APPROVER_TOKEN` | — | lets a host approve over MCP; unset, approval is command-line only |
| `RYU_MCP_APPROVAL_TTL` | `3600` | seconds a request stays approvable; `0` never expires |
| `RYU_MCP_CONFIRM` | `strong` | which writes ask the user first: `strong`, `all` or `off` |
| `RYU_MCP_CONFIRM_STRICT` | `0` | `1`: refuse a strong write when the client cannot ask its user |
| `RYU_MCP_CONFIRM_TIMEOUT` | `300` | seconds the user has to answer; silence is a no |
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

OVSDB answers on port 6640 inside the container, for agents that read the
switches' port state and counters directly. It is not published on the host;
join the container to a network to reach it
(`docker network connect --alias ryu-lab <net> ryu-lab`).

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
- **A VLAN match and the present bit.** Under OpenFlow 1.3 a tagged VID is matched
  as `vid | 0x1000`; `ryu_map_vlan` sets it. Ryu 4.34 with Open vSwitch also reads
  a bare `10` as VLAN 10, so the two spellings meet on the same flow — and both are
  reported back as `dl_vlan`, which is why flows are compared under Ryu's names.
- **Ryu ignores match fields it does not know.** A typo like `in_prt` is dropped
  and the flow matches more than intended, so match fields and action types are
  validated before anything is queued.
- **Ryu answers 200 to flows the switch then refuses.** A missing prerequisite
  (`ip_proto` without `eth_type`), a group that does not exist, `DEC_NW_TTL` without
  an IP match, an action type spelled `output`: Ryu accepts, Open vSwitch does not
  install, nothing reports it. Prerequisites and spelling are checked when the
  request is made; for the rest, after applying, the flow table is read back and a
  write is only `applied` if the switch holds it (`verified: true`), otherwise it is
  `failed` and rolled back.
- **Ryu's own flows are hidden.** The table-miss and LLDP punt flows it installs
  are not anybody's configuration; `include_controller_defaults=true` shows them.

## Tests

```bash
python -m unittest discover -s tests/unit -t .     # no Ryu or network needed
```

`tests/` is split by what each part needs:

| folder | holds |
|---|---|
| `unit/` | the unit tests, against a stateful fake of Ryu's REST API |
| `support/` | that fake and the rig the tests share |
| `security/` | `adversarial` (attacks and a fuzzer against the tool surface) and `mutation_check` (disables each guard in turn) — `python -m tests.security.adversarial` |
| `live/` | `live_lab` and `stress_live`, against a real Ryu and Open vSwitch; they write to its switches, so point them only at a lab you own — `python -m tests.live.live_lab --ryu-url … --container …` |

## Licence

Apache 2.0. See [LICENSE](LICENSE).
