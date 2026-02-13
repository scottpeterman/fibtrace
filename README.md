# fibtrace

Hop-by-hop forwarding chain validation from the device perspective. Not a traceroute — a FIB trace.

## The Problem

When a network path breaks, traceroute tells you *where* packets die. It doesn't tell you *why*.

To find the root cause, you SSH into the first device, check the route table, check the FIB, validate ARP resolution, inspect the egress interface — then move to the next hop and do it all again. Device by device, control plane to data plane, tedious but precise.

Every network engineer knows this workflow. Nobody has automated it.

fibtrace does. Given a target prefix and a starting device, it walks the forwarding chain hop by hop, validating what each device actually knows and what it's actually doing with the traffic. When it finds ECMP, it follows every branch. When it finds a problem, it tells you exactly what broke and where.

## How It Works

At each hop, fibtrace asks four questions:

1. **Is there a route?** — RIB lookup for the prefix
2. **Is it in the FIB?** — Is the route programmed in the forwarding table?
3. **Is the next-hop resolved?** — ARP entry (IPv4) or ND entry (IPv6), MAC address learned?
4. **Is the egress link healthy?** — Interface up, error counters clean?

Then it follows the next-hop to the next device and repeats. The walk continues until it reaches a connected route (end of path), a black hole (problem found), or an unresolvable next-hop (problem found). ECMP paths are followed as a tree — every branch is validated, not just one.

## Quick Start

```bash
pip install paramiko textual rich

# TUI mode (default) — live tree + log visualization
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret

# Demo mode — replay a mock 6-hop ECMP trace (no network needed)
python -m fibtrace --demo

# Host address (auto /32 for IPv4, auto /128 for IPv6)
python -m fibtrace -p 172.16.11.41 -s 172.16.1.6 -u admin --password secret
python -m fibtrace -p 2001:db8:1dc11::14 -s 172.17.1.29 -u admin --password secret

# IPv6 trace (management plane stays IPv4)
python -m fibtrace -p 2001:db8:1dc11::14/128 -s 172.17.1.29 -u admin --password secret

# Legacy SSH devices (old ciphers/KEX)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --legacy-ssh

# Skip MAC table lookups (faster on pure L3 paths)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --skip-mac

# DNS domain suffix for neighbor discovery
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --domain example.com

# JSON output for scripting (headless, no TUI)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --json

# Full diagnostic dump to JSON
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --log /tmp/trace.json
```

## TUI

fibtrace runs as a terminal application with a split-pane layout: a forwarding tree on the left and a live log on the right. Devices appear in the tree as they're discovered, with a spinner while probing and a verdict icon when complete. ECMP branches fork visually as sibling nodes.

![fibtrace TUI — verbose mode showing a 6-hop ECMP trace across Cisco IOS and Arista EOS](https://raw.githubusercontent.com/scottpeterman/fibtrace/main/screenshots/tui1.png)

Three log verbosity levels, toggled live with a keypress:

| Key | Level | Shows |
|-----|-------|-------|
| `b` | **Basic** | Connection events, per-hop verdicts, ECMP notifications, final summary |
| `v` | **Verbose** | + every command sent, parser result (✓/✗), parser type, verdict reasoning |
| `d` | **Debug** | + raw command output excerpts, parse detail, prompt/platform confidence, timing |

![fibtrace TUI — debug mode showing raw command output and JSON parse results per hop](https://raw.githubusercontent.com/scottpeterman/fibtrace/refs/heads/main/screenshots/tui_debug.png)

The status bar shows completion state, device count, ECMP branches, elapsed time, active log level, and keybindings. Press `q` to quit.

### Default Route Fallback

When a device has no specific route for the target prefix, fibtrace doesn't stop. It checks for a default route (`0.0.0.0/0` or `::/0`) and continues the walk through it — because that's what the device would actually do with the traffic. The hop is annotated with `[via default]` in the tree so you can see exactly where the specific routing ends and default forwarding takes over. Only when there's no specific route *and* no default does fibtrace declare `NO_ROUTE`.

### Neighbor Discovery Fallback

When the FIB next-hop IP isn't directly reachable via SSH (common with transit interfaces that use non-management addressing), fibtrace falls back to neighbor discovery on the parent device to find a reachable management address:

1. **LLDP** on the egress interface → extract management address
2. **CDP** on the egress interface → extract management address (Cisco platforms)
3. **DNS resolution** on the LLDP/CDP system name → resolve to IP

For LAG interfaces (Port-Channel, ae, bond, Ethernet-Trunk), fibtrace automatically detects the aggregate and falls back to a filtered full-table query when per-interface LLDP/CDP returns nothing — because most platforms report LLDP neighbors on the physical members, not the bundle.

DNS resolution tries the system name as-is, then with a configurable domain suffix (`--domain`), then bare as a search-domain fallback. This handles environments where LLDP reports short hostnames (e.g., `rtr03.dc1`) that need a domain appended to resolve.

No topology database required — just the protocols the devices already speak.

### IPv6 and Link-Local Next-Hops

fibtrace is fully dual-stack. IPv6 prefixes are traced using the correct address-family commands per platform (`show ipv6 route`, `inet6.0` table, v6 forwarding table lookups) with ND replacing ARP for next-hop resolution.

OSPFv3 and other v6 IGPs commonly use link-local addresses (`fe80::`) as next-hops. These aren't routable — you can't SSH to them. fibtrace resolves link-local next-hops automatically via cross-AF correlation:

```
link-local NH → ND lookup → MAC address → ARP table search → IPv4 management IP → SSH
```

When the ND table is empty (common on devices without IPv6 addresses on the transit interface), fibtrace falls back to EUI-64 MAC derivation — most network hardware generates link-local addresses from the interface MAC using the EUI-64 encoding, so the MAC is embedded directly in the `fe80::` address:

```
fe80::e3f:42ff:fef4:b565 → flip bit 7, remove ff:fe → MAC 0c:3f:42:f4:b5:65 → ARP search → IPv4
```

This happens transparently. The tree shows both the data-plane next-hop and the resolved management target:

```
ge-0/0/0.0 → fe80::ea6:5aff:fe8b:9033 (→ 172.17.1.23)
```

No LLDP, no CDP, no topology database required — just the forwarding tables the device already has.

## Supported Platforms

| Platform | Parsing | IPv4 | IPv6 | Status |
|----------|---------|------|------|--------|
| **Arista EOS** | Native JSON (`\| json`) | ✅ | ✅ | Tested in production lab |
| **Juniper Junos** | Native XML (`\| display xml`) | ✅ | ✅ | Tested in production lab (14.1+) |
| **Cisco IOS/IOS-XE** | Regex (ranked pattern list) | ✅ | ✅ | Tested in production lab |
| **Cisco NX-OS** | Native JSON (`\| json`) | ✅ | v6 commands ready, parsers pending | Parsers written, untested |

Platform detection is automatic — fibtrace fingerprints each device via prompt analysis and `show version` output, then selects the correct command set and parser.

Mixed-vendor paths work transparently. The trace adapts its CLI syntax per hop (e.g., CIDR notation for EOS, dotted-mask for IOS, bare IP for Junos host routes) and its output parsing (JSON for EOS/NX-OS, XML for Junos, regex for IOS). Address family is detected from the target prefix and drives command selection automatically — `show ip route` vs `show ipv6 route`, `show arp` vs `show ipv6 neighbors`, v4 vs v6 FIB tables.

## Verdict Reference

fibtrace evaluates each hop against a truth table and assigns a verdict:

| Verdict | Meaning | Terminal? |
|---------|---------|-----------|
| `HEALTHY` | Route in RIB, programmed in FIB, next-hop resolved, link clean | No — walk continues |
| `NO_ROUTE` | No RIB entry for the prefix (and no default route) | Yes — path is broken here |
| `BLACKHOLE` | FIB entry is null/drop | Yes — traffic is discarded |
| `RIB_ONLY` | Route exists but not programmed in FIB | No — walk continues |
| `INCOMPLETE_ARP` | Next-hop ARP/ND is unresolved | No — walk continues |
| `INTERFACE_DOWN` | Egress interface is down | No — walk continues |
| `INTERFACE_ERRORS` | Error counters above threshold | No — walk continues |
| `UNREACHABLE` | SSH connection to device failed (after neighbor discovery fallback) | Yes — can't evaluate |

Interface errors and ARP issues are flagged but **never stop the trace**. The walk always continues to the next hop — reachability is confirmed or denied by the SSH connection, not by error counters on the previous device.

The error counter threshold is configurable (`--error-threshold`, default 100). Minor errors on long-uptime interfaces are noted but don't change the verdict.

## Architecture

```
fibtrace/
├── __init__.py              # Package exports
├── __main__.py              # python -m fibtrace entry point
├── app.py                   # Textual TUI — tree + log split-pane, live walker integration
├── client.py                # SSH client (Paramiko invoke-shell wrapper)
├── commands_and_parsers.py  # Platform fingerprinting, command sets, AF-aware dispatch
├── diagnostics.py           # Structured diagnostic capture and formatters
├── events.py                # HopEvent dataclass — walker ↔ TUI contract
├── models.py                # Vendor-neutral forwarding data models (dual-stack)
├── parsers.py               # Platform parsers: raw CLI output → model dataclasses
├── theme.tcss               # TUI dark terminal theme (Textual CSS)
└── walker.py                # BFS chain walker, verdict assessment, neighbor discovery
```

### Walker ↔ TUI Integration

The walker is synchronous (Paramiko blocking SSH). The TUI is async (Textual event loop). They communicate through a single shared type — `HopEvent` — defined in `events.py`. Neither side imports the other.

```
Walker thread                    TUI async loop
─────────────                    ──────────────
ChainWalker.walk()               FibTraceApp._run_live_trace()
  ├─ connect, fingerprint          │
  ├─ emit(hop_start) ──queue.put──→├─ queue.get() → _add_pending_node()
  ├─ gather forwarding state       │
  ├─ emit(hop_done)  ──queue.put──→├─ queue.get() → _update_node_verdict()
  ├─ enqueue next-hops             │
  └─ emit(trace_done) ─queue.put──→└─ queue.get() → _update_status()
```

The walker pushes `HopEvent` objects into a thread-safe `queue.Queue`. The TUI polls at 50ms and processes events on the main Textual thread. No callback set? Zero overhead — the walker runs identically in headless mode.

### Design Decisions

**Forwarding-plane only.** fibtrace doesn't care about OSPF metrics, BGP local-pref, or admin distance. The routing protocol already picked a winner — fibtrace validates whether that winner is actually forwarding packets. Route protocol is recorded as a lightweight enum (connected, static, dynamic) for human context, not as an input to any decision.

**Default route aware.** When a device has no specific route but has a default, that's a valid forwarding decision — the device *will* forward the packet. fibtrace follows the default just like any other route, annotating the hop so you can see where specific routing ends. This matters in leaf-spine and stub networks where edge devices routinely forward via default.

**Dual-stack from the ground up.** Address family is detected from the target prefix and drives the entire walk — command selection, parser dispatch, next-hop resolution strategy. IPv4 and IPv6 share the same models, walker, and verdict logic. The only AF-specific code is in command templates and the link-local resolver. Both address families are exercised through the same code paths, so v4 behavior is never regressed by v6 changes.

**Link-local resolution without topology.** OSPFv3 (and IS-IS) use link-local next-hops that can't be SSH'd to. Rather than requiring LLDP, CDP, or a topology database, fibtrace correlates across address families: ND gives a MAC, the ARP table gives the IPv4 address that owns that MAC. This works because any device running dual-stack will have both ND and ARP entries for the same physical neighbor. When the ND table is empty (e.g., IOS devices with no IPv6 on the transit interface), fibtrace derives the MAC directly from the EUI-64 encoding in the link-local address — no extra commands needed. Two extra commands per link-local hop, zero external dependencies.

**Neighbor discovery fallback.** When direct SSH to a FIB next-hop fails (transit IPs not in the management plane, ACLs blocking SSH on data interfaces), fibtrace queries LLDP and CDP on the parent device's egress interface to find the neighbor's management address. For LAG interfaces, it detects the aggregate and falls back to a filtered full-table query. If LLDP/CDP returns a system name but no management IP, fibtrace resolves the name via DNS with an optional domain suffix (`--domain`). Three fallback layers before declaring a device unreachable.

**Hostname-based device tracking.** Devices are identified by the hostname extracted from the CLI prompt, not by the SSH target IP. In real networks, the same device is reachable via multiple IPs (management, loopback, transit interfaces), and different devices can share IPs (unnumbered interfaces, overlapping transit subnets). The prompt is the canonical identity. This means loop detection is post-connection — one SSH handshake is burned to discover a revisit. Acceptable for chains of 3–15 devices.

**BFS tree walk.** ECMP at any hop creates branches. fibtrace walks breadth-first: all devices at depth N are evaluated before depth N+1. Loop detection via visited hostname set catches cycles at the shallowest depth. ECMP convergence (sibling paths reconverging on the same device) is distinguished from real loops via ancestor tracking — each queue item carries a frozenset of hostnames on its path from the root.

**Diagnostic-first.** Every command execution is wrapped in a diagnostic record: the exact command sent, the full raw output, which parser was used, what it extracted (or why it failed), and wall-clock timing. Parser failures are never silent. Three TUI log levels (basic/verbose/debug) surface increasing diagnostic detail in real time, and `--log` dumps the full JSON post-mortem.

### Parser Strategy

Three tiers, best to worst:

| Tier | Method | Platforms | Reliability |
|------|--------|-----------|-------------|
| 1 | Native JSON | Arista EOS, NX-OS | High — structured output |
| 1 | Native XML | Juniper Junos (14.1+) | High — stable across all versions |
| 2 | TextFSM | Cisco IOS/IOS-XE (future) | Medium — template-based |
| 3 | Ranked Regex | Cisco IOS/IOS-XE | Functional — tested against real devices |

Parsers are dispatched via a registry keyed on `(Platform, data_type)`. Data types include: `route`, `fib`, `arp`, `nd`, `arp_by_mac`, `interface`, and `mac_table`. Adding a new platform means writing parser functions for the relevant data types and registering them. The `nd` and `arp_by_mac` parsers are implemented for Junos, EOS, and IOS — all three platforms tested with v6 in production.

#### IOS Ranked Pattern List

IOS output formatting varies across 30+ years of software trains — OSPF routes include `from` and `via` clauses, static routes may omit both, default routes add `, supernet` after the prefix, and recursive CEF entries nest `attached to` under `recursive via`. A single regex can't cover all variants without becoming unmaintainable.

The IOS route parser uses a ranked pattern list: an ordered sequence of `(name, regex, groups)` tuples from most specific to most general. The parser tries each pattern against the Routing Descriptor Blocks text; the first pattern to produce matches wins. This makes each IOS output variant an independently testable unit — when a new variant appears in production, you add a pattern at the right specificity rank without touching existing ones.

Current route next-hop patterns:

| Rank | Name | Matches | Example |
|------|------|---------|---------|
| 1 | `full_from_via` | OSPF, BGP, EIGRP with full descriptor | `* 172.16.1.1, from 172.16.1.1, via Gi0/1` |
| 2 | `static_via` | Static routes with explicit interface | `* 10.1.1.1, via GigabitEthernet0/0` |
| 3 | `static_bare` | Static/default, bare next-hop only | `* 172.16.10.1` |

Diagnostics log which pattern matched, so parser behavior is traceable in the JSON dump without reading regex.

### SSH Client

The SSH client is adapted from [Secure Cartography](https://github.com/scottpeterman/secure_cartography), a production-hardened Paramiko wrapper validated against 350+ devices. Features: invoke-shell mode (required for most network gear), pagination disable shotgun, legacy cipher/KEX support, ANSI sequence filtering, and multi-vendor prompt detection with hostname extraction.

## CLI Reference

```
usage: python -m fibtrace [-h] -p PREFIX -s SOURCE -u USERNAME
                          [--password PASSWORD] [--key-file KEY_FILE]
                          [--max-depth MAX_DEPTH] [--timeout TIMEOUT]
                          [--legacy-ssh] [--error-threshold ERROR_THRESHOLD]
                          [--skip-mac] [--domain DOMAIN]
                          [--log LOG] [--json] [--demo]

Arguments:
  -p, --prefix          Target prefix (e.g., 10.0.0.0/24, 172.16.1.1,
                        2001:db8::/32, or 2001:db8::1)
  -s, --source          Source device IP to start the walk
  -u, --username        SSH username
  --password            SSH password
  --key-file            Path to SSH private key

Options:
  --max-depth           Maximum hop depth (default: 15)
  --timeout             Per-command timeout in seconds (default: 10.0)
  --legacy-ssh          Enable legacy SSH ciphers/KEX for old devices
  --error-threshold     Interface error count threshold (default: 100)
  --skip-mac            Skip MAC table lookups (faster on L3 paths)
  --domain              DNS domain suffix for neighbor hostname resolution
                        (e.g., 'example.com' resolves 'rtr03' as
                        'rtr03.example.com')

Output:
  --log FILE            Write full diagnostic JSON to file
  --json                Output chain result as JSON (headless, no TUI)
  --demo                Run with mock trace data (no network needed)

TUI Controls:
  b                     Basic log level — verdicts and connection events
  v                     Verbose — per-command parse results and verdict reasoning
  d                     Debug — raw output excerpts, timing, parser detail
  q                     Quit
```

## JSON Output

With `--json`, fibtrace outputs a machine-readable trace suitable for integration with other tools:

```json
{
  "target_prefix": "172.16.11.41/32",
  "source_device": "usa-spine-2",
  "status": "complete",
  "is_healthy": true,
  "total_devices": 5,
  "ecmp_branches": 1,
  "duration_seconds": 77.0,
  "hops": [
    {
      "device": "usa-spine-2",
      "ip": "172.16.1.6",
      "platform": "arista_eos",
      "verdict": "healthy",
      "is_terminal": false,
      "next_hops": ["172.16.1.5"],
      "notes": []
    }
  ],
  "anomalies": []
}
```

With `--log FILE`, fibtrace writes a full diagnostic JSON dump including every command sent, raw output received, parser used, parse result, and timing. This is the post-mortem record — everything needed to understand what the tool saw and how it interpreted it.

## Requirements

- Python 3.10+
- paramiko
- textual
- rich

## Roadmap

The core walk engine and TUI are proven across both address families and four vendor platforms. These are the next targets, roughly in priority order:

- **Speed** — Async/parallel SSH within a BFS level. The two ECMP branches at a given depth connect sequentially today; they could connect simultaneously.
- **TextFSM templates** — Replace IOS regex parsers with NTC-templates for better cross-version reliability.
- **NX-OS IPv6 parsers** — v6 command templates are in place; ND and ARP-by-MAC parsers needed for NX-OS to complete quad-platform v6 coverage.
- **MPLS label path tracing** — Models include label stacks and LFIB lookups. Parsers and walker integration needed.
- **VXLAN/overlay tracing** — Follow the overlay, then validate the underlay for each VTEP-to-VTEP segment.
- **Pre/post change comparison** — Snapshot a chain, make a change, snapshot again, diff the forwarding state.
- **NetBox integration** — Credential lookup, topology hints, expected-path validation.
- **Credential vault** — YubiKey, HashiCorp Vault integration via existing nterm patterns.

## License

MIT