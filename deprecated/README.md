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

### Default Route Fallback

When a device has no specific route for the target prefix, fibtrace doesn't stop. It checks for a default route (`0.0.0.0/0` or `::/0`) and continues the walk through it — because that's what the device would actually do with the traffic. The hop is annotated with `[via default]` so you can see exactly where the specific routing ends and default forwarding takes over. Only when there's no specific route *and* no default does fibtrace declare `NO_ROUTE`.

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

This happens transparently. The summary output shows both the data-plane next-hop and the resolved management target:

```
ge-0/0/0.0 → fe80::ea6:5aff:fe8b:9033 (→ 172.17.1.23)
```

No LLDP, no CDP, no topology database required — just the forwarding tables the device already has.

## Quick Start

```bash
pip install paramiko

# Basic IPv4 trace
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret

# IPv6 trace (management plane stays IPv4)
python -m fibtrace -p 2001:db8:1dc11::14/128 -s 172.17.1.29 -u admin --password secret

# Host address (auto /32 for IPv4, auto /128 for IPv6)
python -m fibtrace -p 172.16.11.41 -s 172.16.1.6 -u admin --password secret
python -m fibtrace -p 2001:db8:1dc11::14 -s 172.17.1.29 -u admin --password secret

# Verbose — per-hop detail during the walk
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret -v

# Full diagnostic dump to JSON
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --log /tmp/trace.json

# JSON output for scripting
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --json

# Legacy SSH devices (old ciphers/KEX)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --legacy-ssh

# Skip MAC table lookups (faster on pure L3 paths)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --skip-mac

# DNS domain suffix for neighbor discovery
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --domain example.com
```

## Real Output

Six-hop IPv4 trace starting from a Cisco IOS L2 switch with no specific route — fibtrace follows the default route, then continues across Arista EOS and Cisco IOS with ECMP fan-out at hop 3:

```
fibtrace: 172.16.11.41/32 from usa-leaf-3
──────────────────────────────────────────────────
  hop 0: usa-leaf-3           | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Vlan10 → 172.16.10.1
  hop 1: usa-spine-2          | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Ethernet1 → 172.16.1.5
  hop 2: usa-rtr-1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  GigabitEthernet0/3 → 172.16.128.6
  hop 3: eng-rtr-1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  GigabitEthernet0/2 → 172.16.2.2, GigabitEthernet0/3 → 172.16.2.6
  hop 4: eng-spine-1          | route ✓ fib — nh — link — → HEALTHY (connected)  Vlan11
  hop 5: eng-spine-2          | route ✓ fib — nh — link — → HEALTHY (connected)  Vlan11
──────────────────────────────────────────────────
Status: COMPLETE | 6 devices | 1 ECMP branches | 95.4s
```

Hop 0 has no specific route for the /32 — fibtrace detects the default route (`0.0.0.0/0 via 172.16.10.1`), validates the FIB entry (`recursive via` resolved through Vlan10), confirms ARP resolution, and continues the walk. Verbose mode shows the fallback:

```
  [✓] show ip route 172.16.11.41 parse:[✗] via regex       ← no specific route
  [✓] show ip route 0.0.0.0 0.0.0.0 parse:[✓] via regex   ← default route found
  [✓] show ip cef 0.0.0.0 0.0.0.0 detail parse:[✓] via regex
  [✓] show ip arp 172.16.10.1 parse:[✓] via regex
  [✓] show interfaces Vlan10 parse:[✓] via regex
  ─── Verdict: healthy ───
    route:  [via default] static via 172.16.10.1 on ?
```

Five-hop trace starting from an Arista EOS spine (same path, no default route needed):

```
fibtrace: 172.16.11.41/32 from usa-spine-2
──────────────────────────────────────────────────
  hop 0: usa-spine-2          | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Ethernet1 → 172.16.1.5
  hop 1: usa-rtr-1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  GigabitEthernet0/3 → 172.16.128.6
  hop 2: eng-rtr-1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  GigabitEthernet0/2 → 172.16.2.2, GigabitEthernet0/3 → 172.16.2.6
  hop 3: eng-spine-1          | route ✓ fib — nh — link — → HEALTHY (connected)  Vlan11
  hop 4: eng-spine-2          | route ✓ fib — nh — link — → HEALTHY (connected)  Vlan11
──────────────────────────────────────────────────
Status: COMPLETE | 5 devices | 1 ECMP branches | 77.0s
```

Four-hop IPv4 trace across Juniper vMX (14.1) and Arista EOS, mixed vendor path:

```
fibtrace: 172.17.1.29/32 from border01
──────────────────────────────────────────────────
  hop 0: border01          | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/0.0 → 172.17.1.23
  hop 1: agg1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Port-Channel1 → 172.17.1.10
  hop 2: border1-01        | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/2.0 → 172.17.1.26
  hop 3: border5-01        | route ✓ fib — nh — link — → HEALTHY (connected)  ge-0/0/1.0
──────────────────────────────────────────────────
Status: COMPLETE | 4 devices | 0 ECMP branches | 58.8s
```

Three-hop IPv6 trace across Arista EOS and Juniper Junos with link-local next-hops (OSPFv3):

```
fibtrace: 2001:db8:1dc11::14/128 from spine-01
──────────────────────────────────────────────────
  hop 0: spine-01         | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Ethernet1 → fe80::205:86ff:fe71:5b01 (→ 172.17.1.28)
  hop 1: border5-01        | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/0.0 → fe80::205:86ff:fe71:8503 (→ 172.17.1.33)
  hop 2: border1-02        | route ✓ fib — nh — link — → HEALTHY (connected)  lo0.0
──────────────────────────────────────────────────
Status: COMPLETE | 3 devices | 0 ECMP branches | 46.5s
```

Four-hop IPv6 trace originating from Cisco IOS, across Arista EOS and Juniper Junos — three vendors, link-local resolution via EUI-64 fallback at the IOS hop:

```
fibtrace: 2001:db8:1dc11::12/128 from access-sw1
──────────────────────────────────────────────────
  hop 0: access-sw1               | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  GigabitEthernet0/0 → fe80::e3f:42ff:fef4:b565 (→ 172.17.202.1)
  hop 1: spine-01         | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Ethernet1 → fe80::205:86ff:fe71:5b01 (→ 172.17.1.28)
  hop 2: border5-01        | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/2.0 → fe80::205:86ff:fe71:3902 (→ 172.17.1.27)
  hop 3: border1-01        | route ✓ fib — nh — link — → HEALTHY (connected)  lo0.0
──────────────────────────────────────────────────
Status: COMPLETE | 4 devices | 0 ECMP branches | 80.0s
```

Each line shows: the device hostname, the four forwarding checks (route/FIB/next-hop/link), the verdict, the egress interface(s), and where traffic goes next. For IPv6 link-local next-hops, the resolved IPv4 SSH target is shown in parentheses.

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
├── client.py                # SSH client (Paramiko invoke-shell wrapper)
├── models.py                # Vendor-neutral forwarding data models (dual-stack)
├── commands_and_parsers.py  # Platform fingerprinting, command sets, AF-aware dispatch
├── parsers.py               # Platform parsers: raw CLI output → model dataclasses
├── diagnostics.py           # Structured diagnostic capture and formatters
└── walker.py                # BFS chain walker, verdict assessment, neighbor discovery
```

### Design Decisions

**Forwarding-plane only.** fibtrace doesn't care about OSPF metrics, BGP local-pref, or admin distance. The routing protocol already picked a winner — fibtrace validates whether that winner is actually forwarding packets. Route protocol is recorded as a lightweight enum (connected, static, dynamic) for human context, not as an input to any decision.

**Default route aware.** When a device has no specific route but has a default, that's a valid forwarding decision — the device *will* forward the packet. fibtrace follows the default just like any other route, annotating the hop so you can see where specific routing ends. This matters in leaf-spine and stub networks where edge devices routinely forward via default.

**Dual-stack from the ground up.** Address family is detected from the target prefix and drives the entire walk — command selection, parser dispatch, next-hop resolution strategy. IPv4 and IPv6 share the same models, walker, and verdict logic. The only AF-specific code is in command templates and the link-local resolver. Both address families are exercised through the same code paths, so v4 behavior is never regressed by v6 changes.

**Link-local resolution without topology.** OSPFv3 (and IS-IS) use link-local next-hops that can't be SSH'd to. Rather than requiring LLDP, CDP, or a topology database, fibtrace correlates across address families: ND gives a MAC, the ARP table gives the IPv4 address that owns that MAC. This works because any device running dual-stack will have both ND and ARP entries for the same physical neighbor. When the ND table is empty (e.g., IOS devices with no IPv6 on the transit interface), fibtrace derives the MAC directly from the EUI-64 encoding in the link-local address — no extra commands needed. Two extra commands per link-local hop, zero external dependencies.

**Neighbor discovery fallback.** When direct SSH to a FIB next-hop fails (transit IPs not in the management plane, ACLs blocking SSH on data interfaces), fibtrace queries LLDP and CDP on the parent device's egress interface to find the neighbor's management address. For LAG interfaces, it detects the aggregate and falls back to a filtered full-table query. If LLDP/CDP returns a system name but no management IP, fibtrace resolves the name via DNS with an optional domain suffix (`--domain`). Three fallback layers before declaring a device unreachable.

**Hostname-based device tracking.** Devices are identified by the hostname extracted from the CLI prompt, not by the SSH target IP. In real networks, the same device is reachable via multiple IPs (management, loopback, transit interfaces), and different devices can share IPs (unnumbered interfaces, overlapping transit subnets). The prompt is the canonical identity. This means loop detection is post-connection — one SSH handshake is burned to discover a revisit. Acceptable for chains of 3–15 devices.

**BFS tree walk.** ECMP at any hop creates branches. fibtrace walks breadth-first: all devices at depth N are evaluated before depth N+1. Loop detection via visited hostname set catches cycles at the shallowest depth.

**Diagnostic-first.** Every command execution is wrapped in a diagnostic record: the exact command sent, the full raw output, which parser was used, what it extracted (or why it failed), and wall-clock timing. Parser failures are never silent. Three output levels: summary (always), verbose (`-v`), and full JSON dump (`--log`).

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
                          [-v] [--debug] [--log LOG] [--json]

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
  -v, --verbose         Print per-hop summaries during the walk
  --debug               Debug-level logging
  --log FILE            Write full diagnostic JSON to file
  --json                Output chain result as JSON (for scripting)
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

## Roadmap

The core walk engine is proven across both address families. These are the next targets, roughly in priority order:

- **Speed** — Async/parallel SSH within a BFS level. The two ECMP branches at a given depth connect sequentially today; they could connect simultaneously.
- **TUI dashboard** — Textual-based tree view with color-coded verdicts, drill-down into any hop for full diagnostics. Same pattern as [TerminalTelemetry](https://github.com/scottpeterman/terminaltelemetry).
- **TextFSM templates** — Replace IOS regex parsers with NTC-templates for better cross-version reliability.
- **NX-OS IPv6 parsers** — v6 command templates are in place; ND and ARP-by-MAC parsers needed for NX-OS to complete quad-platform v6 coverage.
- **MPLS label path tracing** — Models include label stacks and LFIB lookups. Parsers and walker integration needed.
- **VXLAN/overlay tracing** — Follow the overlay, then validate the underlay for each VTEP-to-VTEP segment.
- **Pre/post change comparison** — Snapshot a chain, make a change, snapshot again, diff the forwarding state.
- **NetBox integration** — Credential lookup, topology hints, expected-path validation.
- **Credential vault** — YubiKey, HashiCorp Vault integration via existing nterm patterns.

## License

MIT