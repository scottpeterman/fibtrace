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
3. **Is the next-hop resolved?** — ARP/ND entry, MAC address learned?
4. **Is the egress link healthy?** — Interface up, error counters clean?

Then it follows the next-hop to the next device and repeats. The walk continues until it reaches a connected route (end of path), a black hole (problem found), or an unresolvable next-hop (problem found). ECMP paths are followed as a tree — every branch is validated, not just one.

## Quick Start

```bash
pip install paramiko

# Basic trace
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret

# Verbose — per-hop detail during the walk
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret -v

# Full diagnostic dump to JSON
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --log /tmp/trace.json

# JSON output for scripting
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --json

# Host address (auto /32)
python -m fibtrace -p 172.16.11.41 -s 172.16.1.6 -u admin --password secret

# Legacy SSH devices (old ciphers/KEX)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --legacy-ssh

# Skip MAC table lookups (faster on pure L3 paths)
python -m fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret --skip-mac
```

## Real Output

Five-hop trace across a multi-vendor lab (Arista EOS spines, Cisco IOS routers), ECMP split at hop 2:

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

Four-hop trace across Juniper vMX (14.1) and Arista EOS, mixed vendor path:

```
fibtrace: 172.17.1.29/32 from edge01.iad1
──────────────────────────────────────────────────
  hop 0: edge01.iad1          | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/0.0 → 172.17.1.23
  hop 1: agg1.iad1            | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  Port-Channel1 → 172.17.1.10
  hop 2: edge1-01.iad1        | route ✓ fib ✓ nh ✓ link ✓ → HEALTHY  ge-0/0/2.0 → 172.17.1.26
  hop 3: edge5-01.iad1        | route ✓ fib — nh — link — → HEALTHY (connected)  ge-0/0/1.0
──────────────────────────────────────────────────
Status: COMPLETE | 4 devices | 0 ECMP branches | 58.8s
```

Each line shows: the device hostname, the four forwarding checks (route/FIB/next-hop/link), the verdict, the egress interface(s), and where traffic goes next.

## Supported Platforms

| Platform | Parsing | Status |
|----------|---------|--------|
| **Arista EOS** | Native JSON (`\| json`) | ✅ Tested in production lab |
| **Cisco IOS/IOS-XE** | Regex | ✅ Tested in production lab |
| **Juniper Junos** | Native XML (`\| display xml`) | ✅ Tested in production lab (14.1+) |
| **Cisco NX-OS** | Native JSON (`\| json`) | Parsers written, untested |

Platform detection is automatic — fibtrace fingerprints each device via prompt analysis and `show version` output, then selects the correct command set and parser.

Mixed-vendor paths work transparently. The trace adapts its CLI syntax per hop (e.g., CIDR notation for EOS, dotted-mask for IOS, bare IP for Junos host routes) and its output parsing (JSON for EOS/NX-OS, XML for Junos, regex for IOS).

## Verdict Reference

fibtrace evaluates each hop against a truth table and assigns a verdict:

| Verdict | Meaning | Terminal? |
|---------|---------|-----------|
| `HEALTHY` | Route in RIB, programmed in FIB, next-hop resolved, link clean | No — walk continues |
| `NO_ROUTE` | No RIB entry for the prefix | Yes — path is broken here |
| `BLACKHOLE` | FIB entry is null/drop | Yes — traffic is discarded |
| `RIB_ONLY` | Route exists but not programmed in FIB | No — walk continues |
| `INCOMPLETE_ARP` | Next-hop ARP/ND is unresolved | No — walk continues |
| `INTERFACE_DOWN` | Egress interface is down | No — walk continues |
| `INTERFACE_ERRORS` | Error counters above threshold | No — walk continues |
| `UNREACHABLE` | SSH connection to device failed | Yes — can't evaluate |

Interface errors and ARP issues are flagged but **never stop the trace**. The walk always continues to the next hop — reachability is confirmed or denied by the SSH connection, not by error counters on the previous device.

The error counter threshold is configurable (`--error-threshold`, default 100). Minor errors on long-uptime interfaces are noted but don't change the verdict.

## Architecture

```
fibtrace/
├── __init__.py              # Package exports
├── __main__.py              # python -m fibtrace entry point
├── client.py                # SSH client (Paramiko invoke-shell wrapper)
├── models.py                # Vendor-neutral forwarding data models
├── commands_and_parsers.py  # Platform fingerprinting, command sets, IOS regex patterns
├── parsers.py               # Platform parsers: raw CLI output → model dataclasses
├── diagnostics.py           # Structured diagnostic capture and formatters
└── walker.py                # BFS chain walker, verdict assessment, CLI interface
```

### Design Decisions

**Forwarding-plane only.** fibtrace doesn't care about OSPF metrics, BGP local-pref, or admin distance. The routing protocol already picked a winner — fibtrace validates whether that winner is actually forwarding packets. Route protocol is recorded as a lightweight enum (connected, static, dynamic) for human context, not as an input to any decision.

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
| 3 | Regex | Cisco IOS/IOS-XE | Functional — tested against real devices |

Parsers are dispatched via a registry keyed on `(Platform, data_type)`. Adding a new platform means writing four parser functions (route, FIB, ARP, interface) and registering them.

### SSH Client

The SSH client is adapted from [Secure Cartography](https://github.com/scottpeterman/secure_cartography), a production-hardened Paramiko wrapper validated against 357+ devices. Features: invoke-shell mode (required for most network gear), pagination disable shotgun, legacy cipher/KEX support, ANSI sequence filtering, and multi-vendor prompt detection with hostname extraction.

## CLI Reference

```
usage: python -m fibtrace [-h] -p PREFIX -s SOURCE -u USERNAME
                          [--password PASSWORD] [--key-file KEY_FILE]
                          [--max-depth MAX_DEPTH] [--timeout TIMEOUT]
                          [--legacy-ssh] [--error-threshold ERROR_THRESHOLD]
                          [--skip-mac] [-v] [--debug] [--log LOG] [--json]

Arguments:
  -p, --prefix          Target prefix (e.g., 10.0.0.0/24 or 172.16.1.1)
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

The core walk engine is proven. These are the next targets, roughly in priority order:

- **Speed** — Async/parallel SSH within a BFS level. The two ECMP branches at a given depth connect sequentially today; they could connect simultaneously.
- **TUI dashboard** — Textual-based tree view with color-coded verdicts, drill-down into any hop for full diagnostics. Same pattern as [TerminalTelemetry](https://github.com/scottpeterman/terminaltelemetry).
- **TextFSM templates** — Replace IOS regex parsers with NTC-templates for better cross-version reliability.
- **IPv6** — Models already support it. Wire up v6 command variants and ND parsers.
- **MPLS label path tracing** — Models include label stacks and LFIB lookups. Parsers and walker integration needed.
- **VXLAN/overlay tracing** — Follow the overlay, then validate the underlay for each VTEP-to-VTEP segment.
- **Pre/post change comparison** — Snapshot a chain, make a change, snapshot again, diff the forwarding state.
- **NetBox integration** — Credential lookup, topology hints, expected-path validation.
- **Credential vault** — YubiKey, HashiCorp Vault integration via existing nterm patterns.

## License

MIT