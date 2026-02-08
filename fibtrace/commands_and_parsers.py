"""
Forwarding Chain Validator — Fingerprint, Commands, and Parser Strategy

Fingerprint: fast, dumb, reliable. Identify the platform from what SSH gives us.
Commands: per-platform command sets mapped to the four forwarding questions.
Parsers: structured output where available, regex/TextFSM where not.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


# ============================================================
# Fingerprinting — know what you're talking to, fast
# ============================================================
#
# Strategy: brute force, layered, fast-fail.
#
# Layer 1: SSH banner (before authentication)
#   - Cisco IOS/IOS-XE: often empty or "SSH-2.0-Cisco-1.25"
#   - Arista EOS: "SSH-2.0-OpenSSH_*" (not unique, but eliminates others)
#   - Juniper: "SSH-2.0-OpenSSH_*" (same problem)
#   - NX-OS: "SSH-2.0-OpenSSH_*" or "SSH-2.0-Cisco-1.25"
#   Verdict: helpful for Cisco IOS, not sufficient alone.
#
# Layer 2: Prompt pattern (after authentication, before any command)
#   - Cisco IOS/IOS-XE:  hostname#  or  hostname>
#   - Cisco NX-OS:        hostname#  (same, but often has domain)
#   - Arista EOS:         hostname#  or  hostname>  (same pattern)
#   - Juniper Junos:      user@hostname>  or  user@hostname#
#   Verdict: Juniper is unique. Cisco/Arista still ambiguous.
#
# Layer 3: Single command probe — the decider
#   Send: "show version" (universal, fast, no state change)
#   Match on output patterns:
#

class Platform(Enum):
    CISCO_IOS = "cisco_ios"             # IOS and IOS-XE
    CISCO_NXOS = "cisco_nxos"
    ARISTA_EOS = "arista_eos"
    JUNIPER_JUNOS = "juniper_junos"
    UNKNOWN = "unknown"


@dataclass
class FingerprintSignature:
    """Pattern to match against 'show version' (or equivalent) output."""
    platform: Platform
    patterns: list[str]                 # any match = positive ID
    prompt_pattern: Optional[str] = None  # regex for the CLI prompt


FINGERPRINTS = [
    FingerprintSignature(
        platform=Platform.CISCO_IOS,
        patterns=[
            r"Cisco IOS Software",
            r"Cisco IOS-XE Software",
            r"IOS \(tm\)",
            r"Cisco Internetwork Operating System",
        ],
        prompt_pattern=r"^[\w\-\.]+[#>]\s*$",
    ),
    FingerprintSignature(
        platform=Platform.CISCO_NXOS,
        patterns=[
            r"Cisco Nexus Operating System",
            r"NX-OS",
            r"cisco Nexus",
        ],
        prompt_pattern=r"^[\w\-\.]+[#>]\s*$",
    ),
    FingerprintSignature(
        platform=Platform.ARISTA_EOS,
        patterns=[
            r"Arista",
            r"EOS",
            r"vEOS",
        ],
        prompt_pattern=r"^[\w\-\.]+[#>]\s*$",
    ),
    FingerprintSignature(
        platform=Platform.JUNIPER_JUNOS,
        patterns=[
            r"Juniper Networks",
            r"JUNOS",
            r"junos",
        ],
        prompt_pattern=r"^[\w]+@[\w\-\.]+[>#%]\s*$",
    ),
]


def fingerprint_from_prompt(prompt: str) -> Optional[Platform]:
    """
    Layer 2: Quick check from prompt alone.
    Only Juniper is reliably unique here (user@host>).
    Returns None if ambiguous.
    """
    if re.match(r"^[\w]+@[\w\-\.]+[>#%]\s*$", prompt):
        return Platform.JUNIPER_JUNOS
    return None


def fingerprint_from_show_version(output: str) -> Platform:
    """
    Layer 3: Definitive ID from 'show version' output.
    First match wins — order matters (NX-OS before IOS since
    NX-OS output can contain 'Cisco' which would match IOS).
    """
    # Check NX-OS before IOS — NX-OS contains "Cisco" too
    ordered = [
        Platform.CISCO_NXOS,
        Platform.ARISTA_EOS,
        Platform.JUNIPER_JUNOS,
        Platform.CISCO_IOS,
    ]

    sig_map = {s.platform: s for s in FINGERPRINTS}

    for platform in ordered:
        sig = sig_map[platform]
        for pattern in sig.patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return platform

    return Platform.UNKNOWN


def get_version_command(prompt: str) -> str:
    """
    Even the version command differs by platform.
    If prompt suggests Juniper, use Junos syntax. Otherwise default Cisco/Arista.
    """
    if fingerprint_from_prompt(prompt) == Platform.JUNIPER_JUNOS:
        return "show version"           # same command, but could be 'show version brief'
    return "show version"               # universal enough


# ============================================================
# Disable paging — must happen before any command
# ============================================================

DISABLE_PAGING = {
    Platform.CISCO_IOS:     "terminal length 0",
    Platform.CISCO_NXOS:    "terminal length 0",
    Platform.ARISTA_EOS:    "terminal length 0",       # also: "no paging" in newer EOS
    Platform.JUNIPER_JUNOS: "set cli screen-length 0",
    Platform.UNKNOWN:       "terminal length 0",       # best guess
}


# ============================================================
# Command Sets — per platform, per forwarding question
# ============================================================
#
# Each command set maps to the four model questions:
#   1. Route?       → RIB lookup for target prefix
#   2. FIB?         → Hardware forwarding table lookup
#   3. Resolved?    → ARP/ND + MAC table + interface state
#   4. Link health? → Interface counters
#
# Commands use {prefix} and {next_hop} and {interface} as placeholders.
#


@dataclass
class CommandSet:
    """All commands needed to evaluate forwarding at one hop for one prefix."""

    # 1. Route lookup
    show_route: str                     # RIB entry for prefix
    show_route_v6: Optional[str] = None  # v6 variant if different syntax

    # 2. FIB lookup
    show_fib: str = ""
    show_fib_v6: Optional[str] = None

    # 3. Next-hop resolution
    show_arp: str = ""                  # ARP for v4 next-hop
    show_nd: str = ""                   # ND for v6 next-hop
    show_mac_table: str = ""            # Where does the MAC live?
    show_interface: str = ""            # Interface state + config

    # 4. Link health
    show_interface_counters: str = ""   # Error counters

    # MPLS label forwarding (when encap is MPLS)
    show_mpls_forwarding: str = ""      # LFIB lookup

    # Output mode — does this platform support structured output?
    json_supported: bool = False
    json_suffix: str = ""               # appended to commands for JSON output


COMMAND_SETS: dict[Platform, CommandSet] = {

    Platform.CISCO_IOS: CommandSet(
        # Route
        show_route="show ip route {prefix}",
        show_route_v6="show ipv6 route {prefix}",

        # FIB
        show_fib="show ip cef {prefix} detail",
        show_fib_v6="show ipv6 cef {prefix} detail",

        # Resolution
        show_arp="show ip arp {next_hop}",
        show_nd="show ipv6 neighbors {next_hop}",
        show_mac_table="show mac address-table address {mac}",
        show_interface="show interfaces {interface}",

        # Counters
        show_interface_counters="show interfaces {interface}",   # counters embedded

        # MPLS
        show_mpls_forwarding="show mpls forwarding-table {prefix}",

        # Output
        json_supported=False,
    ),

    Platform.CISCO_NXOS: CommandSet(
        show_route="show ip route {prefix}",
        show_route_v6="show ipv6 route {prefix}",

        show_fib="show forwarding route {prefix}",
        show_fib_v6="show forwarding ipv6 route {prefix}",

        show_arp="show ip arp {next_hop}",
        show_nd="show ipv6 neighbor {next_hop}",
        show_mac_table="show mac address-table address {mac}",
        show_interface="show interface {interface}",

        show_interface_counters="show interface {interface} counters errors",

        show_mpls_forwarding="show mpls forwarding-table {prefix}",

        # NX-OS supports JSON natively
        json_supported=True,
        json_suffix=" | json",
    ),

    Platform.ARISTA_EOS: CommandSet(
        show_route="show ip route {prefix}",
        show_route_v6="show ipv6 route {prefix}",

        show_fib="show ip route {prefix} detail",  # EOS: FIB state in route detail
        show_fib_v6="show ipv6 route {prefix} detail",

        show_arp="show ip arp {next_hop}",
        show_nd="show ipv6 neighbors {next_hop}",
        show_mac_table="show mac address-table address {mac}",
        show_interface="show interfaces {interface}",

        show_interface_counters="show interfaces {interface} counters errors",

        show_mpls_forwarding="show mpls lfib route {prefix}",

        # EOS supports JSON natively
        json_supported=True,
        json_suffix=" | json",
    ),

    Platform.JUNIPER_JUNOS: CommandSet(
        show_route="show route {prefix} active-path",
        show_route_v6="show route {prefix} active-path",   # unified table

        show_fib="show route forwarding-table destination {prefix}",
        show_fib_v6="show route forwarding-table destination {prefix}",

        show_arp="show arp no-resolve",
        show_nd="show ipv6 neighbors",  # full dump (14.1 doesn't support IP filter), parser filters
        show_mac_table="",  # Junos routers (MX/vMX/SRX) don't have ethernet-switching table
                             # EX/QFX switches do, but that's a future platform variant
        show_interface="show interfaces {interface}",

        show_interface_counters="show interfaces {interface} extensive",

        show_mpls_forwarding="show route table mpls.0 label {label}",

        # Junos: XML works on ALL versions (14.1+). JSON requires 14.2+
        # and was unreliable until 17.x. XML is the native structured
        # output — it's what NETCONF uses under the hood.
        json_supported=True,
        json_suffix=" | display xml",
    ),
}


# ============================================================
# Parser Strategy
# ============================================================
#
# Three tiers, best-to-worst:
#
# Tier 1: Native JSON (Arista EOS, NX-OS, Junos)
#   - Append json_suffix to command
#   - Parse JSON response directly into model dataclasses
#   - Most reliable, least fragile
#   - Arista: "show ip route 10.0.0.0/24 | json"
#   - NX-OS:  "show ip route 10.0.0.0/24 | json"
#   - Junos:  "show route 10.0.0.0/24 | display json"
#
# Tier 2: TextFSM templates
#   - For Cisco IOS/IOS-XE (no native JSON on most versions)
#   - NTC-templates covers most show commands
#   - Reliable for well-known output formats
#   - Fallback for older NX-OS / EOS versions
#
# Tier 3: Regex extraction
#   - Last resort for edge cases or unusual output
#   - Per-command, per-platform regex patterns
#   - Fragile, but sometimes the only option
#
# The parser layer sits between raw command output and the models.
# One parser class per platform, each method returns a model dataclass.
#

@dataclass
class ParserConfig:
    """How to parse output for a given platform."""
    platform: Platform
    prefer_json: bool = False
    textfsm_template_dir: Optional[str] = None  # path to NTC-templates or custom
    # When both JSON and TextFSM are available, JSON wins


PARSER_CONFIGS: dict[Platform, ParserConfig] = {
    Platform.CISCO_IOS: ParserConfig(
        platform=Platform.CISCO_IOS,
        prefer_json=False,              # IOS rarely has JSON
        textfsm_template_dir="templates/cisco_ios",
    ),
    Platform.CISCO_NXOS: ParserConfig(
        platform=Platform.CISCO_NXOS,
        prefer_json=True,
        textfsm_template_dir="templates/cisco_nxos",
    ),
    Platform.ARISTA_EOS: ParserConfig(
        platform=Platform.ARISTA_EOS,
        prefer_json=True,
        textfsm_template_dir="templates/arista_eos",
    ),
    Platform.JUNIPER_JUNOS: ParserConfig(
        platform=Platform.JUNIPER_JUNOS,
        prefer_json=True,
        textfsm_template_dir="templates/juniper_junos",
    ),
}


# ============================================================
# Cisco IOS Regex Patterns — the hard case
# ============================================================
#
# IOS is the most likely to need regex/TextFSM since most
# deployed IOS-XE versions lack reliable JSON output.
#

IOS_ROUTE_PATTERNS = {
    # "Routing entry for 10.0.0.0/24"
    "prefix": r"Routing entry for (\S+)",
    # "Known via "ospf 1", distance 110, metric 20"
    "protocol": r'Known via "(\S+)',
    # "  * 172.16.1.1, from 172.16.1.1, via GigabitEthernet0/1"
    "next_hop": r"\*?\s*([\d\.]+),.*via (\S+)",
}

IOS_CEF_PATTERNS = {
    # "10.0.0.0/24
    #    nexthop 172.16.1.1 GigabitEthernet0/1"
    "programmed_nh": r"nexthop\s+([\d\.]+)\s+(\S+)",
    # "attached to GigabitEthernet0/1"
    "attached": r"attached to (\S+)",
    # "drop"
    "drop": r"^\s*drop",
    # "receive"
    "receive": r"^\s*receive",
}

IOS_ARP_PATTERNS = {
    # "Internet  172.16.1.1    12   001a.2b3c.4d5e  ARPA   GigabitEthernet0/1"
    "entry": r"Internet\s+([\d\.]+)\s+(\d+|-)\s+([\da-fA-F\.]+)\s+ARPA\s+(\S+)",
    # Incomplete
    "incomplete": r"Internet\s+([\d\.]+)\s+.*Incomplete",
}

IOS_INTERFACE_PATTERNS = {
    # "GigabitEthernet0/1 is up, line protocol is up"
    "state": r"(\S+) is (\S+), line protocol is (\S+)",
    # "  MTU 1500 bytes, BW 1000000 Kbit/sec"
    "mtu_bw": r"MTU (\d+) bytes, BW (\d+) Kbit",
    # "     5 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored"
    "input_errors": r"(\d+) input errors, (\d+) CRC",
    # "     0 output errors, 0 collisions, 0 interface resets"
    "output_errors": r"(\d+) output errors",
}

IOS_MPLS_PATTERNS = {
    # "Local  Outgoing    Prefix            Bytes tag  Outgoing   Next Hop"
    # "16     Pop tag     10.0.0.0/24       0          Gi0/1      172.16.1.1"
    "entry": r"(\d+)\s+(Pop tag|Swap|Push|\d+)\s+(\S+)\s+\d+\s+(\S+)\s+([\d\.]+)",
}


# ============================================================
# Fingerprint + Gather Flow
# ============================================================
#
# The walker calls this sequence for each device:
#
#   1. SSH connect
#   2. Read prompt → fingerprint_from_prompt()
#      - If Juniper: done, we know
#      - If ambiguous: continue
#   3. Disable paging (using best-guess or confirmed platform)
#   4. Send "show version" → fingerprint_from_show_version()
#      - Now we know the platform definitively
#   5. Select CommandSet and ParserConfig
#   6. Execute commands for target prefix, substituting placeholders
#   7. Parse output into model dataclasses
#   8. Assess HopVerdict
#   9. Determine next_device_ips from resolved next-hops
#  10. SSH to next device(s), repeat
#
# Total commands per hop (typical v4, non-MPLS):
#   - show version:           1  (fingerprint, cached if revisiting)
#   - terminal length 0:      1  (paging)
#   - show ip route:          1  (RIB)
#   - show ip cef:            1  (FIB)
#   - show ip arp:            1  (per next-hop, usually 1-2)
#   - show mac address-table: 0-1 (only on L2 hops)
#   - show interfaces:        1  (per egress interface)
#   ─────────────────────────────
#   ~6-7 commands per hop, <2 seconds on a responsive device
#