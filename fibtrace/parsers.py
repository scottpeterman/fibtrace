"""
Forwarding Chain Validator — Platform Parsers

The missing middle layer: raw command output → model dataclasses.

Three tiers per platform:
  Tier 1: Native JSON   (Arista EOS, NX-OS, Junos)
  Tier 2: TextFSM       (Cisco IOS — future)
  Tier 3: Regex          (Cisco IOS — implemented here)

Every parser function:
  - Takes raw CLI output (str)
  - Returns a model dataclass or None
  - Never raises — failures return None and are captured by diagnostics
  - Handles both expected and degenerate output gracefully

Parser dispatch:
  get_parser(platform, data_type) → callable
  The walker calls this to get the right parser for the platform and data type.
"""

from __future__ import annotations
import json
import re
import logging
from datetime import timedelta
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address
from typing import Optional, Any

from .models import (
    Prefix, AddressFamily, MacAddress,
    ArpEntry, ArpState, MacTableEntry,
    Interface, InterfaceState, InterfaceCounters, L2Type,
    RouteEntry, RouteNextHop, RouteProtocol,
    FibEntry, FibNextHop, FibState,
    Encapsulation, EncapType,
)
from .commands_and_parsers import Platform

logger = logging.getLogger("fibtrace.parsers")


# ============================================================
# Utility — safe extraction helpers
# ============================================================

def _safe_json(raw: str) -> Optional[dict]:
    """Parse JSON from CLI output, stripping leading/trailing garbage."""
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # Some devices prefix JSON with the command echo or prompt
    # Find the first '{' or '['
    for i, ch in enumerate(text):
        if ch in ('{', '['):
            text = text[i:]
            break
    else:
        return None

    # Trim trailing prompt/garbage after the last '}' or ']'
    for i in range(len(text) - 1, -1, -1):
        if text[i] in ('}', ']'):
            text = text[:i + 1]
            break

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _safe_ip(addr_str: str) -> Optional[IPv4Address | IPv6Address]:
    """Parse an IPv4 or IPv6 address, return None on failure."""
    if not addr_str:
        return None
    try:
        return IPv4Address(addr_str.strip())
    except (ValueError, AttributeError):
        try:
            return IPv6Address(addr_str.strip())
        except (ValueError, AttributeError):
            return None


def _safe_network(prefix_str: str) -> Optional[IPv4Network | IPv6Network]:
    """Parse an IPv4 or IPv6 network, return None on failure."""
    if not prefix_str:
        return None
    try:
        return IPv4Network(prefix_str.strip(), strict=False)
    except (ValueError, AttributeError):
        try:
            return IPv6Network(prefix_str.strip(), strict=False)
        except (ValueError, AttributeError):
            return None


def _normalize_mac(mac_str: str) -> Optional[str]:
    """Normalize MAC to aa:bb:cc:dd:ee:ff format."""
    if not mac_str:
        return None
    # Strip and lowercase
    mac = mac_str.strip().lower()
    # Remove common delimiters
    mac = re.sub(r'[.:\-]', '', mac)
    if len(mac) != 12:
        return None
    # Reformat
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


def _classify_protocol(proto_str: str) -> RouteProtocol:
    """Map vendor protocol strings to our lightweight enum."""
    if not proto_str:
        return RouteProtocol.UNKNOWN
    p = proto_str.strip().lower()
    if p in ("connected", "direct", "local"):
        return RouteProtocol.CONNECTED
    if p == "local":
        return RouteProtocol.LOCAL
    if p in ("static",):
        return RouteProtocol.STATIC
    # Everything else is dynamic — we don't care which protocol
    return RouteProtocol.DYNAMIC


def _make_prefix(prefix_str: str) -> Optional[Prefix]:
    """Build a Prefix from a string like '10.0.0.0/24'."""
    net = _safe_network(prefix_str)
    if net is None:
        return None
    return Prefix(network=net)


# ============================================================
# Arista EOS — Native JSON Parsers
# ============================================================
# EOS JSON is the cleanest. Well-structured, consistent key names,
# stable across versions. The happy path.

class AristaEOSParser:
    """Parse Arista EOS JSON command output into model dataclasses."""

    @staticmethod
    def parse_route(raw: str, target_prefix: str) -> Optional[RouteEntry]:
        """
        Parse: show ip route {prefix} | json

        EOS JSON structure:
        {
          "vrfs": {
            "default": {
              "routes": {
                "10.0.0.0/24": {
                  "routeType": "eBGP",
                  "kernelProgrammed": true,
                  "directlyConnected": false,
                  "preference": 200,
                  "metric": 0,
                  "vias": [
                    {"nexthopAddr": "172.16.1.1", "interface": "Ethernet1"}
                  ]
                }
              }
            }
          }
        }
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            routes = data.get("vrfs", {}).get("default", {}).get("routes", {})
            if not routes:
                return None

            # EOS may return the exact prefix or a covering route
            # Try exact match first, then any route present
            route_data = routes.get(target_prefix)
            if route_data is None:
                # Take the first (and usually only) route returned
                if routes:
                    prefix_key = next(iter(routes))
                    route_data = routes[prefix_key]
                    target_prefix = prefix_key
                else:
                    return None

            prefix = _make_prefix(target_prefix)
            if prefix is None:
                return None

            # Classify route type
            route_type = route_data.get("routeType", "")
            directly_connected = route_data.get("directlyConnected", False)

            if directly_connected:
                protocol = RouteProtocol.CONNECTED
            else:
                protocol = _classify_protocol(route_type)

            # Build next-hops from vias
            next_hops = []
            for via in route_data.get("vias", []):
                nh_addr = _safe_ip(via.get("nexthopAddr", ""))
                nh_intf = via.get("interface")
                next_hops.append(RouteNextHop(
                    address=nh_addr,
                    interface=nh_intf,
                ))

            return RouteEntry(
                prefix=prefix,
                protocol=protocol,
                next_hops=next_hops,
            )

        except (KeyError, TypeError, StopIteration) as e:
            logger.debug(f"EOS route parse error: {e}")
            return None

    @staticmethod
    def parse_fib(raw: str, target_prefix: str) -> Optional[FibEntry]:
        """
        Parse: show ip route {prefix} detail | json

        EOS doesn't have a separate CEF/FIB command — the route detail
        includes FIB programming state via 'kernelProgrammed' and
        'hardwareProgrammed' flags.
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            routes = data.get("vrfs", {}).get("default", {}).get("routes", {})
            if not routes:
                return None

            route_data = routes.get(target_prefix)
            if route_data is None and routes:
                prefix_key = next(iter(routes))
                route_data = routes[prefix_key]
                target_prefix = prefix_key

            if route_data is None:
                return None

            prefix = _make_prefix(target_prefix)
            if prefix is None:
                return None

            # FIB state from programming flags
            kernel = route_data.get("kernelProgrammed", False)
            hardware = route_data.get("hardwareProgrammed", True)  # default True on SW platforms

            if route_data.get("routeAction") == "drop":
                state = FibState.DROP
            elif kernel or hardware:
                state = FibState.PROGRAMMED
            else:
                state = FibState.NOT_PROGRAMMED

            # Connected routes use GLEAN for the subnet
            if route_data.get("directlyConnected", False):
                state = FibState.GLEAN

            # Build FIB next-hops
            fib_nhs = []
            for via in route_data.get("vias", []):
                fib_nhs.append(FibNextHop(
                    address=_safe_ip(via.get("nexthopAddr", "")),
                    interface=via.get("interface"),
                ))

            return FibEntry(
                prefix=prefix,
                state=state,
                next_hops=fib_nhs,
                resolved=state == FibState.PROGRAMMED and len(fib_nhs) > 0,
            )

        except (KeyError, TypeError, StopIteration) as e:
            logger.debug(f"EOS FIB parse error: {e}")
            return None

    @staticmethod
    def parse_arp(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """
        Parse: show ip arp {next_hop} | json

        {
          "ipV4Neighbors": [
            {
              "hwAddress": "00:1a:2b:3c:4d:5e",
              "address": "172.16.1.1",
              "interface": "Ethernet1",
              "age": 123
            }
          ]
        }
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            neighbors = data.get("ipV4Neighbors", [])
            if not neighbors:
                return None

            entry = neighbors[0]
            ip_addr = _safe_ip(entry.get("address", ""))
            hw_addr = entry.get("hwAddress", "")
            normalized = _normalize_mac(hw_addr)

            # Determine state
            if not hw_addr or hw_addr == "00:00:00:00:00:00":
                state = ArpState.INCOMPLETE
                mac = None
            else:
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None

            age_secs = entry.get("age")
            age = timedelta(seconds=age_secs) if age_secs is not None else None

            return ArpEntry(
                ip_address=ip_addr,
                mac=mac,
                state=state,
                age=age,
                interface=entry.get("interface"),
            )

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"EOS ARP parse error: {e}")
            return None

    @staticmethod
    def parse_interface(raw: str) -> Optional[Interface]:
        """
        Parse: show interfaces {intf} | json

        {
          "interfaces": {
            "Ethernet1": {
              "name": "Ethernet1",
              "lineProtocolStatus": "up",
              "interfaceStatus": "connected",
              "mtu": 1500,
              "bandwidth": 1000000000,
              "description": "",
              "interfaceCounters": {
                "totalInErrors": 0,
                "totalOutErrors": 0,
                "inDiscards": 0,
                "outDiscards": 0,
                "inputErrorsDetail": {"runtFrames": 0, "fcsErrors": 0, ...}
              }
            }
          }
        }
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            interfaces = data.get("interfaces", {})
            if not interfaces:
                return None

            intf_name = next(iter(interfaces))
            intf_data = interfaces[intf_name]

            # State mapping
            line_proto = intf_data.get("lineProtocolStatus", "").lower()
            intf_status = intf_data.get("interfaceStatus", "").lower()

            if "admin" in intf_status and "down" in intf_status:
                state = InterfaceState.ADMIN_DOWN
            elif line_proto == "up":
                state = InterfaceState.UP_UP
            elif intf_status in ("connected",) and line_proto in ("up",):
                state = InterfaceState.UP_UP
            elif "down" in line_proto:
                if "up" in intf_status or "connected" in intf_status:
                    state = InterfaceState.UP_DOWN
                else:
                    state = InterfaceState.DOWN_DOWN
            else:
                state = InterfaceState.UNKNOWN

            # Counters
            counters_data = intf_data.get("interfaceCounters", {})
            error_detail = counters_data.get("inputErrorsDetail", {})
            counters = InterfaceCounters(
                in_errors=counters_data.get("totalInErrors", 0),
                out_errors=counters_data.get("totalOutErrors", 0),
                in_discards=counters_data.get("inDiscards", 0),
                out_discards=counters_data.get("outDiscards", 0),
                crc_errors=error_detail.get("fcsErrors", 0),
            )

            # Speed — EOS reports in bps
            bw = intf_data.get("bandwidth", 0)
            speed_mbps = bw // 1_000_000 if bw else None

            return Interface(
                name=intf_name,
                state=state,
                speed_mbps=speed_mbps,
                mtu=intf_data.get("mtu"),
                description=intf_data.get("description") or None,
                counters=counters,
            )

        except (KeyError, TypeError, StopIteration) as e:
            logger.debug(f"EOS interface parse error: {e}")
            return None

    @staticmethod
    def parse_mac_table(raw: str) -> Optional[MacTableEntry]:
        """Parse: show mac address-table address {mac} | json"""
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            entries = data.get("unicastTable", {}).get("tableEntries", [])
            if not entries:
                return None

            entry = entries[0]
            mac_str = _normalize_mac(entry.get("macAddress", ""))
            if not mac_str:
                return None

            return MacTableEntry(
                mac=MacAddress(address=mac_str),
                vlan=entry.get("vlanId"),
                interface=entry.get("interface", ""),
                entry_type=entry.get("entryType", "dynamic"),
            )

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"EOS MAC table parse error: {e}")
            return None

    @staticmethod
    def parse_nd(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """
        Parse: show ipv6 neighbors {next_hop} | json

        Real output from EOS:
        {
          "ipV6Neighbors": [
            {
              "address": "fe80::205:86ff:fe71:5b01",
              "age": 2422,
              "hwAddress": "0005.8671.5b01",
              "interface": "Et1"
            }
          ]
        }

        Note: EOS uses dotted-quad MAC format (0005.8671.5b01).
        _normalize_mac handles the conversion.
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            neighbors = data.get("ipV6Neighbors", [])
            if not neighbors:
                return None

            # Find matching entry or take first
            entry = None
            if target_ip:
                for n in neighbors:
                    if n.get("address", "") == target_ip:
                        entry = n
                        break
            if entry is None:
                if target_ip and neighbors:
                    # Target not found — incomplete
                    return ArpEntry(
                        ip_address=_safe_ip(target_ip),
                        state=ArpState.INCOMPLETE,
                    )
                entry = neighbors[0] if neighbors else None
            if entry is None:
                return None

            ip_addr = _safe_ip(entry.get("address", ""))
            hw_addr = entry.get("hwAddress", "")
            normalized = _normalize_mac(hw_addr)

            if not hw_addr or hw_addr == "00:00:00:00:00:00":
                state = ArpState.INCOMPLETE
                mac = None
            else:
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None

            age_secs = entry.get("age")
            age = timedelta(seconds=age_secs) if age_secs is not None else None

            return ArpEntry(
                ip_address=ip_addr,
                mac=mac,
                state=state,
                age=age,
                interface=entry.get("interface"),
            )

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"EOS ND parse error: {e}")
            return None

    @staticmethod
    def search_arp_by_mac(raw: str, target_mac: str) -> Optional[ArpEntry]:
        """
        Search full ARP table for an entry matching this MAC address.

        Uses 'show ip arp | json' output (ipV4Neighbors list).
        Searches by hwAddress instead of by IP — the cross-AF resolver.
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            neighbors = data.get("ipV4Neighbors", [])
            if not neighbors:
                return None

            normalized_target = _normalize_mac(target_mac)
            if not normalized_target:
                return None

            for entry in neighbors:
                hw_addr = entry.get("hwAddress", "")
                if _normalize_mac(hw_addr) == normalized_target:
                    ip_addr = _safe_ip(entry.get("address", ""))
                    return ArpEntry(
                        ip_address=ip_addr,
                        mac=MacAddress(address=normalized_target),
                        state=ArpState.RESOLVED,
                        interface=entry.get("interface"),
                    )

            return None  # MAC not found in ARP table

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"EOS ARP-by-MAC search error: {e}")
            return None


# ============================================================
# Cisco NX-OS — Native JSON Parsers
# ============================================================
# NX-OS JSON is... functional. Nested TABLE_*/ROW_* structure
# where ROW_* can be a dict (single entry) or list (multiple).
# Handle both.

class NXOSParser:
    """Parse Cisco NX-OS JSON command output into model dataclasses."""

    @staticmethod
    def _ensure_list(val: Any) -> list:
        """NX-OS returns dict for single entries, list for multiple."""
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            return [val]
        return []

    @staticmethod
    def parse_route(raw: str, target_prefix: str) -> Optional[RouteEntry]:
        """
        Parse: show ip route {prefix} | json

        NX-OS JSON structure (TABLE_/ROW_ pattern):
        {
          "TABLE_vrf": {"ROW_vrf": {
            "TABLE_addrf": {"ROW_addrf": {
              "TABLE_prefix": {"ROW_prefix": {
                "ipprefix": "10.0.0.0/24",
                "ucast-nhops": "1",
                "TABLE_path": {"ROW_path": {
                  "ipnexthop": "172.16.1.1",
                  "ifname": "Eth1/1",
                  "clientname": "ospf-1",
                  "attached": "false"
                }}
              }}
            }}
          }}
        }
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            vrf = data.get("TABLE_vrf", {}).get("ROW_vrf", {})
            addrf = vrf.get("TABLE_addrf", {}).get("ROW_addrf", {})
            prefix_table = addrf.get("TABLE_prefix", {}).get("ROW_prefix", {})

            rows = NXOSParser._ensure_list(prefix_table)
            if not rows:
                return None

            row = rows[0]
            prefix_str = row.get("ipprefix", target_prefix)
            prefix = _make_prefix(prefix_str)
            if prefix is None:
                return None

            # Protocol from clientname
            client = row.get("clientname", "")
            attached = str(row.get("attached", "false")).lower() == "true"

            if attached:
                protocol = RouteProtocol.CONNECTED
            else:
                protocol = _classify_protocol(client)

            # Next-hops
            paths = NXOSParser._ensure_list(
                row.get("TABLE_path", {}).get("ROW_path", {})
            )
            next_hops = []
            for path in paths:
                next_hops.append(RouteNextHop(
                    address=_safe_ip(path.get("ipnexthop", "")),
                    interface=path.get("ifname"),
                ))

            return RouteEntry(
                prefix=prefix,
                protocol=protocol,
                next_hops=next_hops,
            )

        except (KeyError, TypeError) as e:
            logger.debug(f"NXOS route parse error: {e}")
            return None

    @staticmethod
    def parse_fib(raw: str, target_prefix: str) -> Optional[FibEntry]:
        """
        Parse: show forwarding route {prefix} | json

        NX-OS forwarding table output.
        """
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            # NX-OS forwarding table structure varies by version
            # Common keys: TABLE_module/ROW_module → TABLE_prefix/ROW_prefix
            table = data
            # Try to dig through the nesting
            for key in ("TABLE_module", "TABLE_prefix"):
                if key in table:
                    row_key = key.replace("TABLE_", "ROW_")
                    table = table.get(key, {}).get(row_key, {})

            rows = NXOSParser._ensure_list(table)

            # Look for our prefix
            for row in rows:
                pfx_str = row.get("ip_prefix", row.get("ipprefix", ""))
                if pfx_str:
                    prefix = _make_prefix(pfx_str)
                    break
            else:
                prefix = _make_prefix(target_prefix)

            if prefix is None:
                return None

            # Determine state
            # NX-OS forwarding table entries that exist are programmed
            state = FibState.PROGRAMMED if rows else FibState.NOT_PROGRAMMED

            fib_nhs = []
            for row in rows:
                nh_addr = row.get("next_hop", row.get("ipnexthop", ""))
                nh_intf = row.get("ifname", row.get("interface", ""))
                if nh_addr or nh_intf:
                    fib_nhs.append(FibNextHop(
                        address=_safe_ip(nh_addr),
                        interface=nh_intf or None,
                    ))

            return FibEntry(
                prefix=prefix,
                state=state,
                next_hops=fib_nhs,
                resolved=state == FibState.PROGRAMMED and len(fib_nhs) > 0,
            )

        except (KeyError, TypeError) as e:
            logger.debug(f"NXOS FIB parse error: {e}")
            return None

    @staticmethod
    def parse_arp(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """Parse: show ip arp {next_hop} | json"""
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            rows = NXOSParser._ensure_list(
                data.get("TABLE_vrf", {}).get("ROW_vrf", {})
                .get("TABLE_adj", {}).get("ROW_adj", {})
            )
            if not rows:
                return None

            entry = rows[0]
            ip_addr = _safe_ip(entry.get("ip-addr-out", ""))
            hw_addr = entry.get("mac", "")
            normalized = _normalize_mac(hw_addr)

            incomplete = "incomplete" in str(entry.get("incomplete", "")).lower()

            if incomplete or not hw_addr:
                state = ArpState.INCOMPLETE
                mac = None
            else:
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None

            return ArpEntry(
                ip_address=ip_addr,
                mac=mac,
                state=state,
                interface=entry.get("intf-out"),
            )

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"NXOS ARP parse error: {e}")
            return None

    @staticmethod
    def parse_interface(raw: str) -> Optional[Interface]:
        """Parse: show interface {interface} | json"""
        data = _safe_json(raw)
        if data is None:
            return None

        try:
            rows = NXOSParser._ensure_list(
                data.get("TABLE_interface", {}).get("ROW_interface", {})
            )
            if not rows:
                return None

            intf = rows[0]
            name = intf.get("interface", "")

            # State
            admin = intf.get("admin_state", "").lower()
            oper = intf.get("state", "").lower()

            if admin == "down":
                state = InterfaceState.ADMIN_DOWN
            elif oper == "up":
                state = InterfaceState.UP_UP
            elif admin == "up" and oper == "down":
                state = InterfaceState.UP_DOWN
            else:
                state = InterfaceState.DOWN_DOWN

            counters = InterfaceCounters(
                in_errors=int(intf.get("eth_inerr", 0)),
                out_errors=int(intf.get("eth_outerr", 0)),
                in_discards=int(intf.get("eth_indiscard", 0)),
                out_discards=int(intf.get("eth_outdiscard", 0)),
                crc_errors=int(intf.get("eth_crc", 0)),
            )

            speed = intf.get("eth_speed", "")
            speed_mbps = None
            if speed:
                # "1000 Mb/s" or similar
                m = re.search(r'(\d+)', str(speed))
                if m:
                    speed_mbps = int(m.group(1))

            return Interface(
                name=name,
                state=state,
                speed_mbps=speed_mbps,
                mtu=int(intf.get("eth_mtu", 0)) or None,
                description=intf.get("desc") or None,
                counters=counters,
            )

        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"NXOS interface parse error: {e}")
            return None


# ============================================================
# Juniper Junos — XML Parsers
# ============================================================
# XML (| display xml) is the native structured output on Junos.
# Available on ALL versions — 14.1 through current.
# JSON (| display json) wasn't added until 14.2 and was unreliable
# until 17.x. XML is what NETCONF uses under the hood.
#
# Namespace handling: Junos XML includes versioned xmlns attributes
# that change with every release. We strip them all and work with
# bare element names. This is deliberate — we're parsing CLI output,
# not building a NETCONF client.

import xml.etree.ElementTree as ET


def _strip_ns(xml_str: str) -> str:
    """
    Strip XML namespace declarations and prefixes from Junos output.

    Junos wraps everything in versioned namespaces like:
      xmlns="http://xml.juniper.net/junos/14.1R1/junos-routing"
      xmlns:junos="http://xml.juniper.net/junos/14.1R1/junos"

    These change every version. Stripping them gives us stable element
    names to parse against. Also handles the junos: attribute prefix.
    """
    # Remove default namespace declarations
    xml_str = re.sub(r'\s+xmlns\s*=\s*"[^"]*"', '', xml_str)
    # Remove prefixed namespace declarations
    xml_str = re.sub(r'\s+xmlns:\w+\s*=\s*"[^"]*"', '', xml_str)
    # Remove namespace prefixes on attributes (junos:style="brief" → style="brief")
    xml_str = re.sub(r'(\s)\w+:(\w+)=', r'\1\2=', xml_str)
    return xml_str


def _safe_xml(raw: str) -> Optional[ET.Element]:
    """
    Parse XML from Junos CLI output.

    Handles:
    - Leading command echo / prompt before <?xml or <rpc-reply
    - Trailing prompt after </rpc-reply>
    - Namespace stripping
    """
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # Find the start of XML — either <?xml or <rpc-reply
    xml_start = -1
    for marker in ('<?xml', '<rpc-reply'):
        idx = text.find(marker)
        if idx >= 0:
            if xml_start < 0 or idx < xml_start:
                xml_start = idx

    if xml_start < 0:
        return None

    # Find the end — </rpc-reply>
    xml_end = text.rfind('</rpc-reply>')
    if xml_end < 0:
        return None
    xml_end += len('</rpc-reply>')

    text = text[xml_start:xml_end]

    # Strip namespaces
    text = _strip_ns(text)

    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        logger.debug(f"Junos XML parse error: {e}")
        return None


def _xml_text(element: Optional[ET.Element], tag: str, default: str = "") -> str:
    """Get text content of a child element, or default."""
    if element is None:
        return default
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _xml_find_all(element: Optional[ET.Element], path: str) -> list[ET.Element]:
    """Find all matching elements, returning empty list on None."""
    if element is None:
        return []
    return element.findall(path)


class JunosParser:
    """
    Parse Juniper Junos XML command output into model dataclasses.

    Uses | display xml which works on ALL Junos versions (14.1+).
    Namespace-stripped for version-independent parsing.
    """

    @staticmethod
    def parse_route(raw: str, target_prefix: str) -> Optional[RouteEntry]:
        """
        Parse: show route {prefix} active-path | display xml

        <rpc-reply>
          <route-information>
            <route-table>
              <table-name>inet.0</table-name>
              <rt>
                <rt-destination>172.17.1.28/31</rt-destination>
                <rt-entry>
                  <active-tag>*</active-tag>
                  <protocol-name>OSPF</protocol-name>
                  <nh>
                    <to>172.17.1.23</to>
                    <via>ge-0/0/0.0</via>
                  </nh>
                  <nh>
                    <to>172.17.1.25</to>
                    <via>ge-0/0/1.0</via>
                  </nh>
                </rt-entry>
              </rt>
            </route-table>
          </route-information>
        </rpc-reply>
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            # Navigate: rpc-reply → route-information → route-table → rt
            route_info = root.find('.//route-information')
            if route_info is None:
                return None

            route_table = route_info.find('route-table')
            if route_table is None:
                return None

            rt = route_table.find('rt')
            if rt is None:
                return None

            # Prefix
            dest = _xml_text(rt, 'rt-destination') or target_prefix
            prefix = _make_prefix(dest)
            if prefix is None:
                return None

            # Protocol from rt-entry
            rt_entry = rt.find('rt-entry')
            if rt_entry is None:
                return None

            proto_name = _xml_text(rt_entry, 'protocol-name')
            protocol = _classify_protocol(proto_name)

            # Check for Direct/Local (connected)
            if proto_name.lower() in ('direct', 'local'):
                protocol = RouteProtocol.CONNECTED

            # Next-hops — multiple <nh> elements under rt-entry
            next_hops = []
            for nh in _xml_find_all(rt_entry, 'nh'):
                nh_addr = _xml_text(nh, 'to')
                nh_intf = _xml_text(nh, 'via')
                next_hops.append(RouteNextHop(
                    address=_safe_ip(nh_addr),
                    interface=nh_intf or None,
                ))

            return RouteEntry(
                prefix=prefix,
                protocol=protocol,
                next_hops=next_hops,
            )

        except Exception as e:
            logger.debug(f"Junos route parse error: {e}")
            return None

    @staticmethod
    def parse_fib(raw: str, target_prefix: str) -> Optional[FibEntry]:
        """
        Parse: show route forwarding-table destination {prefix} | display xml

        <rpc-reply>
          <forwarding-table-information>
            <route-table>
              <table-name>default</table-name>
              <address-family>Internet</address-family>
              <rt-entry>
                <rt-destination>172.17.1.28/31</rt-destination>
                <nh>
                  <nh-type>unicast</nh-type>
                  <to>172.17.1.23</to>
                  <via>ge-0/0/0.0</via>
                </nh>
              </rt-entry>
            </route-table>
          </forwarding-table-information>
        </rpc-reply>
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            ft_info = root.find('.//forwarding-table-information')
            if ft_info is None:
                return None

            route_table = ft_info.find('route-table')
            if route_table is None:
                return None

            rt_entry = route_table.find('rt-entry')
            if rt_entry is None:
                return None

            dest = _xml_text(rt_entry, 'rt-destination') or target_prefix
            prefix = _make_prefix(dest)
            if prefix is None:
                return None

            # Build next-hops and determine state
            fib_nhs = []
            state = FibState.PROGRAMMED

            for nh in _xml_find_all(rt_entry, 'nh'):
                nh_type = _xml_text(nh, 'nh-type').lower()

                if 'discard' in nh_type or 'reject' in nh_type:
                    state = FibState.DROP
                elif 'receive' in nh_type or 'local' in nh_type:
                    state = FibState.RECEIVE
                elif 'hold' in nh_type:
                    state = FibState.NOT_PROGRAMMED
                else:
                    to_addr = _xml_text(nh, 'to')
                    via_intf = _xml_text(nh, 'via')
                    if to_addr or via_intf:
                        fib_nhs.append(FibNextHop(
                            address=_safe_ip(to_addr),
                            interface=via_intf or None,
                        ))

            return FibEntry(
                prefix=prefix,
                state=state,
                next_hops=fib_nhs,
                resolved=state == FibState.PROGRAMMED and len(fib_nhs) > 0,
            )

        except Exception as e:
            logger.debug(f"Junos FIB parse error: {e}")
            return None

    @staticmethod
    def parse_arp(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """
        Parse: show arp no-resolve | display xml

        Junos doesn't filter ARP by IP on the CLI — 'show arp no-resolve'
        dumps the full table. We parse all entries and match by target_ip.

        <rpc-reply>
          <arp-table-information>
            <arp-table-entry>
              <mac-address>00:1a:2b:3c:4d:5e</mac-address>
              <ip-address>172.17.1.23</ip-address>
              <interface-name>ge-0/0/0.0</interface-name>
            </arp-table-entry>
            <arp-table-entry>
              ...more entries...
            </arp-table-entry>
          </arp-table-information>
        </rpc-reply>
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            arp_info = root.find('.//arp-table-information')
            if arp_info is None:
                return None

            entries = _xml_find_all(arp_info, 'arp-table-entry')
            if not entries:
                return None

            # Find the entry matching target_ip, or take first if no filter
            matched = None
            for entry in entries:
                ip_str = _xml_text(entry, 'ip-address')
                if target_ip and ip_str == target_ip:
                    matched = entry
                    break

            if matched is None:
                if target_ip:
                    # Target IP not in ARP table → incomplete
                    return ArpEntry(
                        ip_address=_safe_ip(target_ip),
                        state=ArpState.INCOMPLETE,
                    )
                # No filter, take first
                matched = entries[0]

            ip_str = _xml_text(matched, 'ip-address')
            mac_str = _xml_text(matched, 'mac-address')
            intf = _xml_text(matched, 'interface-name')

            normalized = _normalize_mac(mac_str)

            if not mac_str or mac_str.lower() in ('incomplete', 'none'):
                state = ArpState.INCOMPLETE
                mac = None
            else:
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None

            return ArpEntry(
                ip_address=_safe_ip(ip_str),
                mac=mac,
                state=state,
                interface=intf or None,
            )

        except Exception as e:
            logger.debug(f"Junos ARP parse error: {e}")
            return None

    @staticmethod
    def parse_interface(raw: str) -> Optional[Interface]:
        """
        Parse: show interfaces {interface} | display xml

        <rpc-reply>
          <interface-information>
            <physical-interface>
              <name>ge-0/0/0</name>
              <admin-status>up</admin-status>
              <oper-status>up</oper-status>
              <speed>1000mbps</speed>
              <mtu>1514</mtu>
              <input-error-list>
                <input-errors>0</input-errors>
                <input-drops>0</input-drops>
                <framing-errors>0</framing-errors>
              </input-error-list>
              <output-error-list>
                <output-errors>0</output-errors>
                <output-drops>0</output-drops>
              </output-error-list>
            </physical-interface>
          </interface-information>
        </rpc-reply>
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            intf_info = root.find('.//interface-information')
            if intf_info is None:
                return None

            # Could be physical-interface or logical-interface
            intf = intf_info.find('physical-interface')
            if intf is None:
                intf = intf_info.find('logical-interface')
            if intf is None:
                return None

            name = _xml_text(intf, 'name')
            admin = _xml_text(intf, 'admin-status').lower()
            oper = _xml_text(intf, 'oper-status').lower()

            if admin and oper:
                # Physical interface — has explicit status elements
                if admin == 'down':
                    state = InterfaceState.ADMIN_DOWN
                elif oper == 'up' and admin == 'up':
                    state = InterfaceState.UP_UP
                elif admin == 'up' and oper == 'down':
                    state = InterfaceState.UP_DOWN
                else:
                    state = InterfaceState.DOWN_DOWN
            else:
                # Logical interface (ge-0/0/0.0) — no admin-status/oper-status.
                # State is in if-config-flags: <iff-up/> means up,
                # <iff-down/> means admin down. If iff-up is present,
                # the logical interface is operationally up.
                config_flags = intf.find('if-config-flags')
                if config_flags is not None and config_flags.find('iff-up') is not None:
                    state = InterfaceState.UP_UP
                elif config_flags is not None and config_flags.find('iff-down') is not None:
                    state = InterfaceState.ADMIN_DOWN
                else:
                    # No flags at all — can't determine, assume up if we got here
                    state = InterfaceState.UNKNOWN

            # Speed
            speed_str = _xml_text(intf, 'speed')
            speed_mbps = None
            if speed_str:
                m = re.search(r'(\d+)', speed_str)
                if m:
                    val = int(m.group(1))
                    # Junos reports "1000mbps" or "10Gbps"
                    if 'gbps' in speed_str.lower():
                        speed_mbps = val * 1000
                    else:
                        speed_mbps = val

            # MTU — top level on physical, inside address-family on logical
            mtu_str = _xml_text(intf, 'mtu')
            if not mtu_str:
                # Logical interface: check address-family (prefer inet)
                for af in _xml_find_all(intf, 'address-family'):
                    af_name = _xml_text(af, 'address-family-name')
                    af_mtu = _xml_text(af, 'mtu')
                    if af_mtu and af_mtu.lower() != 'unlimited':
                        mtu_str = af_mtu
                        if af_name == 'inet':
                            break  # prefer inet MTU
            mtu = None
            if mtu_str:
                m = re.search(r'(\d+)', mtu_str)
                if m:
                    mtu = int(m.group(1))

            # Description
            description = _xml_text(intf, 'description') or None

            # Counters — from input-error-list / output-error-list
            in_errors = 0
            out_errors = 0
            in_discards = 0
            out_discards = 0
            crc_errors = 0

            in_err_list = intf.find('input-error-list')
            if in_err_list is not None:
                in_errors = int(_xml_text(in_err_list, 'input-errors', '0'))
                in_discards = int(_xml_text(in_err_list, 'input-drops', '0'))
                crc_errors = int(_xml_text(in_err_list, 'framing-errors', '0'))

            out_err_list = intf.find('output-error-list')
            if out_err_list is not None:
                out_errors = int(_xml_text(out_err_list, 'output-errors', '0'))
                out_discards = int(_xml_text(out_err_list, 'output-drops', '0'))

            counters = InterfaceCounters(
                in_errors=in_errors,
                out_errors=out_errors,
                in_discards=in_discards,
                out_discards=out_discards,
                crc_errors=crc_errors,
            )

            return Interface(
                name=name,
                state=state,
                speed_mbps=speed_mbps,
                mtu=mtu,
                description=description,
                counters=counters,
            )

        except Exception as e:
            logger.debug(f"Junos interface parse error: {e}")
            return None

    @staticmethod
    def parse_nd(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """
        Parse: show ipv6 neighbors {next_hop} | display xml

        Real output from Junos 14.1:
        <rpc-reply>
          <ipv6-nd-information>
            <ipv6-nd-entry>
              <ipv6-nd-neighbor-address>fe80::ea6:5aff:fe8b:9033</ipv6-nd-neighbor-address>
              <ipv6-nd-neighbor-l2-address>0c:a6:5a:8b:90:33</ipv6-nd-neighbor-l2-address>
              <ipv6-nd-state>stale</ipv6-nd-state>
              <ipv6-nd-expire>685</ipv6-nd-expire>
              <ipv6-nd-isrouter>yes</ipv6-nd-isrouter>
              <ipv6-nd-issecure>no</ipv6-nd-issecure>
              <ipv6-nd-interface-name>ge-0/0/0.0</ipv6-nd-interface-name>
            </ipv6-nd-entry>
          </ipv6-nd-information>
        </rpc-reply>

        Returns ArpEntry (same model — MAC, state, interface all map directly).
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            nd_info = root.find('.//ipv6-nd-information')
            if nd_info is None:
                return None

            entries = _xml_find_all(nd_info, 'ipv6-nd-entry')
            if not entries:
                return None

            # Find entry matching target_ip, or take first if no filter
            matched = None
            for entry in entries:
                addr_str = _xml_text(entry, 'ipv6-nd-neighbor-address')
                if target_ip and addr_str == target_ip:
                    matched = entry
                    break

            if matched is None:
                if target_ip:
                    return ArpEntry(
                        ip_address=_safe_ip(target_ip),
                        state=ArpState.INCOMPLETE,
                    )
                matched = entries[0]

            addr_str = _xml_text(matched, 'ipv6-nd-neighbor-address')
            mac_str = _xml_text(matched, 'ipv6-nd-neighbor-l2-address')
            intf = _xml_text(matched, 'ipv6-nd-interface-name')
            nd_state = _xml_text(matched, 'ipv6-nd-state').lower()

            normalized = _normalize_mac(mac_str)

            if not mac_str or mac_str.lower() in ('incomplete', 'none'):
                state = ArpState.INCOMPLETE
                mac = None
            elif nd_state == 'stale':
                # Stale is resolved — MAC is valid, just not recently confirmed
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None
            elif nd_state in ('reachable', 'delay', 'probe'):
                state = ArpState.RESOLVED
                mac = MacAddress(address=normalized) if normalized else None
            else:
                state = ArpState.UNKNOWN
                mac = MacAddress(address=normalized) if normalized else None

            return ArpEntry(
                ip_address=_safe_ip(addr_str),
                mac=mac,
                state=state,
                interface=intf or None,
            )

        except Exception as e:
            logger.debug(f"Junos ND parse error: {e}")
            return None

    @staticmethod
    def search_arp_by_mac(raw: str, target_mac: str) -> Optional[ArpEntry]:
        """
        Search full ARP table for an entry matching this MAC address.

        Uses the same 'show arp no-resolve | display xml' output that
        parse_arp already handles — but searches by MAC instead of by IP.

        This is the cross-AF link-local resolver: ND gives us a MAC,
        we find the IPv4 address that owns that MAC in the ARP table.
        """
        root = _safe_xml(raw)
        if root is None:
            return None

        try:
            arp_info = root.find('.//arp-table-information')
            if arp_info is None:
                return None

            normalized_target = _normalize_mac(target_mac)
            if not normalized_target:
                return None

            for entry in _xml_find_all(arp_info, 'arp-table-entry'):
                mac_str = _xml_text(entry, 'mac-address')
                if _normalize_mac(mac_str) == normalized_target:
                    ip_str = _xml_text(entry, 'ip-address')
                    intf = _xml_text(entry, 'interface-name')
                    return ArpEntry(
                        ip_address=_safe_ip(ip_str),
                        mac=MacAddress(address=normalized_target),
                        state=ArpState.RESOLVED,
                        interface=intf or None,
                    )

            return None  # MAC not found in ARP table

        except Exception as e:
            logger.debug(f"Junos ARP-by-MAC search error: {e}")
            return None


# ============================================================
# Cisco IOS/IOS-XE — Regex Parsers
# ============================================================
# The hard case. No JSON, variable formatting across versions.
# These patterns are conservative — better to return None than
# parse wrong data. TextFSM is the future upgrade path here.

class CiscoIOSParser:
    """Parse Cisco IOS/IOS-XE CLI output via regex into model dataclasses."""

    @staticmethod
    def parse_route(raw: str, target_prefix: str) -> Optional[RouteEntry]:
        """
        Parse: show ip route {prefix}

        Sample output:
        Routing entry for 10.0.0.0/24
          Known via "ospf 1", distance 110, metric 20, type intra area
          Last update from 172.16.1.1 on GigabitEthernet0/1, 00:05:32 ago
          Routing Descriptor Blocks:
          * 172.16.1.1, from 172.16.1.1, 00:05:32 ago, via GigabitEthernet0/1
              Route metric is 20, traffic share count is 1
            172.16.2.1, from 172.16.2.1, 00:05:32 ago, via GigabitEthernet0/2
              Route metric is 20, traffic share count is 1

        Or for connected:
        Routing entry for 192.168.1.0/24
          Known via "connected", distance 0, metric 0 (connected, via interface)
        """
        if not raw or not raw.strip():
            return None

        # Check for "not in table" or similar
        if re.search(r"not in table|% Network not in table", raw, re.IGNORECASE):
            return None

        try:
            # Extract prefix
            m = re.search(r"Routing entry for (\S+)", raw)
            if not m:
                return None
            prefix = _make_prefix(m.group(1))
            if prefix is None:
                return None

            # Extract protocol
            m = re.search(r'Known via "([^"]+)"', raw)
            proto_str = m.group(1) if m else ""
            protocol = _classify_protocol(proto_str.split()[0] if proto_str else "")

            # Connected check
            if "connected" in proto_str.lower():
                protocol = RouteProtocol.CONNECTED

            # Extract next-hops from Routing Descriptor Blocks
            next_hops = []
            # Pattern: * 172.16.1.1, from ..., via GigabitEthernet0/1
            # or:        172.16.1.1, from ..., via GigabitEthernet0/1
            for m in re.finditer(
                r'(?:\*\s+)?([\d\.]+),\s+from\s+[\d\.]+,.*?via\s+(\S+)', raw
            ):
                next_hops.append(RouteNextHop(
                    address=_safe_ip(m.group(1)),
                    interface=m.group(2).rstrip(','),
                ))

            # Connected routes: "directly connected, via GigabitEthernet0/1"
            if not next_hops and protocol == RouteProtocol.CONNECTED:
                m = re.search(r'directly connected,?\s*via\s+(\S+)', raw, re.IGNORECASE)
                if m:
                    next_hops.append(RouteNextHop(
                        address=None,
                        interface=m.group(1),
                    ))

            return RouteEntry(
                prefix=prefix,
                protocol=protocol,
                next_hops=next_hops,
            )

        except Exception as e:
            logger.debug(f"IOS route parse error: {e}")
            return None

    @staticmethod
    def parse_fib(raw: str, target_prefix: str) -> Optional[FibEntry]:
        """
        Parse: show ip cef {prefix} detail

        Sample output:
        10.0.0.0/24
          nexthop 172.16.1.1 GigabitEthernet0/1

        Or:
        10.0.0.0/24
          attached to GigabitEthernet0/1

        Or:
        0.0.0.0/0
          no route

        Or:
        10.0.0.0/24
          drop
        """
        if not raw or not raw.strip():
            return None

        try:
            # Prefix on first meaningful line
            m = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', raw)
            if not m:
                return None
            prefix = _make_prefix(m.group(1))
            if prefix is None:
                return None

            # Check for drop
            if re.search(r'^\s*drop', raw, re.MULTILINE):
                return FibEntry(prefix=prefix, state=FibState.DROP, resolved=False)

            # Check for receive
            if re.search(r'^\s*receive', raw, re.MULTILINE):
                return FibEntry(prefix=prefix, state=FibState.RECEIVE, resolved=True)

            # Check for "no route"
            if re.search(r'no route', raw, re.IGNORECASE):
                return FibEntry(prefix=prefix, state=FibState.NOT_PROGRAMMED, resolved=False)

            # Check for "attached"
            m = re.search(r'attached to (\S+)', raw)
            if m:
                return FibEntry(
                    prefix=prefix,
                    state=FibState.GLEAN,
                    next_hops=[FibNextHop(interface=m.group(1))],
                    resolved=True,
                )

            # Extract nexthop entries
            fib_nhs = []
            for m in re.finditer(r'nexthop\s+([\d\.]+)\s+(\S+)', raw):
                fib_nhs.append(FibNextHop(
                    address=_safe_ip(m.group(1)),
                    interface=m.group(2),
                ))

            if fib_nhs:
                return FibEntry(
                    prefix=prefix,
                    state=FibState.PROGRAMMED,
                    next_hops=fib_nhs,
                    resolved=True,
                )

            # Got a prefix line but couldn't parse the action
            return FibEntry(prefix=prefix, state=FibState.UNKNOWN, resolved=False)

        except Exception as e:
            logger.debug(f"IOS FIB parse error: {e}")
            return None

    @staticmethod
    def parse_arp(raw: str, target_ip: str = "") -> Optional[ArpEntry]:
        """
        Parse: show ip arp {next_hop}

        Sample:
        Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        Internet  172.16.1.1             12   001a.2b3c.4d5e  ARPA   GigabitEthernet0/1

        Or incomplete:
        Internet  172.16.1.1              -   Incomplete      ARPA
        """
        if not raw or not raw.strip():
            return None

        try:
            # Check for incomplete first
            m = re.search(
                r'Internet\s+([\d\.]+)\s+.*Incomplete', raw, re.IGNORECASE
            )
            if m:
                return ArpEntry(
                    ip_address=_safe_ip(m.group(1)),
                    state=ArpState.INCOMPLETE,
                )

            # Normal entry
            m = re.search(
                r'Internet\s+([\d\.]+)\s+(\d+|-)\s+'
                r'([\da-fA-F\.]+)\s+ARPA\s+(\S+)',
                raw
            )
            if not m:
                return None

            ip_addr = _safe_ip(m.group(1))
            age_str = m.group(2)
            mac_str = _normalize_mac(m.group(3))
            intf = m.group(4)

            age = None
            if age_str != "-":
                try:
                    age = timedelta(minutes=int(age_str))
                except ValueError:
                    pass

            return ArpEntry(
                ip_address=ip_addr,
                mac=MacAddress(address=mac_str) if mac_str else None,
                state=ArpState.RESOLVED if mac_str else ArpState.INCOMPLETE,
                age=age,
                interface=intf,
            )

        except Exception as e:
            logger.debug(f"IOS ARP parse error: {e}")
            return None

    @staticmethod
    def parse_interface(raw: str) -> Optional[Interface]:
        """
        Parse: show interfaces {interface}

        Sample:
        GigabitEthernet0/1 is up, line protocol is up
          Hardware is iGbE, address is 001a.2b3c.4d5e (bia 001a.2b3c.4d5e)
          MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
          ...
             5 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored
             0 output errors, 0 collisions, 0 interface resets
        """
        if not raw or not raw.strip():
            return None

        try:
            # Interface state
            m = re.search(r'(\S+) is (\S+), line protocol is (\S+)', raw)
            if not m:
                return None

            name = m.group(1)
            admin_state = m.group(2).lower()
            line_state = m.group(3).lower()

            if "administratively" in admin_state or admin_state == "down":
                if "administratively" in raw.split('\n')[0].lower():
                    state = InterfaceState.ADMIN_DOWN
                elif admin_state == "up" and line_state == "up":
                    state = InterfaceState.UP_UP
                elif admin_state == "up":
                    state = InterfaceState.UP_DOWN
                else:
                    state = InterfaceState.DOWN_DOWN
            elif admin_state == "up" and line_state == "up":
                state = InterfaceState.UP_UP
            elif admin_state == "up" and line_state == "down":
                state = InterfaceState.UP_DOWN
            else:
                state = InterfaceState.DOWN_DOWN

            # MTU and BW
            mtu = None
            speed_mbps = None
            m = re.search(r'MTU (\d+) bytes', raw)
            if m:
                mtu = int(m.group(1))
            m = re.search(r'BW (\d+) Kbit', raw)
            if m:
                speed_mbps = int(m.group(1)) // 1000

            # Description
            description = None
            m = re.search(r'Description: (.+)', raw)
            if m:
                description = m.group(1).strip()

            # Counters
            in_errors = 0
            out_errors = 0
            crc_errors = 0
            in_discards = 0
            out_discards = 0

            m = re.search(r'(\d+) input errors,\s*(\d+) CRC', raw)
            if m:
                in_errors = int(m.group(1))
                crc_errors = int(m.group(2))

            m = re.search(r'(\d+) output errors', raw)
            if m:
                out_errors = int(m.group(1))

            m = re.search(r'(\d+) input .* ignored', raw)
            if m:
                in_discards = int(m.group(1))

            counters = InterfaceCounters(
                in_errors=in_errors,
                out_errors=out_errors,
                crc_errors=crc_errors,
                in_discards=in_discards,
                out_discards=out_discards,
            )

            return Interface(
                name=name,
                state=state,
                speed_mbps=speed_mbps,
                mtu=mtu,
                description=description,
                counters=counters,
            )

        except Exception as e:
            logger.debug(f"IOS interface parse error: {e}")
            return None


# ============================================================
# Parser Registry — dispatch by platform and data type
# ============================================================

# Data types that can be parsed
PARSE_ROUTE = "route"
PARSE_FIB = "fib"
PARSE_ARP = "arp"
PARSE_ND = "nd"                         # Neighbor Discovery (IPv6 ARP equivalent)
PARSE_ARP_BY_MAC = "arp_by_mac"         # Reverse ARP search by MAC (link-local resolver)
PARSE_INTERFACE = "interface"
PARSE_MAC_TABLE = "mac_table"

# Registry: (Platform, data_type) → parser callable
# Route and FIB parsers take (raw_output, target_prefix)
# ARP and interface parsers take (raw_output,)

_PARSER_REGISTRY: dict[tuple[Platform, str], callable] = {
    # Arista EOS
    (Platform.ARISTA_EOS, PARSE_ROUTE):       AristaEOSParser.parse_route,
    (Platform.ARISTA_EOS, PARSE_FIB):         AristaEOSParser.parse_fib,
    (Platform.ARISTA_EOS, PARSE_ARP):         AristaEOSParser.parse_arp,
    (Platform.ARISTA_EOS, PARSE_ND):          AristaEOSParser.parse_nd,
    (Platform.ARISTA_EOS, PARSE_ARP_BY_MAC):  AristaEOSParser.search_arp_by_mac,
    (Platform.ARISTA_EOS, PARSE_INTERFACE):   AristaEOSParser.parse_interface,
    (Platform.ARISTA_EOS, PARSE_MAC_TABLE):   AristaEOSParser.parse_mac_table,

    # Cisco NX-OS
    (Platform.CISCO_NXOS, PARSE_ROUTE):     NXOSParser.parse_route,
    (Platform.CISCO_NXOS, PARSE_FIB):       NXOSParser.parse_fib,
    (Platform.CISCO_NXOS, PARSE_ARP):       NXOSParser.parse_arp,
    (Platform.CISCO_NXOS, PARSE_INTERFACE): NXOSParser.parse_interface,

    # Juniper Junos
    (Platform.JUNIPER_JUNOS, PARSE_ROUTE):       JunosParser.parse_route,
    (Platform.JUNIPER_JUNOS, PARSE_FIB):         JunosParser.parse_fib,
    (Platform.JUNIPER_JUNOS, PARSE_ARP):         JunosParser.parse_arp,
    (Platform.JUNIPER_JUNOS, PARSE_ND):          JunosParser.parse_nd,
    (Platform.JUNIPER_JUNOS, PARSE_ARP_BY_MAC):  JunosParser.search_arp_by_mac,
    (Platform.JUNIPER_JUNOS, PARSE_INTERFACE):   JunosParser.parse_interface,

    # Cisco IOS
    (Platform.CISCO_IOS, PARSE_ROUTE):     CiscoIOSParser.parse_route,
    (Platform.CISCO_IOS, PARSE_FIB):       CiscoIOSParser.parse_fib,
    (Platform.CISCO_IOS, PARSE_ARP):       CiscoIOSParser.parse_arp,
    (Platform.CISCO_IOS, PARSE_INTERFACE): CiscoIOSParser.parse_interface,
}


def get_parser(platform: Platform, data_type: str) -> Optional[callable]:
    """
    Get the parser function for a platform and data type.

    Returns None if no parser is registered — caller should fall back
    or record a diagnostic.
    """
    return _PARSER_REGISTRY.get((platform, data_type))


def get_parser_name(platform: Platform, data_type: str) -> str:
    """Human-readable parser name for diagnostics."""
    if platform in (Platform.ARISTA_EOS, Platform.CISCO_NXOS):
        return "json"
    if platform == Platform.JUNIPER_JUNOS:
        return "xml"
    if platform == Platform.CISCO_IOS:
        return "regex"
    return "unknown"