"""
Forwarding Chain Walker — BFS tree traversal with hostname-based tracking.

Key change from v1: device identity comes from the CLI prompt, not the IP
we used to SSH in. Unnumbered interfaces, shared transits, and management
IPs that don't match the forwarding plane all make IP a poor unique identifier.
The hostname in the prompt IS the device identity.

Sequence per hop:
    1. SSH to IP from queue
    2. find_prompt() → extract_hostname_from_prompt()
    3. Check visited set (by hostname) — revisit?
    4. If new: fingerprint, gather, assess, enqueue next-hops
    5. If seen: classify as loop or convergence (see below)

Loop vs Convergence (ECMP diamond detection):
    Each queue item carries its ancestor set — the hostnames on the path
    from the source to this item. When we revisit a hostname:
      - If it's in the ancestor set → REAL LOOP (A→B→C→A)
      - If it's NOT in ancestors   → ECMP CONVERGENCE (normal)

    ECMP convergence (sibling paths reconverging) is expected in any
    multi-path network and is NOT flagged as an anomaly.

          source
          /    \\          ← ECMP: two different next-hop IPs
       spine1  spine2       unique hostnames, both visited
        /    \\   / \\
     leaf1  leaf2  leaf3
       \\       /
        spine1              ← ancestor! this IS a loop

          source
          /    \\
       agg-01  agg-02      ← ECMP fan-out
          \\    /
          edge-01           ← convergence, NOT a loop
"""

from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import (
    IPv4Address, IPv4Network, IPv6Address, IPv6Network,
    ip_address as _stdlib_ip_address, ip_network as _stdlib_ip_network,
    AddressValueError,
)
from typing import Optional
import logging
import socket
import sys
import time

from .models import (
    Prefix, AddressFamily, DeviceInfo, Hop, HopVerdict, ForwardingChain, ChainStatus,
    RouteEntry, RouteProtocol, FibEntry, FibState, FibNextHop,
    NextHopResolution, ArpEntry, ArpState, MacAddress, InterfaceState,
    Encapsulation, EncapType,
)
from .commands_and_parsers import (
    Platform, COMMAND_SETS, DISABLE_PAGING,
    fingerprint_from_prompt, fingerprint_from_show_version,
)
from .parsers import (
    get_parser, get_parser_name,
    PARSE_ROUTE, PARSE_FIB, PARSE_ARP, PARSE_ND, PARSE_ARP_BY_MAC,
    PARSE_INTERFACE, PARSE_MAC_TABLE,
)
from .diagnostics import (
    CommandRecord, CommandStatus, ParseResult, FingerprintRecord,
    VerdictRecord, HopDiagnostic, ChainDiagnostic,
    parse_with_diagnostics, setup_logging,
    dump_hop_summary, dump_hop_detail, dump_chain_summary,
)
from .client import SSHClient, SSHClientConfig
from .events import HopEvent, TuiVerdict, EventCallback

logger = logging.getLogger("chainwalk")


# ============================================================
# Neighbor Discovery (LLDP / CDP)
# ============================================================

@dataclass
class NeighborInfo:
    """Lightweight result from LLDP or CDP neighbor query."""
    system_name: Optional[str] = None
    management_address: Optional[str] = None
    port_id: Optional[str] = None
    source: str = "lldp"  # "lldp" or "cdp"


# Per-platform LLDP commands — keyed by egress interface (physical only)
_LLDP_COMMANDS: dict[Platform, str] = {
    Platform.CISCO_IOS: "show lldp neighbors {interface} detail",
    Platform.CISCO_NXOS: "show lldp neighbors interface {interface} detail",
    Platform.ARISTA_EOS: "show lldp neighbors {interface} detail",
    Platform.JUNIPER_JUNOS: "show lldp neighbors interface {interface}",
}

# LAG fallback — full LLDP table piped through filter for the LAG name.
# Used when the per-interface command returns nothing on an aggregate.
_LLDP_LAG_COMMANDS: dict[Platform, str] = {
    Platform.CISCO_IOS: "show lldp neighbors | include {lag}",
    Platform.CISCO_NXOS: "show lldp neighbors | include {lag}",
    Platform.ARISTA_EOS: "show lldp neighbors | include {lag}",
    Platform.JUNIPER_JUNOS: "show lldp neighbors | match {lag}",
}

# CDP fallback — Cisco-only
_CDP_COMMANDS: dict[Platform, str] = {
    Platform.CISCO_IOS: "show cdp neighbors {interface} detail",
    Platform.CISCO_NXOS: "show cdp neighbors interface {interface} detail",
}

_CDP_LAG_COMMANDS: dict[Platform, str] = {
    Platform.CISCO_IOS: "show cdp neighbors | include {lag}",
    Platform.CISCO_NXOS: "show cdp neighbors | include {lag}",
}

# Patterns that identify a LAG interface name
import re as _re
_LAG_PATTERN = _re.compile(
    r"^(ae|Port-[Cc]hannel|po|bond|Ethernet-Trunk)", _re.IGNORECASE
)


# ============================================================
# Dual-stack address helpers
# ============================================================

def _parse_ip(addr_str: str) -> IPv4Address | IPv6Address:
    """Parse an IPv4 or IPv6 address string. Raises ValueError on failure."""
    return _stdlib_ip_address(addr_str.strip())


def _parse_network(prefix_str: str) -> IPv4Network | IPv6Network:
    """Parse an IPv4 or IPv6 network string. Raises ValueError on failure."""
    return _stdlib_ip_network(prefix_str.strip(), strict=False)


# ============================================================
# Walker Configuration
# ============================================================

@dataclass
class WalkerConfig:
    target_prefix: str
    source_host: str

    # Credentials
    username: str = ""
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None

    # Walk behavior
    max_depth: int = 15
    command_timeout: float = 10.0
    ssh_timeout: int = 10
    inter_command_time: float = 0.5
    legacy_ssh: bool = False

    # Diagnostics
    log_file: Optional[str] = None
    verbose: bool = False
    debug: bool = False
    capture_raw: bool = True

    # SSH reuse
    keep_connections: bool = True

    # Error threshold — cumulative errors below this are flagged
    # but the verdict remains HEALTHY. Set to 0 to flag any errors.
    # Errors NEVER stop the trace — they're always informational.
    interface_error_threshold: int = 100

    # Skip MAC table lookups (faster, less noise on L3-only paths)
    skip_mac_lookup: bool = False

    # DNS domain suffix for neighbor hostname resolution
    # e.g., "kentik.com" → "edge03.iad1" becomes "edge03.iad1.kentik.com"
    dns_domain: Optional[str] = None

    # TUI event callback — if set, walker emits HopEvent at each stage
    event_callback: Optional[EventCallback] = None


# ============================================================
# BFS Queue Item
# ============================================================

@dataclass
class QueueItem:
    """A device to visit. IP is how we get there. Hostname is who it is."""
    ssh_target: str                         # IP or hostname to SSH into
    depth: int
    parent_hostname: Optional[str] = None   # who sent us here (by hostname)
    parent_interface: Optional[str] = None
    expected_hostname: Optional[str] = None  # hint from reverse DNS or prior knowledge
    ancestors: frozenset[str] = field(default_factory=frozenset)  # hostnames in path from root


# ============================================================
# Device Identity — resolved after connection
# ============================================================

@dataclass
class DeviceIdentity:
    """Established after SSH connect + prompt detection."""
    ssh_target: str             # IP we connected to
    prompt_raw: str             # full prompt string
    hostname: str               # extracted hostname — the canonical ID
    platform: Platform = Platform.UNKNOWN


# ============================================================
# Chain Walker
# ============================================================

class ChainWalker:
    """
    BFS walk of the forwarding chain for a given prefix.
    Tracks devices by hostname extracted from CLI prompt.

    Usage:
        config = WalkerConfig(
            target_prefix="10.0.0.0/24",
            source_host="172.16.1.1",
            username="admin",
            password="secret",
        )
        walker = ChainWalker(config)
        chain = walker.walk()

        # chain.status → COMPLETE, BROKEN, LOOP, PARTIAL
        # chain.is_healthy → all hops forwarding
        # walker.diagnostics.dump_json("/tmp/debug.json")
    """

    def __init__(self, config: WalkerConfig):
        self.config = config

        # Keyed by HOSTNAME, not IP
        self._visited: set[str] = set()
        self._connections: dict[str, SSHClient] = {}       # hostname → SSHClient
        self._identity_cache: dict[str, DeviceIdentity] = {}  # hostname → identity
        self._ip_to_hostname: dict[str, str] = {}       # IP → hostname (reverse map)

        self._chain: Optional[ForwardingChain] = None
        self._diagnostics: Optional[ChainDiagnostic] = None

    @property
    def diagnostics(self) -> Optional[ChainDiagnostic]:
        return self._diagnostics

    @property
    def chain(self) -> Optional[ForwardingChain]:
        return self._chain

    # ────────────────────────────────────────────
    # Progress Output
    # ────────────────────────────────────────────

    @staticmethod
    def _progress(msg: str, end: str = "\n"):
        """
        Unconditional progress to stderr. Not gated by --verbose or
        logger config — connection attempts and neighbor discovery are
        the slow parts and the user needs to know what's happening.
        """
        print(msg, file=sys.stderr, end=end, flush=True)

    # ────────────────────────────────────────────
    # TUI Event Emission
    # ────────────────────────────────────────────

    def _emit(self, event: HopEvent) -> None:
        """Send an event to the TUI callback, if registered."""
        cb = self.config.event_callback
        if cb is not None:
            try:
                cb(event)
            except Exception as e:
                logger.debug(f"Event callback error: {e}")

    @staticmethod
    def _verdict_to_tui(verdict: HopVerdict, is_connected: bool = False) -> TuiVerdict:
        """Map walker's HopVerdict to TUI's TuiVerdict."""
        if is_connected and verdict == HopVerdict.HEALTHY:
            return TuiVerdict.HEALTHY_CONNECTED
        mapping = {
            HopVerdict.HEALTHY: TuiVerdict.HEALTHY,
            HopVerdict.NO_ROUTE: TuiVerdict.NO_ROUTE,
            HopVerdict.BLACKHOLE: TuiVerdict.BLACKHOLE,
            HopVerdict.RIB_ONLY: TuiVerdict.RIB_ONLY,
            HopVerdict.INCOMPLETE_ARP: TuiVerdict.INCOMPLETE_ARP,
            HopVerdict.INTERFACE_DOWN: TuiVerdict.INTERFACE_DOWN,
            HopVerdict.INTERFACE_ERRORS: TuiVerdict.INTERFACE_ERRORS,
            HopVerdict.UNREACHABLE: TuiVerdict.UNREACHABLE,
            HopVerdict.CONVERGENCE: TuiVerdict.CONVERGENCE,
        }
        return mapping.get(verdict, TuiVerdict.HEALTHY)

    def _build_checks_string(self, hop: Hop) -> str:
        """Build the 'route ✓ fib ✓ nh ✓ link ✓' summary."""
        v = hop.verdict
        is_connected = hop.is_terminal and hop.route and hop.route.is_connected

        if v == HopVerdict.UNREACHABLE:
            return "unreachable"
        if is_connected:
            return "route ✓ fib — nh — link —"

        r = "✓" if hop.route else "✗"
        if hop.fib and hop.fib.is_forwarding:
            f = "✓"
        elif hop.fib is None:
            f = "?"                     # parser gap — unverified, not failed
        else:
            f = "✗"
        n = "✓" if hop.resolutions and all(
            res.is_resolved for res in hop.resolutions) else "✗"
        link_ok = True
        if hop.resolutions:
            for res in hop.resolutions:
                if (res.egress_interface and
                        res.egress_interface.state != InterfaceState.UP_UP):
                    link_ok = False
        l = "✓" if link_ok else "✗"
        return f"route {r} fib {f} nh {n} link {l}"

    def _build_egress_string(self, hop: Hop) -> str:
        """Build egress interface summary for tree display."""
        is_connected = hop.is_terminal and hop.route and hop.route.is_connected

        if hop.resolutions:
            intfs = []
            for i, res in enumerate(hop.resolutions):
                if res.egress_interface:
                    nh_str = ""
                    if res.next_hop_ip:
                        if (isinstance(res.next_hop_ip, IPv6Address)
                                and res.next_hop_ip.is_link_local):
                            ll_short = str(res.next_hop_ip)
                            if i < len(hop.next_device_ips):
                                resolved = hop.next_device_ips[i]
                                nh_str = f"{ll_short} (→ {resolved})"
                            else:
                                nh_str = f"{ll_short} (unresolved)"
                        else:
                            nh_str = str(res.next_hop_ip)
                    intfs.append(f"{res.egress_interface.name}"
                                 + (f" → {nh_str}" if nh_str else ""))
            if intfs:
                return ", ".join(intfs)
        elif is_connected and hop.route and hop.route.next_hops:
            intf = hop.route.next_hops[0].interface
            if intf:
                return intf
        return ""

    def _build_hop_notes(self, hop: Hop, via_default: bool) -> list[str]:
        """Build TUI-facing note strings."""
        notes = []
        is_connected = hop.is_terminal and hop.route and hop.route.is_connected
        if via_default:
            notes.append("[via default]")
        if is_connected:
            notes.append("(connected)")
        if hop.next_device_ips and len(hop.next_device_ips) > 1:
            notes.append(f"ECMP: {len(hop.next_device_ips)} paths")
        return notes

    def _build_log_lines(self, hop_diag: HopDiagnostic, hop: Hop,
                         identity: DeviceIdentity,
                         via_default: bool, hop_index: int) -> tuple[list, list, list]:
        """
        Build log lines at three verbosity levels from diagnostic data.
        Returns (basic, verbose, debug) — lists of Rich markup strings.
        """
        hostname = identity.hostname
        ssh_target = identity.ssh_target
        platform = identity.platform.value if identity.platform else "unknown"
        is_connected = hop.is_terminal and hop.route and hop.route.is_connected

        # ── Basic: one-line verdict ──
        checks = self._build_checks_string(hop)
        egress = self._build_egress_string(hop)
        verdict_str = hop.verdict.value.upper()
        v_color = "#00ff88" if hop.verdict == HopVerdict.HEALTHY else "#ffcc00"
        if hop.verdict in (HopVerdict.NO_ROUTE, HopVerdict.BLACKHOLE,
                           HopVerdict.UNREACHABLE, HopVerdict.INTERFACE_DOWN):
            v_color = "#ff4444"

        basic_line = f"  [{v_color}]hop {hop_index}: {hostname} → {verdict_str}[/]"
        if is_connected:
            basic_line += "  (connected)"
        if egress:
            basic_line += f"  {egress}"
        if via_default:
            basic_line += "  [#ffcc00]\\[via default][/]"
        if hop.next_device_ips and len(hop.next_device_ips) > 1:
            basic_line += f"  [#00d4ff]ECMP: {len(hop.next_device_ips)} paths[/]"

        basic = [basic_line]

        # ECMP paths on separate lines for basic
        if hop.next_device_ips and len(hop.next_device_ips) > 1 and hop.resolutions:
            for i, res in enumerate(hop.resolutions):
                if res.egress_interface and res.next_hop_ip:
                    basic.append(
                        f"    {res.egress_interface.name} → {res.next_hop_ip}"
                    )

        # ── Verbose: per-command parse results ──
        verbose = []
        for cmd_rec in hop_diag.commands:
            parse_ok = cmd_rec.parse_result in (ParseResult.OK, ParseResult.PARTIAL)
            p_icon = "[#00ff88][✓][/]" if parse_ok else "[#ff4444][✗][/]"
            parser_str = f" via {cmd_rec.parser_used}" if cmd_rec.parser_used else ""

            verbose.append(f"  [#888888][✓] {cmd_rec.command}[/] parse:{p_icon}{parser_str}")

        # Verdict separator
        if hop_diag.verdict:
            vr = hop_diag.verdict
            v_val = vr.verdict if hasattr(vr, 'verdict') else str(vr)
            verbose.append(f"  ─── [{v_color}]Verdict: {v_val}[/] ───")
            if hasattr(vr, 'route_detail') and vr.route_detail:
                detail = vr.route_detail
                if via_default:
                    detail = f"[#ffcc00]\\[via default][/] {detail}"
                verbose.append(f"    route: {detail}")
        verbose.append("")

        # ── Debug: verbose + raw output excerpts ──
        debug = []
        for cmd_rec in hop_diag.commands:
            parse_ok = cmd_rec.parse_result in (ParseResult.OK, ParseResult.PARTIAL)
            p_icon = "[#00ff88][✓][/]" if parse_ok else "[#ff4444][✗][/]"
            parser_str = f" via {cmd_rec.parser_used}" if cmd_rec.parser_used else ""

            debug.append(f"  [#888888][✓] {cmd_rec.command}[/] parse:{p_icon}{parser_str}")

            # Raw output excerpt (first 120 chars of each line, max 3 lines)
            if cmd_rec.raw_output:
                for line in cmd_rec.raw_output.strip().splitlines()[:3]:
                    line = line.strip()[:120]
                    if line:
                        debug.append(f"    [#444444]{line}[/]")

            # Parse detail (what matched or why it failed)
            if cmd_rec.parse_detail:
                debug.append(f"    [#444444]{cmd_rec.parse_detail}[/]")

            # Error message if command errored
            if cmd_rec.error_message:
                debug.append(f"    [#ff4444]{cmd_rec.error_message}[/]")

            # Timing
            if cmd_rec.duration_ms:
                debug.append(f"    [#444444]elapsed: {cmd_rec.duration_ms:.0f}ms[/]")

        if hop_diag.verdict:
            vr = hop_diag.verdict
            v_val = vr.verdict if hasattr(vr, 'verdict') else str(vr)
            debug.append(f"  ─── [{v_color}]Verdict: {v_val}[/] ───")
            if hasattr(vr, 'route_detail') and vr.route_detail:
                debug.append(f"    route: {vr.route_detail}")
            if hasattr(vr, 'fib_detail') and vr.fib_detail:
                debug.append(f"    fib: {vr.fib_detail}")
            if hasattr(vr, 'nh_detail') and vr.nh_detail:
                debug.append(f"    nh: {vr.nh_detail}")
            if hasattr(vr, 'link_detail') and vr.link_detail:
                debug.append(f"    link: {vr.link_detail}")
        debug.append("")

        return basic, verbose, debug

    # ────────────────────────────────────────────
    # Main Walk
    # ────────────────────────────────────────────

    def walk(self) -> ForwardingChain:
        """Execute the BFS chain walk. Returns the complete ForwardingChain."""

        # Setup logging
        setup_logging(
            log_file=self.config.log_file,
            debug=self.config.debug,
            verbose=self.config.verbose,
        )

        logger.info(f"Starting chain walk: {self.config.target_prefix} "
                     f"from {self.config.source_host}")
        self._progress(
            f"fibtrace: {self.config.target_prefix} "
            f"from {self.config.source_host}"
        )

        self._visited.clear()
        self._connections.clear()
        self._identity_cache.clear()
        self._ip_to_hostname.clear()

        started_at = datetime.now()

        # Build target prefix
        try:
            target_net = _parse_network(self.config.target_prefix)
        except ValueError as e:
            logger.error(f"Invalid prefix: {self.config.target_prefix}: {e}")
            raise

        source_device = DeviceInfo(
            hostname="(pending)",
            ip_address=_parse_ip(self.config.source_host),
        )

        # Initialize chain and diagnostics
        self._chain = ForwardingChain(
            target_prefix=Prefix(network=target_net),
            source_device=source_device,
            started_at=started_at,
        )
        self._diagnostics = ChainDiagnostic(
            target_prefix=self.config.target_prefix,
            started_at=started_at,
        )

        # BFS queue
        queue: deque[QueueItem] = deque()
        queue.append(QueueItem(
            ssh_target=self.config.source_host,
            depth=0,
        ))

        hop_index = 0
        loop_detected = False

        while queue:
            item = queue.popleft()

            # ── Guard: max depth ──
            if item.depth > self.config.max_depth:
                logger.warning(f"Max depth {self.config.max_depth} reached "
                               f"at {item.ssh_target}")
                self._chain.anomalies.append(
                    f"Max depth reached at {item.ssh_target}"
                )
                continue

            # ── Guard: already know this IP maps to a visited hostname? ──
            if item.ssh_target in self._ip_to_hostname:
                known_hostname = self._ip_to_hostname[item.ssh_target]
                if known_hostname in self._visited:
                    logger.debug(f"IP {item.ssh_target} → {known_hostname} "
                                 f"(already visited, skipping)")
                    continue

            # ── 1. Connect ──
            client = self._connect(item.ssh_target)

            # ── 1b. Neighbor discovery fallback ──
            # If direct SSH failed and we have a parent, try LLDP/CDP/DNS
            # to find a reachable management address for this next-hop.
            resolved_via = None
            if (client is None
                    and item.parent_hostname
                    and item.parent_interface):
                self._progress(
                    f"  ↪ neighbor discovery via "
                    f"{item.parent_hostname}/{item.parent_interface}..."
                )
                resolved_target = self._resolve_via_neighbors(item)
                if resolved_target:
                    client = self._connect(resolved_target)
                    if client:
                        resolved_via = resolved_target
                        logger.info(
                            f"Reached {item.ssh_target} via neighbor "
                            f"discovery → {resolved_target}"
                        )
                        # Update ssh_target so identity/caching uses the
                        # reachable address, not the transit IP
                        item.ssh_target = resolved_target
                    else:
                        self._progress(
                            f"  ↪ neighbor discovery found {resolved_target} "
                            f"but SSH failed"
                        )
                else:
                    self._progress("  ↪ no neighbor found")

            if client is None:
                logger.error(f"Cannot reach {item.ssh_target}")
                # Record unreachable hop
                unreachable_device = DeviceInfo(
                    hostname=f"unreachable-{item.ssh_target}",
                    ip_address=_parse_ip(item.ssh_target),
                )
                unreachable_hop = Hop(
                    device=unreachable_device,
                    target_prefix=self._chain.target_prefix,
                    verdict=HopVerdict.UNREACHABLE,
                    notes=[
                        f"SSH connection failed to {item.ssh_target}"
                        + (f" (neighbor discovery also tried via "
                           f"{item.parent_hostname}/{item.parent_interface})"
                           if item.parent_interface else "")
                    ],
                )
                self._chain.hops.append(unreachable_hop)

                hop_diag = HopDiagnostic(
                    device=f"unreachable-{item.ssh_target}",
                    hop_index=hop_index,
                )
                hop_diag.verdict = VerdictRecord(
                    device=f"unreachable-{item.ssh_target}",
                    prefix=self.config.target_prefix,
                    verdict=HopVerdict.UNREACHABLE.value,
                )
                self._diagnostics.hops.append(hop_diag)

                # Emit unreachable to TUI
                self._emit(HopEvent(
                    event="hop_start",
                    device=f"unreachable-{item.ssh_target}",
                    ip=item.ssh_target,
                    parent_device=item.parent_hostname,
                    log_basic=[
                        f"[#ff4444]Cannot reach {item.ssh_target}[/]",
                    ],
                ))
                self._emit(HopEvent(
                    event="hop_done",
                    device=f"unreachable-{item.ssh_target}",
                    ip=item.ssh_target,
                    parent_device=item.parent_hostname,
                    verdict=TuiVerdict.UNREACHABLE,
                    checks="unreachable",
                    log_basic=[
                        f"  [#ff4444]hop {hop_index}: unreachable-{item.ssh_target} → UNREACHABLE[/]",
                    ],
                    log_verbose=[
                        f"  [#ff4444]SSH connection failed to {item.ssh_target}[/]",
                        f"  ─── [#ff4444]Verdict: unreachable[/] ───",
                        "",
                    ],
                    log_debug=[
                        f"  [#ff4444]SSH connection failed to {item.ssh_target}[/]",
                        f"    [#444444]parent: {item.parent_hostname or 'none'}, "
                        f"interface: {item.parent_interface or 'none'}[/]",
                        f"  ─── [#ff4444]Verdict: unreachable[/] ───",
                        "",
                    ],
                ))
                hop_index += 1
                continue

            # ── 2. Identify — this is the moment of truth ──
            identity = self._identify_device(client, item.ssh_target)

            if identity is None:
                logger.error(f"Cannot identify device at {item.ssh_target}")
                self._release_connection(client, item.ssh_target)
                hop_index += 1
                continue

            # ── 3. Revisit check BY HOSTNAME ──
            # Distinguish real loops from ECMP convergence:
            #   Loop:        A → B → C → A  (ancestor revisited — forwarding loop)
            #   Convergence: A → B → D, A → C → D  (sibling paths meet — normal ECMP)
            if identity.hostname in self._visited:
                self._release_connection(client, item.ssh_target)
                # Cache this IP so the pre-connection guard (step 0) catches
                # any remaining queue items pointing at the same address.
                self._ip_to_hostname[item.ssh_target] = identity.hostname
                if identity.hostname in item.ancestors:
                    # Real loop — this device is in our own forwarding path
                    logger.warning(
                        f"Loop detected: {item.ssh_target} is {identity.hostname} "
                        f"(ancestor in forwarding path)"
                    )
                    loop_detected = True
                    self._chain.anomalies.append(
                        f"Loop: {identity.hostname} appears in its own "
                        f"forwarding path via {item.ssh_target} "
                        f"(parent: {item.parent_hostname})"
                    )
                else:
                    # ECMP convergence — already visited via a sibling path.
                    # Record a lightweight convergence hop so the tree and
                    # summary output can show where branches reconverge.
                    logger.info(
                        f"ECMP convergence: {item.ssh_target} is "
                        f"{identity.hostname} (visited via different branch, "
                        f"parent: {item.parent_hostname})"
                    )

                    convergence_hop = Hop(
                        device=DeviceInfo(
                            hostname=identity.hostname,
                            ip_address=_parse_ip(item.ssh_target),
                            platform=(identity.platform.value
                                      if identity.platform else None),
                        ),
                        target_prefix=self._chain.target_prefix,
                        verdict=HopVerdict.CONVERGENCE,
                        notes=[
                            f"ECMP convergence — already visited via "
                            f"sibling branch"
                        ],
                        parent_hostname=item.parent_hostname,
                        depth=item.depth,
                        converges_to=identity.hostname,
                    )
                    self._chain.hops.append(convergence_hop)

                    # Emit to TUI so the tree can render the convergence link
                    self._emit(HopEvent(
                        event="hop_done",
                        device=identity.hostname,
                        ip=item.ssh_target,
                        parent_device=item.parent_hostname,
                        platform=(identity.platform.value
                                  if identity.platform else None),
                        verdict=TuiVerdict.CONVERGENCE,
                        checks="converges",
                        notes=["(converges)"],
                        log_basic=[
                            f"  [#00d4ff]↪ {identity.hostname}[/] (converges)",
                        ],
                        log_verbose=[
                            f"  [#00d4ff]↪ {identity.hostname}[/] — ECMP convergence "
                            f"(already visited via sibling branch, "
                            f"parent: {item.parent_hostname})",
                            "",
                        ],
                        log_debug=[
                            f"  [#00d4ff]↪ {identity.hostname}[/] — ECMP convergence",
                            f"    [#444444]visited via: {item.ssh_target}, "
                            f"parent: {item.parent_hostname}[/]",
                            f"    [#444444]original visit cached at depth "
                            f"{item.depth}[/]",
                            "",
                        ],
                    ))

                    self._progress(
                        f"  ↪ {identity.hostname} (converges)"
                    )

                continue

            # ── Mark visited ──
            self._visited.add(identity.hostname)
            self._ip_to_hostname[item.ssh_target] = identity.hostname

            # Cache connection by hostname
            if self.config.keep_connections:
                self._connections[identity.hostname] = client

            logger.info(
                f"Hop {hop_index} (depth {item.depth}): "
                f"{identity.hostname} via {item.ssh_target}"
            )

            # Update source_device on first hop
            if hop_index == 0:
                self._chain.source_device = DeviceInfo(
                    hostname=identity.hostname,
                    ip_address=_parse_ip(item.ssh_target),
                )

            # ── 4. Fingerprint ──
            platform, fp_record = self._fingerprint_device(client, identity)
            identity.platform = platform

            # ── 4b. Emit hop_start to TUI ──
            self._emit(HopEvent(
                event="hop_start",
                device=identity.hostname,
                ip=item.ssh_target,
                parent_device=item.parent_hostname,
                platform=platform.value,
                log_basic=[
                    f"[#00d4ff]Connecting to {identity.hostname}[/] ({item.ssh_target})",
                ],
                log_verbose=[
                    f"[#00d4ff]Connecting to {identity.hostname}[/] ({item.ssh_target})",
                    f"  Platform detected: [bold]{platform.value}[/]",
                ],
                log_debug=[
                    f"[#00d4ff]Connecting to {identity.hostname}[/] ({item.ssh_target})",
                    f"  Prompt detected: [bold]{identity.prompt_raw}[/]",
                    f"  Platform detected: [bold]{platform.value}[/]"
                    + (f" (confidence: {fp_record.confidence})" if fp_record else ""),
                ],
            ))

            # ── 5. Gather forwarding state ──
            hop, hop_diag = self._gather_forwarding_state(
                client, identity, hop_index
            )

            # Attach fingerprint to diagnostics
            if hop_diag and fp_record:
                hop_diag.fingerprint = fp_record

            # Add to chain and diagnostics
            if hop is not None:
                # Attach tree structure so TUI/summary can render the tree
                hop.parent_hostname = item.parent_hostname
                hop.depth = item.depth
                self._chain.hops.append(hop)
            if hop_diag is not None:
                self._diagnostics.hops.append(hop_diag)

            # ── 5b. Emit hop_done to TUI ──
            if hop is not None and hop_diag is not None:
                is_connected = (hop.is_terminal and hop.route
                                and hop.route.is_connected)
                via_default = any("default route" in n for n in hop.notes)

                basic, verbose, debug = self._build_log_lines(
                    hop_diag, hop, identity, via_default, hop_index
                )
                self._emit(HopEvent(
                    event="hop_done",
                    device=identity.hostname,
                    ip=item.ssh_target,
                    parent_device=item.parent_hostname,
                    platform=platform.value,
                    verdict=self._verdict_to_tui(hop.verdict, is_connected),
                    checks=self._build_checks_string(hop),
                    egress=self._build_egress_string(hop),
                    notes=self._build_hop_notes(hop, via_default),
                    log_basic=basic,
                    log_verbose=verbose,
                    log_debug=debug,
                ))

            hop_index += 1

            # ── 6. Report progress ──
            if hop_diag:
                self._progress(f"  {dump_hop_summary(hop_diag)}")
            if self.config.verbose and hop_diag:
                print(dump_hop_detail(hop_diag))

            # ── 7. Check terminal ──
            if hop is None or hop.is_terminal:
                logger.info(f"Terminal hop at {identity.hostname}")
                continue

            # ── 8. Enqueue next-hop devices (ECMP fan-out) ──
            # Build next-hop IP → egress interface mapping for neighbor
            # discovery fallback. If direct SSH to the FIB next-hop fails,
            # we need the egress interface to query LLDP/CDP on the parent.
            nh_egress_map: dict[str, str] = {}
            if hop.resolutions:
                for i, res in enumerate(hop.resolutions):
                    intf_name = (res.egress_interface.name
                                 if res.egress_interface else None)
                    if intf_name and res.next_hop_ip:
                        nh_egress_map[str(res.next_hop_ip)] = intf_name
                # Index-match for resolved link-local targets
                if len(hop.next_device_ips) == len(hop.resolutions):
                    for ip, res in zip(hop.next_device_ips, hop.resolutions):
                        intf_name = (res.egress_interface.name
                                     if res.egress_interface else None)
                        if intf_name:
                            nh_egress_map[str(ip)] = intf_name

            next_ancestors = item.ancestors | {identity.hostname}
            for next_ip in hop.next_device_ips:
                queue.append(QueueItem(
                    ssh_target=str(next_ip),
                    depth=item.depth + 1,
                    parent_hostname=identity.hostname,
                    parent_interface=nh_egress_map.get(str(next_ip)),
                    ancestors=next_ancestors,
                ))

            # Track ECMP
            if len(hop.next_device_ips) > 1:
                self._chain.ecmp_branch_points += 1

        # ── Finalize ──
        completed_at = datetime.now()
        elapsed = (completed_at - started_at).total_seconds()

        self._chain.completed_at = completed_at
        self._chain.total_devices = len(self._visited)
        self._diagnostics.completed_at = completed_at

        # Determine chain status
        if loop_detected:
            self._chain.status = ChainStatus.LOOP
        elif any(h.verdict in (HopVerdict.NO_ROUTE, HopVerdict.BLACKHOLE,
                                HopVerdict.UNREACHABLE)
                 for h in self._chain.hops):
            self._chain.status = ChainStatus.BROKEN
        elif any(h.verdict == HopVerdict.UNKNOWN for h in self._chain.hops):
            self._chain.status = ChainStatus.PARTIAL
        else:
            self._chain.status = ChainStatus.COMPLETE

        logger.info(
            f"Walk complete: {hop_index} hops, "
            f"{len(self._visited)} unique devices, "
            f"{elapsed:.1f}s → {self._chain.status.value}"
        )
        logger.info(f"Devices visited: {', '.join(sorted(self._visited))}")

        # Emit trace_done to TUI
        self._emit(HopEvent(
            event="trace_done",
            total_devices=self._chain.total_devices,
            ecmp_branches=self._chain.ecmp_branch_points,
            duration=elapsed,
            is_healthy=self._chain.is_healthy,
            status=self._chain.status.value,
            log_basic=[
                "",
                f"[#00ff88]━━━ Trace complete ━━━[/]",
                f"  Status: [{('#00ff88' if self._chain.is_healthy else '#ff4444')}]"
                f"{self._chain.status.value.upper()}[/] │ "
                f"{self._chain.total_devices} devices │ "
                f"{self._chain.ecmp_branch_points} ECMP branches │ {elapsed:.1f}s",
            ],
            log_verbose=[
                "",
                f"[#00ff88]━━━ Trace complete ━━━[/]",
                f"  Status: [{('#00ff88' if self._chain.is_healthy else '#ff4444')}]"
                f"{self._chain.status.value.upper()}[/] │ "
                f"{self._chain.total_devices} devices │ "
                f"{self._chain.ecmp_branch_points} ECMP branches │ {elapsed:.1f}s",
                f"  {'All paths healthy — forwarding chain validated end-to-end' if self._chain.is_healthy else 'Issues detected — see verdicts above'}",
            ] + ([f"  Anomalies: {', '.join(self._chain.anomalies)}"]
                 if self._chain.anomalies else []),
            log_debug=[
                "",
                f"[#00ff88]━━━ Trace complete ━━━[/]",
                f"  Status: [{('#00ff88' if self._chain.is_healthy else '#ff4444')}]"
                f"{self._chain.status.value.upper()}[/] │ "
                f"{self._chain.total_devices} devices │ "
                f"{self._chain.ecmp_branch_points} ECMP branches │ {elapsed:.1f}s",
                f"  {'All paths healthy' if self._chain.is_healthy else 'Issues detected'}",
                f"  [#444444]BFS depth: {max((h.depth for h in [item] if hasattr(item, 'depth')), default='?')}, "
                f"visited: {{{', '.join(sorted(self._visited))}}}[/]",
                f"  [#444444]Total SSH sessions: {len(self._visited)}, "
                f"total commands: {sum(len(h.commands) for h in self._diagnostics.hops)}[/]",
            ] + ([f"  [#ffcc00]Anomalies: {', '.join(self._chain.anomalies)}[/]"]
                 if self._chain.anomalies else []),
        ))

        # Dump diagnostics if requested
        if self.config.log_file:
            self._diagnostics.dump_json(self.config.log_file)
            logger.info(f"Diagnostics written to {self.config.log_file}")

        self._cleanup_connections()
        return self._chain

    # ────────────────────────────────────────────
    # Device Identity
    # ────────────────────────────────────────────

    def _identify_device(self, client: SSHClient,
                         ssh_target: str) -> Optional[DeviceIdentity]:
        """
        Establish device identity from the CLI prompt.
        Happens BEFORE fingerprinting — just need the prompt,
        which find_prompt() already captured during connection.

        If we've already identified (and fingerprinted) this hostname,
        return the cached identity — don't overwrite it with a fresh
        un-fingerprinted one.
        """
        prompt = client._detected_prompt or ""
        hostname = client.extract_hostname_from_prompt(prompt)

        if not hostname:
            logger.warning(
                f"Cannot extract hostname from prompt on {ssh_target}, "
                f"prompt was: {prompt!r}"
            )
            hostname = f"unknown-{ssh_target}"

        # Return existing identity if already fingerprinted
        if hostname in self._identity_cache:
            self._ip_to_hostname[ssh_target] = hostname
            logger.debug(
                f"Device identity (cached): {ssh_target} → {hostname}"
            )
            return self._identity_cache[hostname]

        identity = DeviceIdentity(
            ssh_target=ssh_target,
            prompt_raw=prompt,
            hostname=hostname,
        )

        self._identity_cache[hostname] = identity
        self._ip_to_hostname[ssh_target] = hostname

        logger.debug(f"Device identity: {ssh_target} → {hostname} "
                      f"(prompt: {prompt!r})")
        return identity

    # ────────────────────────────────────────────
    # Fingerprinting
    # ────────────────────────────────────────────

    def _fingerprint_device(self, client: SSHClient,
                            identity: DeviceIdentity
                            ) -> tuple[Platform, Optional[FingerprintRecord]]:
        """Identify platform via prompt analysis + show version."""
        hostname = identity.hostname
        fp_record = FingerprintRecord(device=hostname, prompt_raw=identity.prompt_raw)

        # Quick check from prompt (catches Juniper)
        quick_guess = fingerprint_from_prompt(identity.prompt_raw)
        if quick_guess:
            fp_record.prompt_guess = quick_guess.value

        # Definitive: show version
        version_output = self._execute_command(
            client, "show version",
            timeout=self.config.command_timeout,
        )
        fp_record.show_version_output = version_output

        platform = fingerprint_from_show_version(version_output)
        fp_record.final_platform = platform.value
        fp_record.confidence = "show_version" if platform != Platform.UNKNOWN else "fallback"

        logger.info(f"[{hostname}] Platform: {platform.value} "
                     f"(confidence: {fp_record.confidence})")

        return platform, fp_record

    # ────────────────────────────────────────────
    # Forwarding State Gathering
    # ────────────────────────────────────────────

    def _gather_forwarding_state(self, client: SSHClient,
                                  identity: DeviceIdentity,
                                  hop_index: int
                                  ) -> tuple[Optional[Hop], Optional[HopDiagnostic]]:
        """
        Complete evaluation of forwarding at one device.

        Four questions:
            1. Route?    → RIB lookup
            2. FIB?      → Hardware forwarding table
            3. Resolved? → ARP/ND, MAC, egress interface
            4. Healthy?  → Interface counters (informational, never stops the walk)
        """
        hostname = identity.hostname
        platform = identity.platform
        prefix = self.config.target_prefix

        hop_diag = HopDiagnostic(device=hostname, hop_index=hop_index)

        device_info = DeviceInfo(
            hostname=hostname,
            ip_address=_parse_ip(identity.ssh_target),
            platform=platform.value,
        )

        # Get platform-specific command set
        commands = COMMAND_SETS.get(platform, COMMAND_SETS.get(Platform.CISCO_IOS))
        json_suffix = commands.json_suffix if commands.json_supported else ""

        # Format prefix for this platform's CLI syntax
        cli_prefix = self._format_prefix_for_platform(prefix, platform)

        # Detect address family from target prefix
        is_v6 = isinstance(_parse_network(prefix), IPv6Network)

        # ── 1. RIB Lookup ──
        if is_v6 and commands.show_route_v6:
            route_cmd = commands.show_route_v6.format(prefix=cli_prefix)
        else:
            route_cmd = commands.show_route.format(prefix=cli_prefix)
        if json_suffix:
            route_cmd += json_suffix

        route_output = self._execute_command(client, route_cmd)
        route_parser = get_parser(platform, PARSE_ROUTE)
        route_entry = None

        if route_parser:
            route_entry, route_record = parse_with_diagnostics(
                device=hostname, platform=platform.value,
                command=route_cmd, raw_output=route_output,
                parser_func=lambda raw: route_parser(raw, prefix),
                parser_name=get_parser_name(platform, PARSE_ROUTE),
                logger=logger,
            )
            hop_diag.commands.append(route_record)
        else:
            logger.warning(f"[{hostname}] No route parser for {platform.value}")

        # No specific route → try default route before giving up
        via_default = False
        default_prefix = "::/0" if is_v6 else "0.0.0.0/0"
        if route_entry is None:
            default_cli = self._format_prefix_for_platform(
                default_prefix, platform
            )
            if is_v6 and commands.show_route_v6:
                default_cmd = commands.show_route_v6.format(
                    prefix=default_cli
                )
            else:
                default_cmd = commands.show_route.format(
                    prefix=default_cli
                )
            if json_suffix:
                default_cmd += json_suffix

            logger.info(
                f"[{hostname}] No specific route for {prefix}, "
                f"checking default route"
            )

            default_output = self._execute_command(client, default_cmd)
            if route_parser:
                route_entry, default_record = parse_with_diagnostics(
                    device=hostname, platform=platform.value,
                    command=default_cmd, raw_output=default_output,
                    parser_func=lambda raw: route_parser(
                        raw, default_prefix
                    ),
                    parser_name=get_parser_name(platform, PARSE_ROUTE),
                    logger=logger,
                )
                hop_diag.commands.append(default_record)

            if route_entry is not None:
                via_default = True
                logger.info(
                    f"[{hostname}] Using default route for {prefix}"
                )
            else:
                # No specific route AND no default → truly no route
                verdict = HopVerdict.NO_ROUTE
                hop = Hop(
                    device=device_info,
                    target_prefix=self._chain.target_prefix,
                    route=None,
                    verdict=verdict,
                    notes=["No RIB entry for prefix (no default route)"],
                )
                hop_diag.verdict = self._build_verdict_record(
                    hostname, prefix, verdict,
                    route_detail="No RIB entry (no default route)",
                )
                return hop, hop_diag

        # Connected route → terminal, HEALTHY
        if route_entry.is_connected:
            hop = Hop(
                device=device_info,
                target_prefix=self._chain.target_prefix,
                route=route_entry,
                verdict=HopVerdict.HEALTHY,
                notes=["Connected route — end of chain"],
            )
            hop_diag.verdict = self._build_verdict_record(
                hostname, prefix, HopVerdict.HEALTHY,
                route_found=True,
                route_detail=f"Connected via {route_entry.next_hops[0].interface}"
                    if route_entry.next_hops else "Connected",
                fib_programmed=True,
                fib_detail="Connected (implicit)",
                nh_resolved=True,
                nh_detail="Directly connected",
                link_healthy=True,
                link_detail="N/A (connected)",
            )
            return hop, hop_diag

        # ── 2. FIB Lookup ──
        # When using default route, FIB lookup must also use the default prefix
        fib_prefix = default_prefix if via_default else prefix
        fib_cli_prefix = (self._format_prefix_for_platform(fib_prefix, platform)
                          if via_default else cli_prefix)
        if is_v6 and commands.show_fib_v6:
            fib_cmd = commands.show_fib_v6.format(prefix=fib_cli_prefix)
        else:
            fib_cmd = commands.show_fib.format(prefix=fib_cli_prefix)
        if json_suffix:
            fib_cmd += json_suffix

        fib_output = self._execute_command(client, fib_cmd)
        fib_parser = get_parser(platform, PARSE_FIB)
        fib_entry = None

        if fib_parser:
            fib_entry, fib_record = parse_with_diagnostics(
                device=hostname, platform=platform.value,
                command=fib_cmd, raw_output=fib_output,
                parser_func=lambda raw: fib_parser(raw, fib_prefix),
                parser_name=get_parser_name(platform, PARSE_FIB),
                logger=logger,
            )
            hop_diag.commands.append(fib_record)

        # FIB state checks (non-terminal except DROP)
        if fib_entry and fib_entry.state == FibState.DROP:
            hop = Hop(
                device=device_info,
                target_prefix=self._chain.target_prefix,
                route=route_entry,
                fib=fib_entry,
                verdict=HopVerdict.BLACKHOLE,
                notes=["FIB entry is null/drop — blackhole"],
            )
            hop_diag.verdict = self._build_verdict_record(
                hostname, prefix, HopVerdict.BLACKHOLE,
                route_found=True,
                route_detail=self._summarize_route(route_entry),
                fib_detail="Drop/null route",
            )
            return hop, hop_diag

        if fib_entry and fib_entry.state == FibState.RECEIVE:
            hop = Hop(
                device=device_info,
                target_prefix=self._chain.target_prefix,
                route=route_entry,
                fib=fib_entry,
                verdict=HopVerdict.HEALTHY,
                notes=["Destined to this device (receive)"],
            )
            hop_diag.verdict = self._build_verdict_record(
                hostname, prefix, HopVerdict.HEALTHY,
                route_found=True,
                route_detail=self._summarize_route(route_entry),
                fib_programmed=True,
                fib_detail="Receive (local destination)",
                nh_resolved=True, link_healthy=True,
            )
            return hop, hop_diag

        # ── 3. Per-next-hop resolution ──
        # Use FIB next-hops if available, fall back to RIB next-hops
        nh_source = "fib"
        if fib_entry and fib_entry.next_hops:
            nh_list = [
                (nh.address, nh.interface) for nh in fib_entry.next_hops
            ]
        elif route_entry and route_entry.next_hops:
            nh_list = [
                (nh.address, nh.interface) for nh in route_entry.next_hops
            ]
            nh_source = "rib"
        else:
            nh_list = []

        resolutions = []
        next_device_ips = []

        for nh_addr, nh_intf in nh_list:
            resolution = NextHopResolution(next_hop_ip=nh_addr)

            # 3a. ARP or ND lookup depending on next-hop address family
            if nh_addr:
                nh_is_v6 = isinstance(nh_addr, IPv6Address)

                if nh_is_v6:
                    # IPv6 next-hop → use ND
                    # IOS doesn't accept link-local as a positional arg —
                    # use '| include' to filter from the full ND table
                    if (platform == Platform.CISCO_IOS
                            and nh_addr.is_link_local):
                        nd_base = commands.show_nd.split('{')[0].strip()
                        nd_cmd = f"{nd_base} | include {nh_addr}"
                    else:
                        nd_cmd = commands.show_nd.format(next_hop=str(nh_addr))
                    if json_suffix:
                        nd_cmd += json_suffix

                    nd_output = self._execute_command(client, nd_cmd)
                    nd_parser = get_parser(platform, PARSE_ND)

                    if nd_parser:
                        arp_entry, arp_record = parse_with_diagnostics(
                            device=hostname, platform=platform.value,
                            command=nd_cmd, raw_output=nd_output,
                            parser_func=lambda raw, _ip=str(nh_addr): nd_parser(raw, _ip),
                            parser_name=get_parser_name(platform, PARSE_ND),
                            logger=logger,
                        )
                        hop_diag.commands.append(arp_record)
                        resolution.arp_entry = arp_entry
                    else:
                        arp_entry = None
                else:
                    # IPv4 next-hop → use ARP (existing logic)
                    arp_cmd = commands.show_arp.format(next_hop=str(nh_addr))
                    if json_suffix:
                        arp_cmd += json_suffix

                    arp_output = self._execute_command(client, arp_cmd)
                    arp_parser = get_parser(platform, PARSE_ARP)

                    if arp_parser:
                        arp_entry, arp_record = parse_with_diagnostics(
                            device=hostname, platform=platform.value,
                            command=arp_cmd, raw_output=arp_output,
                            parser_func=lambda raw, _ip=str(nh_addr): arp_parser(raw, _ip),
                            parser_name=get_parser_name(platform, PARSE_ARP),
                            logger=logger,
                        )
                        hop_diag.commands.append(arp_record)
                        resolution.arp_entry = arp_entry
                    else:
                        arp_entry = None

                # 3b. MAC table (conditional, optional)
                if (not self.config.skip_mac_lookup
                        and commands.show_mac_table
                        and arp_entry and arp_entry.mac
                        and arp_entry.mac.address):
                    mac_cmd = commands.show_mac_table.format(
                        mac=arp_entry.mac.address
                    )
                    if json_suffix:
                        mac_cmd += json_suffix

                    mac_output = self._execute_command(client, mac_cmd)
                    mac_parser = get_parser(platform, PARSE_MAC_TABLE)

                    if mac_parser:
                        mac_entry, mac_record = parse_with_diagnostics(
                            device=hostname, platform=platform.value,
                            command=mac_cmd, raw_output=mac_output,
                            parser_func=mac_parser,
                            parser_name=get_parser_name(platform, PARSE_MAC_TABLE),
                            logger=logger,
                        )
                        hop_diag.commands.append(mac_record)
                        resolution.mac_entry = mac_entry

            # 3c. Egress interface
            intf_name = nh_intf
            # If ARP resolved to an interface, prefer that
            if resolution.arp_entry and resolution.arp_entry.interface:
                intf_name = resolution.arp_entry.interface

            if intf_name:
                intf_cmd = commands.show_interface.format(interface=intf_name)
                if json_suffix:
                    intf_cmd += json_suffix

                intf_output = self._execute_command(client, intf_cmd)
                intf_parser = get_parser(platform, PARSE_INTERFACE)

                if intf_parser:
                    interface, intf_record = parse_with_diagnostics(
                        device=hostname, platform=platform.value,
                        command=intf_cmd, raw_output=intf_output,
                        parser_func=intf_parser,
                        parser_name=get_parser_name(platform, PARSE_INTERFACE),
                        logger=logger,
                    )
                    hop_diag.commands.append(intf_record)
                    resolution.egress_interface = interface

            resolutions.append(resolution)

            # Collect next-hop IPs for BFS queue — always, regardless of errors
            # Link-local v6 next-hops must be resolved to routable SSH targets
            if nh_addr:
                if isinstance(nh_addr, IPv6Address) and nh_addr.is_link_local:
                    # ── Link-local resolution: ND → MAC → ARP → IPv4 SSH target ──
                    resolved_ip = self._resolve_link_local(
                        client, platform, hostname, commands,
                        json_suffix, nh_addr, nh_intf, resolution,
                        hop_diag,
                    )
                    if resolved_ip:
                        next_device_ips.append(resolved_ip)
                    else:
                        notes_ll = (
                            f"Cannot resolve link-local {nh_addr} on "
                            f"{nh_intf or '?'} — MAC not found in ARP table"
                        )
                        logger.warning(f"[{hostname}] {notes_ll}")
                else:
                    next_device_ips.append(nh_addr)

        # ── 4. Assess verdict ──
        verdict, detail, notes = self._assess_verdict(
            route_entry, fib_entry, resolutions
        )

        # Annotate when forwarding via default route
        if via_default:
            notes.insert(0, f"No specific route for {prefix} — using default route")

        hop = Hop(
            device=device_info,
            target_prefix=self._chain.target_prefix,
            route=route_entry,
            fib=fib_entry,
            resolutions=resolutions,
            verdict=verdict,
            notes=notes,
            next_device_ips=next_device_ips,
        )

        route_summary = self._summarize_route(route_entry)
        if via_default:
            route_summary = f"[via default] {route_summary}"

        hop_diag.verdict = self._build_verdict_record(
            hostname, prefix, verdict,
            route_found=True,
            route_detail=route_summary,
            fib_programmed=fib_entry is not None and fib_entry.is_forwarding,
            fib_detail=self._summarize_fib(fib_entry),
            nh_resolved=all(r.is_resolved for r in resolutions) if resolutions else False,
            nh_detail=f"{len(resolutions)} next-hop(s), source: {nh_source}",
            link_healthy=verdict not in (
                HopVerdict.INTERFACE_DOWN,
            ),
            link_detail=detail,
        )

        return hop, hop_diag

    # ────────────────────────────────────────────
    # Link-Local Resolution (IPv6 → IPv4 SSH target)
    # ────────────────────────────────────────────

    @staticmethod
    def _mac_from_eui64(addr: IPv6Address) -> Optional[str]:
        """
        Derive MAC address from an EUI-64 link-local IPv6 address.

        EUI-64 embeds the MAC in the interface identifier with ff:fe
        inserted in the middle and bit 7 (Universal/Local) flipped.

        fe80::e3f:42ff:fef4:b565
          → interface ID bytes: 0e:3f:42:ff:fe:f4:b5:65
          → ff:fe in middle confirms EUI-64
          → remove ff:fe:             0e:3f:42:f4:b5:65
          → flip bit 7 of byte 0:    0c:3f:42:f4:b5:65
          → MAC: 0c:3f:42:f4:b5:65

        Returns normalized MAC (aa:bb:cc:dd:ee:ff) or None if not EUI-64.
        """
        if not addr.is_link_local:
            return None

        # Get the full 16-byte packed representation
        packed = addr.packed  # 16 bytes
        # Interface ID is bytes 8-15
        iid = packed[8:16]

        # EUI-64 marker: bytes 3-4 of IID must be ff:fe
        if iid[3] != 0xFF or iid[4] != 0xFE:
            return None

        # Extract MAC: IID bytes [0:3] + [5:8], flip bit 7 of byte 0
        mac_bytes = bytearray([
            iid[0] ^ 0x02,  # flip Universal/Local bit
            iid[1],
            iid[2],
            iid[5],
            iid[6],
            iid[7],
        ])

        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def _resolve_link_local(
        self, client, platform: Platform, hostname: str,
        commands, json_suffix: str,
        nh_addr: IPv6Address, nh_intf: str,
        resolution: NextHopResolution,
        hop_diag,
    ) -> Optional[IPv4Address]:
        """
        Resolve a link-local v6 next-hop to a routable IPv4 SSH target.

        Strategy: ND → MAC → ARP (cross-AF correlation).
        Fallback: if ND table is empty, derive MAC from EUI-64 encoding
                  in the link-local address itself (works for most hardware).

        The ND lookup was already done in the resolution loop — the MAC
        is on resolution.arp_entry. We just need to search the ARP table
        for a matching MAC to get the corresponding IPv4 address.

        Uses data the walker is already collecting — no LLDP, no CDP,
        no topology hints. Two commands total: ND (already done) + ARP
        full table (one extra command per link-local next-hop).
        """
        # Step 1: Get MAC from ND entry (already resolved)
        nd_entry = resolution.arp_entry
        if nd_entry and nd_entry.mac and nd_entry.mac.address:
            target_mac = nd_entry.mac.address
            logger.debug(
                f"[{hostname}] Link-local {nh_addr} → MAC {target_mac} (from ND)"
            )
        else:
            # Fallback: derive MAC from EUI-64 link-local encoding
            eui64_mac = self._mac_from_eui64(nh_addr)
            if eui64_mac:
                logger.info(
                    f"[{hostname}] ND empty for {nh_addr} — derived MAC "
                    f"{eui64_mac} from EUI-64 encoding"
                )
                target_mac = eui64_mac
                # Populate the resolution entry so downstream reporting works
                resolution.arp_entry = ArpEntry(
                    ip_address=nh_addr,
                    mac=MacAddress(address=eui64_mac),
                    interface=nh_intf,
                    state=ArpState.RESOLVED,
                )
            else:
                logger.warning(
                    f"[{hostname}] ND lookup failed for {nh_addr} and address "
                    f"is not EUI-64 — no MAC available"
                )
                return None

        # Step 2: Fetch full ARP table and search by MAC
        # Junos: show_arp is already unfiltered ("show arp no-resolve")
        # EOS/IOS/NX-OS: strip the {next_hop} placeholder to get full table
        arp_base_cmd = commands.show_arp
        if '{next_hop}' in arp_base_cmd:
            arp_base_cmd = arp_base_cmd.split('{')[0].strip()
        if json_suffix:
            arp_base_cmd += json_suffix

        arp_full_output = self._execute_command(client, arp_base_cmd)
        arp_mac_parser = get_parser(platform, PARSE_ARP_BY_MAC)

        if not arp_mac_parser:
            logger.warning(
                f"[{hostname}] No ARP-by-MAC parser for {platform.value}"
            )
            return None

        arp_match, arp_mac_record = parse_with_diagnostics(
            device=hostname, platform=platform.value,
            command=arp_base_cmd, raw_output=arp_full_output,
            parser_func=lambda raw, _mac=target_mac: arp_mac_parser(raw, _mac),
            parser_name=f"{get_parser_name(platform, PARSE_ARP_BY_MAC)}/mac-search",
            logger=logger,
        )
        hop_diag.commands.append(arp_mac_record)

        if arp_match and arp_match.ip_address:
            resolved_v4 = arp_match.ip_address
            logger.info(
                f"[{hostname}] Link-local resolved: "
                f"{nh_addr} → MAC {target_mac} → {resolved_v4}"
            )
            return resolved_v4

        logger.warning(
            f"[{hostname}] MAC {target_mac} (from ND for {nh_addr}) "
            f"not found in ARP table"
        )
        return None

    # ────────────────────────────────────────────
    # Neighbor Discovery Fallback (LLDP → CDP → DNS)
    # ────────────────────────────────────────────

    def _resolve_via_neighbors(self, item: QueueItem) -> Optional[str]:
        """
        When direct SSH to a FIB next-hop fails, use neighbor discovery
        on the parent device to find a reachable management address.

        Fallback cascade:
            1. LLDP on parent's egress interface → management address
            2. CDP on parent's egress interface → management address
            3. LLDP/CDP system name → DNS (with optional domain suffix)

        Requires a cached connection to the parent device and the
        egress interface name (both carried on the QueueItem).
        """
        parent_client = self._connections.get(item.parent_hostname)
        if not parent_client:
            logger.debug(
                f"No cached connection to parent {item.parent_hostname} "
                f"for neighbor discovery"
            )
            return None

        parent_identity = self._identity_cache.get(item.parent_hostname)
        if not parent_identity:
            return None

        platform = parent_identity.platform
        interface = item.parent_interface

        logger.info(
            f"[{item.parent_hostname}] Neighbor discovery for "
            f"{item.ssh_target} via {interface} "
            f"(platform: {platform.value})"
        )

        # ── Try LLDP ──
        neighbor = self._query_neighbor_protocol(
            parent_client, platform, item.parent_hostname,
            interface, protocol="lldp",
        )

        # ── Try CDP if LLDP didn't produce results ──
        if neighbor is None:
            neighbor = self._query_neighbor_protocol(
                parent_client, platform, item.parent_hostname,
                interface, protocol="cdp",
            )

        if neighbor is None:
            logger.info(
                f"[{item.parent_hostname}] No LLDP/CDP neighbor on {interface}"
            )
            return None

        # ── Layer 1: Management address from neighbor discovery ──
        if neighbor.management_address:
            self._progress(
                f"  ↪ {neighbor.source.upper()}: "
                f"{neighbor.system_name or '?'} → {neighbor.management_address}"
            )
            return neighbor.management_address

        # ── Layer 2: DNS resolution on system name ──
        if neighbor.system_name:
            self._progress(
                f"  ↪ {neighbor.source.upper()}: "
                f"{neighbor.system_name} (resolving DNS...)",
                end=""
            )
            resolved = self._resolve_hostname_dns(neighbor.system_name)
            if resolved:
                self._progress(f" {resolved}")
                return resolved
            self._progress(" failed")

        logger.warning(
            f"[{item.parent_hostname}] Neighbor discovery found "
            f"{neighbor.source.upper()} neighbor "
            f"'{neighbor.system_name or '(unnamed)'}' on {interface} "
            f"but no reachable address"
        )
        return None

    @staticmethod
    def _strip_subinterface(interface: str) -> str:
        """ae0.0 → ae0, GigabitEthernet0/0.100 → GigabitEthernet0/0"""
        if '.' in interface:
            base, unit = interface.rsplit('.', 1)
            if unit.isdigit():
                return base
        return interface

    def _query_neighbor_protocol(
        self, client: SSHClient, platform: Platform,
        hostname: str, interface: str, protocol: str = "lldp",
    ) -> Optional[NeighborInfo]:
        """
        Run LLDP or CDP on the given interface.

        Sequence:
            1. Strip subinterface unit (ae0.0 → ae0)
            2. Try per-interface detail query (works on some platforms for LAGs)
            3. If empty and interface is a LAG, try full table with pipe filter

        LLDP/CDP commands never get JSON/XML suffixes — text-only parsing.
        """
        import re

        if protocol == "lldp":
            cmd_map = _LLDP_COMMANDS
            lag_cmd_map = _LLDP_LAG_COMMANDS
        elif protocol == "cdp":
            cmd_map = _CDP_COMMANDS
            lag_cmd_map = _CDP_LAG_COMMANDS
        else:
            return None

        bare_intf = self._strip_subinterface(interface)
        is_lag = bool(_LAG_PATTERN.match(bare_intf))

        # ── Try 1: per-interface detail query ──
        cmd_template = cmd_map.get(platform)
        if cmd_template:
            cmd = cmd_template.format(interface=bare_intf)
            logger.info(
                f"[{hostname}] {protocol.upper()} try 1: {cmd}"
            )
            output = self._execute_command(
                client, cmd, timeout=self.config.command_timeout,
            )
            # Strip command echo and prompts — look for actual content
            content = output.strip() if output else ""
            logger.info(
                f"[{hostname}] {protocol.upper()} try 1 result: "
                f"{len(content)} chars"
            )
            if content:
                result = self._parse_neighbor_detail(content, protocol)
                if result:
                    logger.info(
                        f"[{hostname}] {protocol.upper()} per-interface hit: "
                        f"name={result.system_name} ip={result.management_address}"
                    )
                    return result

        # ── Try 2: LAG table filter (ae, Port-Channel, etc.) ──
        if is_lag:
            lag_template = lag_cmd_map.get(platform)
            if lag_template:
                lag_cmd = lag_template.format(lag=bare_intf)
                logger.info(
                    f"[{hostname}] {protocol.upper()} try 2 (LAG): {lag_cmd}"
                )
                lag_output = self._execute_command(
                    client, lag_cmd, timeout=self.config.command_timeout,
                )
                content = lag_output.strip() if lag_output else ""
                logger.info(
                    f"[{hostname}] {protocol.upper()} try 2 result: "
                    f"{len(content)} chars"
                )
                if content:
                    result = self._parse_neighbor_brief(content, protocol)
                    if result:
                        logger.info(
                            f"[{hostname}] {protocol.upper()} LAG filter hit: "
                            f"name={result.system_name} "
                            f"ip={result.management_address}"
                        )
                        return result
            else:
                logger.info(
                    f"[{hostname}] No {protocol.upper()} LAG command "
                    f"for {platform.value}"
                )
        else:
            logger.info(
                f"[{hostname}] {bare_intf} is not a LAG, "
                f"skipping table filter"
            )

        logger.info(
            f"[{hostname}] {protocol.upper()} found nothing on {interface}"
        )
        return None

    @staticmethod
    def _extract_ipv4(text: str) -> Optional[str]:
        """
        Find the first real IPv4 address in text, ignoring OIDs.

        OIDs like 1.3.6.1.2.1.31 have more than 4 dotted segments.
        We require exactly 4 octets (0-255) not embedded in a longer
        dotted sequence.
        """
        import re
        # Match 4 octets NOT preceded or followed by dot+digit
        for m in re.finditer(
            r"(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![.\d])",
            text,
        ):
            octets = m.group(1).split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                return m.group(1)
        return None

    @staticmethod
    def _parse_neighbor_detail(output: str, protocol: str) -> Optional[NeighborInfo]:
        """
        Parse detail-format LLDP/CDP output.
        Looks for labeled fields (System Name:, Device ID:, etc.)
        and management IP specifically from labeled fields — NOT any
        random IP in the output (detail has OIDs, capability codes,
        and other numeric fields that look like IPs).
        """
        import re

        if not output:
            return None

        system_name = None
        for pattern in (
            r"System Name\s*:\s*(\S+)",   # IOS, EOS, NX-OS LLDP
            r"Device ID\s*:\s*(\S+)",      # CDP
            r"SysName\s*:\s*(\S+)",        # Junos
        ):
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                system_name = m.group(1).strip().rstrip(',')
                break

        # Only extract IPs from management-labeled lines
        mgmt_addr = None
        for pattern in (
            r"Management [Aa]ddress(?:es)?\s*[:\-]\s*(\d+\.\d+\.\d+\.\d+)",
            r"IP [Aa]ddress\s*:\s*(\d+\.\d+\.\d+\.\d+)",
            r"Address\s*:\s*(\d+\.\d+\.\d+\.\d+)",
        ):
            m = re.search(pattern, output)
            if m:
                candidate = m.group(1)
                octets = candidate.split('.')
                if all(0 <= int(o) <= 255 for o in octets):
                    mgmt_addr = candidate
                    break

        if not system_name and not mgmt_addr:
            return None

        return NeighborInfo(
            system_name=system_name,
            management_address=mgmt_addr,
            source=protocol,
        )

    @staticmethod
    def _parse_neighbor_brief(output: str, protocol: str) -> Optional[NeighborInfo]:
        """
        Parse brief-format LLDP/CDP table lines.

        Junos brief:
          et-0/0/50  ae0  08:05:e2:13:fe:40  INT::... edge1-01.iad1.kentik.com

        IOS/EOS/NX-OS brief:
          edge1-01.iad1    Gi0/1    120    B,R    Gi0/2

        System name is the last field (Junos) or first field (IOS/CDP).
        We grab both candidates and pick the one that looks like a hostname.
        Any IPv4 address in the output is a bonus.
        """
        import re

        if not output:
            return None

        # Collect candidate names from all non-empty lines
        # Skip obvious header/separator lines
        candidates = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('-') or 'Local' in line and 'Interface' in line:
                continue
            fields = line.split()
            if len(fields) >= 2:
                candidates.add(fields[-1])    # last field (Junos system name)
                candidates.add(fields[0])     # first field (IOS/CDP device ID)

        # Pick the best candidate: prefer FQDN, then anything with a dot,
        # then anything alphanumeric that isn't a MAC or chassis ID
        mac_pattern = re.compile(r"^([0-9a-f]{2}[:\-.]){2,}", re.IGNORECASE)
        system_name = None
        for candidate in sorted(candidates, key=lambda c: -c.count('.')):
            if mac_pattern.match(candidate):
                continue
            if re.match(r"^[a-zA-Z]", candidate):
                system_name = candidate.rstrip(',')
                break

        mgmt_addr = ChainWalker._extract_ipv4(output)

        if not system_name and not mgmt_addr:
            return None

        return NeighborInfo(
            system_name=system_name,
            management_address=mgmt_addr,
            source=protocol,
        )

    def _resolve_hostname_dns(self, system_name: str) -> Optional[str]:
        """
        Resolve a neighbor system name to an IP via DNS.

        Tries in order:
            1. {system_name} as-is (if it looks like an FQDN already)
            2. {system_name}.{dns_domain}  (if --domain configured
               and name doesn't already end with the domain)
            3. {system_name} bare (relies on search domain)

        Returns IPv4 address string or None.
        """
        clean_name = system_name.rstrip('.')
        domain = self.config.dns_domain

        candidates = []

        # If name already looks fully qualified, try it first
        already_qualified = (
            domain and clean_name.lower().endswith(f".{domain.lower()}")
        )
        if already_qualified or clean_name.count('.') >= 2:
            candidates.append(clean_name)

        # Append domain if configured and not already present
        if domain and not already_qualified:
            candidates.append(f"{clean_name}.{domain}")

        # Always try bare name as final fallback
        if clean_name not in candidates:
            candidates.append(clean_name)

        for name in candidates:
            try:
                results = socket.getaddrinfo(
                    name, None, socket.AF_INET, socket.SOCK_STREAM,
                )
                if results:
                    ip = results[0][4][0]
                    logger.info(f"DNS resolved: {name} → {ip}")
                    return ip
            except socket.gaierror:
                logger.debug(f"DNS lookup failed: {name}")
                continue
            except Exception as e:
                logger.debug(f"DNS error for {name}: {e}")
                continue

        return None

    # ────────────────────────────────────────────
    # Verdict Assessment
    # ────────────────────────────────────────────

    def _assess_verdict(self, route, fib, resolutions
                        ) -> tuple[HopVerdict, str, list[str]]:
        """
        Walk the four questions. Short-circuit at structural failures.

        IMPORTANT: Interface errors are informational — they never stop the walk.
        The trace always continues to the next hop. The verdict truth table:

            route?  fib?       nh?    link?  → verdict
            ─────   ────       ────   ─────  ─────────
            no      -          -      -      → NO_ROUTE
            yes     drop       -      -      → BLACKHOLE
            yes     !fwd       -      -      → RIB_ONLY (genuine FIB miss)
            yes     unverified yes    up     → HEALTHY (parser gap — note added)
            yes     yes        no     -      → INCOMPLETE_ARP (walk continues!)
            yes     yes        yes    down   → INTERFACE_DOWN (walk continues!)
            yes     yes        yes    errs   → INTERFACE_ERRORS (walk continues!)
            yes     yes        yes    up     → HEALTHY
        """
        notes = []

        if route is None:
            return HopVerdict.NO_ROUTE, "No RIB entry for prefix", notes

        if route.is_connected:
            return HopVerdict.HEALTHY, "Connected route — end of chain", notes

        # FIB checks — distinguish real problems from parser gaps.
        # A missing FIB entry might mean "parser couldn't handle this
        # platform's output" rather than "not programmed." Don't
        # short-circuit to RIB_ONLY — fall through and let NH/link
        # checks determine whether forwarding is actually working.
        fib_unverified = False
        if fib is None:
            notes.append("FIB entry not verified (parser gap or "
                         "platform limitation — not a forwarding failure)")
            fib_unverified = True
        elif fib.state == FibState.DROP:
            return HopVerdict.BLACKHOLE, "FIB entry is null/drop", notes
        elif fib.state == FibState.RECEIVE:
            return HopVerdict.HEALTHY, "Destined to this device (receive)", notes
        elif not fib.is_forwarding and fib.state != FibState.GLEAN:
            notes.append(f"FIB state is {fib.state.value} — not actively forwarding")
            return HopVerdict.RIB_ONLY, f"FIB state: {fib.state.value}", notes

        # Next-hop resolution checks
        if not resolutions:
            notes.append("No next-hops to resolve — possible parser gap")
            return HopVerdict.HEALTHY, "No next-hops (connected or parser gap)", notes

        all_resolved = True
        any_incomplete = False
        for res in resolutions:
            if not res.is_resolved:
                all_resolved = False
                if res.arp_entry and res.arp_entry.state == ArpState.INCOMPLETE:
                    any_incomplete = True

        if not all_resolved:
            detail = "Next-hop ARP/ND incomplete" if any_incomplete else "Next-hop not fully resolved"
            notes.append(detail)
            # STILL walk — the next hop might be reachable via another path
            # or the ARP might resolve during the trace
            return HopVerdict.INCOMPLETE_ARP, detail, notes

        # Interface health — INFORMATIONAL ONLY
        # Errors flag the verdict but NEVER stop the trace.
        # The walk always continues via next_device_ips.
        interface_issues = []
        for res in resolutions:
            intf = res.egress_interface
            if intf is None:
                continue

            # Interface down is serious but still doesn't stop the trace
            if intf.state in (InterfaceState.DOWN_DOWN, InterfaceState.ADMIN_DOWN):
                interface_issues.append(
                    (HopVerdict.INTERFACE_DOWN, f"{intf.name} is {intf.state.value}")
                )
                continue

            if intf.state == InterfaceState.UP_DOWN:
                interface_issues.append(
                    (HopVerdict.INTERFACE_DOWN, f"{intf.name} is up/down (line protocol)")
                )
                continue

            # Error counters — threshold-based
            if intf.counters:
                c = intf.counters
                total_errors = (
                    c.crc_errors + c.in_errors + c.out_errors +
                    c.in_discards + c.out_discards
                )
                threshold = self.config.interface_error_threshold

                if total_errors > 0:
                    error_detail = (
                        f"{intf.name}: {total_errors} total errors "
                        f"(CRC:{c.crc_errors} in:{c.in_errors} "
                        f"out:{c.out_errors} disc:{c.in_discards}/{c.out_discards})"
                    )
                    if total_errors > threshold:
                        interface_issues.append(
                            (HopVerdict.INTERFACE_ERRORS, error_detail)
                        )
                    else:
                        # Below threshold — note it but don't change verdict
                        notes.append(
                            f"Minor errors on {intf.name}: {total_errors} total "
                            f"(threshold: {threshold})"
                        )

        if interface_issues:
            # Pick the worst issue for the verdict
            for verdict, detail in interface_issues:
                if verdict == HopVerdict.INTERFACE_DOWN:
                    notes.append(detail)
                    return HopVerdict.INTERFACE_DOWN, detail, notes

            # All remaining are INTERFACE_ERRORS
            worst = interface_issues[0]
            notes.append(worst[1])
            return HopVerdict.INTERFACE_ERRORS, worst[1], notes

        if fib_unverified:
            return HopVerdict.HEALTHY, "Route → FIB (unverified) → resolved → link clean", notes
        return HopVerdict.HEALTHY, "Route → FIB → resolved → link clean", notes

    # ────────────────────────────────────────────
    # SSH Connection Management
    # ────────────────────────────────────────────

    def _connect(self, ssh_target: str) -> Optional[SSHClient]:
        """
        Establish SSH connection. Returns client or None.
        Connection is not cached yet — caching happens after we know the hostname.
        """
        # Quick check: do we already have a connection to this IP
        # via a known hostname?
        if ssh_target in self._ip_to_hostname:
            hostname = self._ip_to_hostname[ssh_target]
            if hostname in self._connections:
                logger.debug(f"Reusing connection: {ssh_target} → {hostname}")
                return self._connections[hostname]

        try:
            self._progress(f"  → connecting {ssh_target}...", end="")
            logger.debug(f"SSH connecting to {ssh_target}")

            config = SSHClientConfig(
                host=ssh_target,
                username=self.config.username,
                password=self.config.password,
                key_file=self.config.key_file,
                key_passphrase=self.config.key_passphrase,
                port=22,
                timeout=self.config.ssh_timeout,
                inter_command_time=self.config.inter_command_time,
                legacy_mode=self.config.legacy_ssh,
            )
            client = SSHClient(config)
            client.connect()
            client.find_prompt()
            client.disable_pagination()
            client.set_expect_prompt(client._detected_prompt)
            hostname = client.extract_hostname_from_prompt(
                client._detected_prompt or ""
            )
            self._progress(f" {hostname or 'ok'}")
            return client

        except Exception as e:
            self._progress(f" failed ({e})")
            logger.error(f"SSH failed to {ssh_target}: {e}")
            return None

    def _execute_command(self, client: SSHClient, command: str,
                         timeout: Optional[float] = None) -> str:
        """Execute a command and return raw output. Never raises."""
        try:
            output = client.execute_command(
                command, timeout=timeout or self.config.command_timeout
            )
            return output or ""
        except Exception as e:
            logger.error(f"Command failed: {command}: {e}")
            return ""

    def _release_connection(self, client: SSHClient, ssh_target: str):
        """Release a connection we don't need (loop detection, etc)."""
        if not self.config.keep_connections:
            try:
                client.disconnect()
            except Exception:
                pass

    def _cleanup_connections(self):
        """Close all cached SSH connections."""
        for hostname, client in self._connections.items():
            try:
                client.disconnect()
                logger.debug(f"Disconnected from {hostname}")
            except Exception as e:
                logger.debug(f"Disconnect error for {hostname}: {e}")
        self._connections.clear()

    # ────────────────────────────────────────────
    # Verdict/Diagnostic Helpers
    # ────────────────────────────────────────────

    def _build_verdict_record(self, hostname, prefix, verdict,
                              route_found=False, route_detail="",
                              fib_programmed=False, fib_detail="",
                              nh_resolved=False, nh_detail="",
                              link_healthy=False, link_detail="",
                              ) -> VerdictRecord:
        return VerdictRecord(
            device=hostname,
            prefix=prefix,
            verdict=verdict.value,
            route_found=route_found,
            route_detail=route_detail,
            fib_programmed=fib_programmed,
            fib_detail=fib_detail,
            nh_resolved=nh_resolved,
            nh_detail=nh_detail,
            link_healthy=link_healthy,
            link_detail=link_detail,
        )

    @staticmethod
    def _format_prefix_for_platform(prefix: str, platform: Platform) -> str:
        """
        Format a prefix string for a platform's CLI syntax.

        IPv4:
          IOS/IOS-XE: no CIDR notation. 'show ip route 10.0.0.1' for hosts,
                      'show ip route 10.0.0.0 255.255.255.0' for subnets.
          Junos:      bare IP for hosts, CIDR for subnets.
                      'show route 10.0.0.1' works, '10.0.0.1/32' does not.
          NX-OS:      CIDR works, but bare IP also works.
          EOS:        CIDR works fine.

        IPv6:
          IOS/IOS-XE: CIDR notation works for v6 (unlike v4 dotted-mask).
          Junos:      bare address for /128 host routes, CIDR otherwise.
          NX-OS/EOS:  CIDR works fine.
        """
        try:
            net = _parse_network(prefix)
        except ValueError:
            return prefix  # pass through, let the device error

        if isinstance(net, IPv6Network):
            # IPv6 formatting
            if platform == Platform.JUNIPER_JUNOS:
                if net.prefixlen == 128:
                    return str(net.network_address)
                return str(net)
            if platform == Platform.CISCO_IOS:
                # IOS 'show ipv6 cef' does NOT accept CIDR notation —
                # bare address triggers longest-match lookup, which is
                # what we want for both /128 hosts and subnet probes.
                return str(net.network_address)
            # EOS, NX-OS: CIDR works for v6
            return str(net)

        # IPv4 formatting (existing logic)
        if platform == Platform.CISCO_IOS:
            if net.prefixlen == 32:
                return str(net.network_address)
            else:
                return f"{net.network_address} {net.netmask}"

        if platform == Platform.JUNIPER_JUNOS:
            if net.prefixlen == 32:
                return str(net.network_address)
            return str(net)

        # EOS, NX-OS: CIDR notation works
        return str(net)

    @staticmethod
    def _summarize_route(route: Optional[RouteEntry]) -> str:
        if not route:
            return "none"
        nh_count = len(route.next_hops)
        proto = route.protocol.value
        if route.is_ecmp:
            return f"{proto}, {nh_count} ECMP paths"
        if route.next_hops:
            nh = route.next_hops[0]
            return f"{proto} via {nh.address or 'connected'} on {nh.interface or '?'}"
        return proto

    @staticmethod
    def _summarize_fib(fib: Optional[FibEntry]) -> str:
        if not fib:
            return "no FIB entry"
        state = fib.state.value
        nh_count = len(fib.next_hops)
        if fib.is_forwarding:
            return f"{state}, {nh_count} path(s)"
        return state

    # ────────────────────────────────────────────
    # Utility
    # ────────────────────────────────────────────

    def get_device_by_hostname(self, hostname: str) -> Optional[DeviceIdentity]:
        return self._identity_cache.get(hostname)

    def get_hostname_for_ip(self, ip: str) -> Optional[str]:
        return self._ip_to_hostname.get(ip)


# ============================================================
# CLI Entry Point
# ============================================================

def main():
    """
    fibtrace --prefix 10.0.0.0/24 --source 172.16.1.1 \\
             --username admin --password secret \\
             --log /tmp/fibtrace.json -v
    """
    import argparse
    import json as json_mod

    parser = argparse.ArgumentParser(
        description="Walk the forwarding chain for a prefix through the network.",
        epilog=(
            "Examples:\n"
            "  fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret\n"
            "  fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret -v\n"
            "  fibtrace -p 10.0.0.0/24 -s 172.16.1.1 -u admin --password secret "
            "--log /tmp/ft.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-p", "--prefix", required=True,
                        help="Target prefix (e.g., 10.0.0.0/24)")
    parser.add_argument("-s", "--source", required=True,
                        help="Source device IP to start the walk")

    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--key-file", default=None)

    parser.add_argument("--max-depth", type=int, default=15)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Per-command timeout in seconds")
    parser.add_argument("--legacy-ssh", action="store_true",
                        help="Enable legacy SSH ciphers/KEX")

    parser.add_argument("--error-threshold", type=int, default=100,
                        help="Interface error count threshold (default: 100)")
    parser.add_argument("--skip-mac", action="store_true",
                        help="Skip MAC table lookups")
    parser.add_argument("--domain", default=None,
                        help="DNS domain suffix for neighbor hostname resolution "
                             "(e.g., 'kentik.com' resolves 'edge03' as "
                             "'edge03.kentik.com')")

    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print per-hop summaries")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log", default=None,
                        help="Write full diagnostic JSON to file")
    parser.add_argument("--json", action="store_true",
                        help="Output chain result as JSON")

    args = parser.parse_args()

    # ── Validate inputs before we touch SSH ──
    # Prefix: must be a valid IPv4 or IPv6 network or host address
    prefix_str = args.prefix
    try:
        # If no mask, detect address family for default mask
        if '/' not in prefix_str:
            addr = _parse_ip(prefix_str)
            prefix_str += '/128' if isinstance(addr, IPv6Address) else '/32'
        _parse_network(prefix_str)
    except (ValueError, AddressValueError) as e:
        parser.error(f"Invalid prefix '{args.prefix}': {e}")

    # Source: must be a valid IPv4 or IPv6 address
    try:
        _parse_ip(args.source)
    except (ValueError, AddressValueError) as e:
        parser.error(f"Invalid source address '{args.source}': {e}")

    config = WalkerConfig(
        target_prefix=prefix_str,
        source_host=args.source,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        max_depth=args.max_depth,
        command_timeout=args.timeout,
        legacy_ssh=args.legacy_ssh,
        interface_error_threshold=args.error_threshold,
        skip_mac_lookup=args.skip_mac,
        dns_domain=args.domain,
        verbose=args.verbose,
        debug=args.debug,
        log_file=args.log,
    )

    walker = ChainWalker(config)
    chain = walker.walk()

    if args.json:
        # JSON output for scripting
        output = {
            "target_prefix": str(chain.target_prefix.network),
            "source_device": chain.source_device.hostname,
            "status": chain.status.value,
            "is_healthy": chain.is_healthy,
            "total_devices": chain.total_devices,
            "ecmp_branches": chain.ecmp_branch_points,
            "duration_seconds": chain.duration.total_seconds() if chain.duration else None,
            "hops": [
                {
                    "device": h.device.hostname,
                    "ip": str(h.device.ip_address),
                    "platform": h.device.platform or "unknown",
                    "verdict": h.verdict.value,
                    "is_terminal": h.is_terminal,
                    "next_hops": [str(ip) for ip in h.next_device_ips],
                    "notes": h.notes,
                    "parent": h.parent_hostname,
                    "depth": h.depth,
                    **({"converges_to": h.converges_to}
                       if h.converges_to else {}),
                }
                for h in chain.hops
            ],
            "anomalies": chain.anomalies,
        }
        print(json_mod.dumps(output, indent=2, default=str))
    else:
        # Human-readable summary
        print(f"\nfibtrace: {config.target_prefix} from "
              f"{chain.source_device.hostname}")
        print("─" * 50)

        for hop in chain.hops:
            v = hop.verdict

            # Convergence marker — not a real forwarding hop
            if v == HopVerdict.CONVERGENCE:
                conv_name = hop.converges_to or hop.device.hostname
                print(f"  hop {chain.hops.index(hop)}: {conv_name:20s} | "
                      f"↪ converges (visited via sibling ECMP branch)")
                continue

            checks = ""
            is_connected = (hop.is_terminal and hop.route
                            and hop.route.is_connected)

            if v == HopVerdict.UNREACHABLE:
                checks = "unreachable"
            elif is_connected:
                # Connected route — FIB/NH/link checks weren't run
                checks = "route ✓ fib — nh — link —"
            else:
                r = "✓" if hop.route else "✗"
                if hop.fib and hop.fib.is_forwarding:
                    f = "✓"
                elif hop.fib is None:
                    f = "?"
                else:
                    f = "✗"
                n = "✓" if hop.resolutions and all(
                    res.is_resolved for res in hop.resolutions) else "✗"
                # Link check
                link_ok = True
                if hop.resolutions:
                    for res in hop.resolutions:
                        if (res.egress_interface and
                                res.egress_interface.state != InterfaceState.UP_UP):
                            link_ok = False
                l = "✓" if link_ok else "✗"
                checks = f"route {r} fib {f} nh {n} link {l}"

            terminal = " (connected)" if is_connected else ""

            # Egress interface(s) — show where traffic leaves this hop
            egress = ""
            if hop.resolutions:
                intfs = []
                for i, res in enumerate(hop.resolutions):
                    if res.egress_interface:
                        nh_str = ""
                        if res.next_hop_ip:
                            if (isinstance(res.next_hop_ip, IPv6Address)
                                    and res.next_hop_ip.is_link_local):
                                # Show link-local truncated + resolved IPv4 target
                                ll_short = str(res.next_hop_ip)
                                # Find resolved target in next_device_ips
                                if i < len(hop.next_device_ips):
                                    resolved = hop.next_device_ips[i]
                                    nh_str = f"{ll_short} (→ {resolved})"
                                else:
                                    nh_str = f"{ll_short} (unresolved)"
                            else:
                                nh_str = str(res.next_hop_ip)
                        intfs.append(f"{res.egress_interface.name}"
                                     + (f" → {nh_str}" if nh_str else ""))
                if intfs:
                    egress = "  " + ", ".join(intfs)
            elif is_connected and hop.route and hop.route.next_hops:
                # Connected route — interface is on the route entry
                intf = hop.route.next_hops[0].interface
                if intf:
                    egress = f"  {intf}"

            print(f"  hop {chain.hops.index(hop)}: {hop.device.hostname:20s} | "
                  f"{checks} → {v.value.upper()}{terminal}{egress}")

        print("─" * 50)
        elapsed = f"{chain.duration.total_seconds():.1f}s" if chain.duration else "?"
        print(f"Status: {chain.status.value.upper()} | "
              f"{chain.total_devices} devices | "
              f"{chain.ecmp_branch_points} ECMP branches | "
              f"{elapsed}")

        if chain.anomalies:
            print(f"\nAnomalies:")
            for a in chain.anomalies:
                print(f"  ⚠ {a}")

        print()


if __name__ == "__main__":
    main()