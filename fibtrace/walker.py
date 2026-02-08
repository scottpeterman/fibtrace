"""
Forwarding Chain Walker — BFS tree traversal with hostname-based tracking.

Key change from v1: device identity comes from the CLI prompt, not the IP
we used to SSH in. Unnumbered interfaces, shared transits, and management
IPs that don't match the forwarding plane all make IP a poor unique identifier.
The hostname in the prompt IS the device identity.

Sequence per hop:
    1. SSH to IP from queue
    2. find_prompt() → extract_hostname_from_prompt()
    3. Check visited set (by hostname) — loop?
    4. If new: fingerprint, gather, assess, enqueue next-hops
    5. If seen: already visited this box via different IP, skip

The one cost: loop detection is post-connection, not pre-connection.
We burn one SSH handshake to discover we've been here before.
Acceptable for chains of 3-15 devices.

          source
          /    \\          ← ECMP: two different next-hop IPs
       spine1  spine2       but spine1# and spine2# are unique
        /        |  \\
     leaf1    leaf2  leaf3
       \\       /
        spine1              ← same hostname! loop detected, skip
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
import time

from .models import (
    Prefix, AddressFamily, DeviceInfo, Hop, HopVerdict, ForwardingChain, ChainStatus,
    RouteEntry, RouteProtocol, FibEntry, FibState, FibNextHop,
    NextHopResolution, ArpState, InterfaceState,
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

logger = logging.getLogger("fibtrace")


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
    ssh_timeout: int = 30
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
                    notes=[f"SSH connection failed to {item.ssh_target}"],
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
                hop_index += 1
                continue

            # ── 2. Identify — this is the moment of truth ──
            identity = self._identify_device(client, item.ssh_target)

            if identity is None:
                logger.error(f"Cannot identify device at {item.ssh_target}")
                self._release_connection(client, item.ssh_target)
                hop_index += 1
                continue

            # ── 3. Loop detection BY HOSTNAME ──
            if identity.hostname in self._visited:
                logger.warning(
                    f"Loop detected: {item.ssh_target} is {identity.hostname} "
                    f"(already visited)"
                )
                self._release_connection(client, item.ssh_target)
                loop_detected = True
                self._chain.anomalies.append(
                    f"Loop: reached {identity.hostname} again via "
                    f"{item.ssh_target} (parent: {item.parent_hostname})"
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

            # ── 5. Gather forwarding state ──
            hop, hop_diag = self._gather_forwarding_state(
                client, identity, hop_index
            )

            # Attach fingerprint to diagnostics
            if hop_diag and fp_record:
                hop_diag.fingerprint = fp_record

            # Add to chain and diagnostics
            if hop is not None:
                self._chain.hops.append(hop)
            if hop_diag is not None:
                self._diagnostics.hops.append(hop_diag)

            hop_index += 1

            # ── 6. Report progress ──
            if self.config.verbose and hop_diag:
                print(dump_hop_summary(hop_diag))

            # ── 7. Check terminal ──
            if hop is None or hop.is_terminal:
                logger.info(f"Terminal hop at {identity.hostname}")
                continue

            # ── 8. Enqueue next-hop devices (ECMP fan-out) ──
            for next_ip in hop.next_device_ips:
                queue.append(QueueItem(
                    ssh_target=str(next_ip),
                    depth=item.depth + 1,
                    parent_hostname=identity.hostname,
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
        """
        prompt = client._detected_prompt or ""
        hostname = client.extract_hostname_from_prompt(prompt)

        if not hostname:
            logger.warning(
                f"Cannot extract hostname from prompt on {ssh_target}, "
                f"prompt was: {prompt!r}"
            )
            hostname = f"unknown-{ssh_target}"

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

        # No route → terminal, NO_ROUTE verdict
        if route_entry is None:
            verdict = HopVerdict.NO_ROUTE
            hop = Hop(
                device=device_info,
                target_prefix=self._chain.target_prefix,
                route=None,
                verdict=verdict,
                notes=["No RIB entry for prefix"],
            )
            hop_diag.verdict = self._build_verdict_record(
                hostname, prefix, verdict,
                route_detail="No RIB entry",
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
        if is_v6 and commands.show_fib_v6:
            fib_cmd = commands.show_fib_v6.format(prefix=cli_prefix)
        else:
            fib_cmd = commands.show_fib.format(prefix=cli_prefix)
        if json_suffix:
            fib_cmd += json_suffix

        fib_output = self._execute_command(client, fib_cmd)
        fib_parser = get_parser(platform, PARSE_FIB)
        fib_entry = None

        if fib_parser:
            fib_entry, fib_record = parse_with_diagnostics(
                device=hostname, platform=platform.value,
                command=fib_cmd, raw_output=fib_output,
                parser_func=lambda raw: fib_parser(raw, prefix),
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

        hop_diag.verdict = self._build_verdict_record(
            hostname, prefix, verdict,
            route_found=True,
            route_detail=self._summarize_route(route_entry),
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

        The ND lookup was already done in the resolution loop — the MAC
        is on resolution.arp_entry. We just need to search the ARP table
        for a matching MAC to get the corresponding IPv4 address.

        Uses data the walker is already collecting — no LLDP, no CDP,
        no topology hints. Two commands total: ND (already done) + ARP
        full table (one extra command per link-local next-hop).
        """
        # Step 1: Get MAC from ND entry (already resolved)
        nd_entry = resolution.arp_entry
        if not nd_entry or not nd_entry.mac or not nd_entry.mac.address:
            logger.warning(
                f"[{hostname}] ND lookup failed for {nh_addr} — no MAC available"
            )
            return None

        target_mac = nd_entry.mac.address
        logger.debug(
            f"[{hostname}] Link-local {nh_addr} → MAC {target_mac}, "
            f"searching ARP table..."
        )

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
    # Verdict Assessment
    # ────────────────────────────────────────────

    def _assess_verdict(self, route, fib, resolutions
                        ) -> tuple[HopVerdict, str, list[str]]:
        """
        Walk the four questions. Short-circuit at structural failures.

        IMPORTANT: Interface errors are informational — they never stop the walk.
        The trace always continues to the next hop. The verdict truth table:

            route?  fib?   nh?    link?  → verdict
            ─────   ────   ────   ─────  ─────────
            no      -      -      -      → NO_ROUTE
            yes     drop   -      -      → BLACKHOLE
            yes     no     -      -      → RIB_ONLY
            yes     yes    no     -      → INCOMPLETE_ARP (walk continues!)
            yes     yes    yes    down   → INTERFACE_DOWN (walk continues!)
            yes     yes    yes    errs   → INTERFACE_ERRORS (walk continues!)
            yes     yes    yes    up     → HEALTHY
        """
        notes = []

        if route is None:
            return HopVerdict.NO_ROUTE, "No RIB entry for prefix", notes

        if route.is_connected:
            return HopVerdict.HEALTHY, "Connected route — end of chain", notes

        # FIB checks
        if fib is None:
            notes.append("Route in RIB but no FIB entry found — "
                         "may be a parser issue or genuinely not programmed")
            return HopVerdict.RIB_ONLY, "Route in RIB but no FIB entry", notes

        if fib.state == FibState.DROP:
            return HopVerdict.BLACKHOLE, "FIB entry is null/drop", notes

        if fib.state == FibState.RECEIVE:
            return HopVerdict.HEALTHY, "Destined to this device (receive)", notes

        if not fib.is_forwarding and fib.state != FibState.GLEAN:
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
            return client

        except Exception as e:
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
            # IOS, EOS, NX-OS: CIDR works for v6
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
                f = "✓" if (hop.fib and hop.fib.is_forwarding) else "✗"
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