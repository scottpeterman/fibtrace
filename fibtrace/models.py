"""
Forwarding Chain Validator — Core Data Models (v2)
Vendor-neutral. Forwarding-plane only. Underlay-first.

The question at every hop:
  Is there a route? → Is it in the FIB? → Is the next-hop resolved? → Is the link healthy?
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address


# ============================================================
# Address & Prefix
# ============================================================

class AddressFamily(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass
class Prefix:
    network: IPv4Network | IPv6Network
    family: AddressFamily = field(init=False)

    def __post_init__(self):
        self.family = (
            AddressFamily.IPV4 if isinstance(self.network, IPv4Network)
            else AddressFamily.IPV6
        )


@dataclass
class MacAddress:
    address: str                        # normalized aa:bb:cc:dd:ee:ff
    vendor_oui: Optional[str] = None    # OUI lookup for sanity checks


# ============================================================
# L2 — Link-Layer Resolution
# ============================================================

class L2Type(Enum):
    ETHERNET = "ethernet"
    POINT_TO_POINT = "point-to-point"
    LOOPBACK = "loopback"
    VIRTUAL = "virtual"                 # SVI, IRB, BVI


class ArpState(Enum):
    RESOLVED = "resolved"
    INCOMPLETE = "incomplete"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass
class ArpEntry:
    """ARP (v4) or ND (v6) neighbor resolution."""
    ip_address: IPv4Address | IPv6Address
    mac: Optional[MacAddress] = None
    state: ArpState = ArpState.UNKNOWN
    age: Optional[timedelta] = None
    interface: Optional[str] = None
    vlan: Optional[int] = None


@dataclass
class MacTableEntry:
    """CAM table — where does this MAC physically live?"""
    mac: MacAddress
    vlan: Optional[int] = None
    interface: str = ""
    entry_type: str = "dynamic"         # dynamic, static
    age: Optional[timedelta] = None


# ============================================================
# Interface
# ============================================================

class InterfaceState(Enum):
    UP_UP = "up/up"
    UP_DOWN = "up/down"
    DOWN_DOWN = "down/down"
    ADMIN_DOWN = "admin-down"
    UNKNOWN = "unknown"


@dataclass
class InterfaceCounters:
    """Egress link health — errors, discards, drops."""
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    crc_errors: int = 0
    input_queue_drops: int = 0
    output_queue_drops: int = 0
    sample_time: Optional[datetime] = None


@dataclass
class Interface:
    name: str
    state: InterfaceState = InterfaceState.UNKNOWN
    l2_type: L2Type = L2Type.ETHERNET
    speed_mbps: Optional[int] = None
    mtu: Optional[int] = None
    description: Optional[str] = None
    ip_addresses: list[IPv4Address | IPv6Address] = field(default_factory=list)
    counters: Optional[InterfaceCounters] = None
    lag_member_of: Optional[str] = None
    lag_members: list[str] = field(default_factory=list)


# ============================================================
# Encapsulation — what's wrapped around the packet at this hop
# ============================================================

class EncapType(Enum):
    NONE = "none"
    MPLS = "mpls"
    GRE = "gre"
    VXLAN = "vxlan"
    IPSEC = "ipsec"
    GENEVE = "geneve"


@dataclass
class MplsLabel:
    """A single label in the stack. Don't care why — LDP, SR, RSVP, whatever."""
    label: int
    operation: str = "push"             # push, swap, pop
    exp: int = 0
    ttl: Optional[int] = None
    bottom_of_stack: bool = False


@dataclass
class MplsLabelStack:
    labels: list[MplsLabel] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.labels)


@dataclass
class VxlanHeader:
    vni: int
    source_vtep: Optional[IPv4Address] = None
    destination_vtep: Optional[IPv4Address] = None


@dataclass
class Encapsulation:
    encap_type: EncapType = EncapType.NONE
    mpls_stack: Optional[MplsLabelStack] = None
    vxlan: Optional[VxlanHeader] = None


# ============================================================
# Route — does the box know where to send this prefix?
# ============================================================

class RouteProtocol(Enum):
    """Lightweight — just enough to distinguish connected from routed."""
    CONNECTED = "connected"
    STATIC = "static"
    DYNAMIC = "dynamic"                 # OSPF, BGP, ISIS, EIGRP — doesn't matter
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass
class RouteNextHop:
    address: Optional[IPv4Address | IPv6Address] = None  # None for connected
    interface: Optional[str] = None
    weight: int = 1                     # ECMP / UCMP weight
    is_recursive: bool = False
    resolving_route: Optional[Prefix] = None
    label_stack: Optional[MplsLabelStack] = None


@dataclass
class RouteEntry:
    """RIB entry. The box picked a winner — we just record what it picked."""
    prefix: Prefix
    protocol: RouteProtocol = RouteProtocol.UNKNOWN
    next_hops: list[RouteNextHop] = field(default_factory=list)

    @property
    def is_ecmp(self) -> bool:
        return len(self.next_hops) > 1

    @property
    def is_connected(self) -> bool:
        return self.protocol == RouteProtocol.CONNECTED


# ============================================================
# FIB — is it actually programmed for forwarding?
# ============================================================

class FibState(Enum):
    PROGRAMMED = "programmed"
    NOT_PROGRAMMED = "not-programmed"
    GLEAN = "glean"                     # connected, punt for ARP
    DROP = "drop"                       # null route / blackhole
    RECEIVE = "receive"                 # destined to this device
    UNKNOWN = "unknown"


@dataclass
class FibNextHop:
    address: Optional[IPv4Address | IPv6Address] = None
    interface: Optional[str] = None
    weight: int = 1
    encapsulation: Encapsulation = field(default_factory=Encapsulation)


@dataclass
class FibEntry:
    """What the hardware actually does with this prefix."""
    prefix: Prefix
    state: FibState = FibState.UNKNOWN
    next_hops: list[FibNextHop] = field(default_factory=list)
    resolved: bool = False

    @property
    def is_ecmp(self) -> bool:
        return len(self.next_hops) > 1

    @property
    def is_forwarding(self) -> bool:
        return self.state == FibState.PROGRAMMED and len(self.next_hops) > 0


# ============================================================
# Next-Hop Resolution — L3 → L2 → egress
# ============================================================

@dataclass
class NextHopResolution:
    """The full resolution chain for a single next-hop."""
    next_hop_ip: Optional[IPv4Address | IPv6Address] = None
    arp_entry: Optional[ArpEntry] = None
    mac_entry: Optional[MacTableEntry] = None
    egress_interface: Optional[Interface] = None
    encapsulation: Encapsulation = field(default_factory=Encapsulation)

    @property
    def is_resolved(self) -> bool:
        if self.encapsulation.encap_type == EncapType.MPLS:
            return self.egress_interface is not None
        return (
            self.arp_entry is not None
            and self.arp_entry.state == ArpState.RESOLVED
            and self.egress_interface is not None
        )


# ============================================================
# Hop — composite result at a single device
# ============================================================

@dataclass
class DeviceInfo:
    hostname: str
    ip_address: IPv4Address | IPv6Address
    platform: Optional[str] = None      # "cisco_ios", "arista_eos", etc.
    vendor: Optional[str] = None
    model: Optional[str] = None


class HopVerdict(Enum):
    """What's the forwarding health at this hop?"""
    HEALTHY = "healthy"
    RIB_ONLY = "rib-only"              # route exists, not in FIB
    NO_ROUTE = "no-route"
    BLACKHOLE = "blackhole"
    INCOMPLETE_ARP = "incomplete-arp"
    INTERFACE_DOWN = "interface-down"
    INTERFACE_ERRORS = "interface-errors"
    UNREACHABLE = "unreachable"         # couldn't reach the device
    UNKNOWN = "unknown"


@dataclass
class Hop:
    """
    Everything we know about forwarding at a single device.
    The fundamental unit of the chain walk.
    """
    device: DeviceInfo
    target_prefix: Prefix
    timestamp: datetime = field(default_factory=datetime.now)

    # The four questions
    route: Optional[RouteEntry] = None          # 1. Is there a route?
    fib: Optional[FibEntry] = None              # 2. Is it in the FIB?
    resolutions: list[NextHopResolution] = field(default_factory=list)  # 3. Next-hop resolved?
    # 4. Link healthy? — lives on resolution.egress_interface.counters

    # Assessment
    verdict: HopVerdict = HopVerdict.UNKNOWN
    notes: list[str] = field(default_factory=list)

    # Where does the chain go next? (multiple = ECMP branch)
    next_device_ips: list[IPv4Address | IPv6Address] = field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        if self.route and self.route.is_connected:
            return True
        if self.fib and self.fib.state in (FibState.DROP, FibState.RECEIVE):
            return True
        return not self.next_device_ips


# ============================================================
# Chain — the full walk
# ============================================================

class ChainStatus(Enum):
    COMPLETE = "complete"
    BROKEN = "broken"
    LOOP = "loop"
    PARTIAL = "partial"                 # max hops or device unreachable
    IN_PROGRESS = "in-progress"


@dataclass
class ForwardingChain:
    """
    The complete result of walking a prefix through the network.
    A tree — ECMP branches at any hop.
    """
    target_prefix: Prefix
    source_device: DeviceInfo
    hops: list[Hop] = field(default_factory=list)
    status: ChainStatus = ChainStatus.IN_PROGRESS
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_devices: int = 0
    ecmp_branch_points: int = 0
    anomalies: list[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return (
            self.status == ChainStatus.COMPLETE
            and all(h.verdict == HopVerdict.HEALTHY for h in self.hops)
        )

    @property
    def duration(self) -> Optional[timedelta]:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None