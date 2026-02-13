"""
fibtrace — Hop-by-hop forwarding chain validation from the device perspective.

Not a traceroute — a FIB trace.
"""

__version__ = "0.1.0"

from .models import (
    Prefix, AddressFamily,
    RouteEntry, RouteProtocol, RouteNextHop,
    FibEntry, FibState, FibNextHop,
    ArpEntry, ArpState, MacTableEntry, MacAddress,
    Interface, InterfaceState, InterfaceCounters,
    NextHopResolution,
    DeviceInfo, Hop, HopVerdict,
    ForwardingChain, ChainStatus,
    Encapsulation, EncapType, MplsLabelStack,
)

from .commands_and_parsers import Platform
from .walker import ChainWalker, WalkerConfig
from .diagnostics import ChainDiagnostic, HopDiagnostic