"""
Shared event types for walker ↔ TUI communication.

This module defines the HopEvent dataclass that the walker emits and
the TUI consumes. Neither side imports the other — this is the only
shared dependency.

Usage (walker side):
    from .events import HopEvent, TuiVerdict
    callback(HopEvent(event="hop_done", device="spine-1", ...))

Usage (TUI side):
    from .events import HopEvent, TuiVerdict, LogLevel
    for evt in event_stream:
        process(evt)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class TuiVerdict(Enum):
    """Verdict icons for tree display. Maps 1:1 to walker's HopVerdict."""
    HEALTHY = "healthy"
    HEALTHY_CONNECTED = "healthy_connected"
    NO_ROUTE = "no_route"
    BLACKHOLE = "blackhole"
    RIB_ONLY = "rib_only"
    INCOMPLETE_ARP = "incomplete_arp"
    INTERFACE_DOWN = "interface_down"
    INTERFACE_ERRORS = "interface_errors"
    UNREACHABLE = "unreachable"
    CONVERGENCE = "convergence"


# Verdict → (color, icon) for the tree pane
VERDICT_STYLE: dict[TuiVerdict, tuple[str, str]] = {
    TuiVerdict.HEALTHY:           ("#00ff88", "✓"),
    TuiVerdict.HEALTHY_CONNECTED: ("#00ff88", "✓"),
    TuiVerdict.NO_ROUTE:          ("#ff4444", "✗"),
    TuiVerdict.BLACKHOLE:         ("#ff4444", "⊘"),
    TuiVerdict.RIB_ONLY:          ("#ffcc00", "⚠"),
    TuiVerdict.INCOMPLETE_ARP:    ("#ffcc00", "⚠"),
    TuiVerdict.INTERFACE_DOWN:    ("#ff4444", "▼"),
    TuiVerdict.INTERFACE_ERRORS:  ("#ff8800", "⚠"),
    TuiVerdict.UNREACHABLE:       ("#ff4444", "✗"),
    TuiVerdict.CONVERGENCE:       ("#00d4ff", "↪"),
}


class LogLevel(Enum):
    BASIC = "basic"
    VERBOSE = "verbose"
    DEBUG = "debug"


@dataclass
class HopEvent:
    """
    One event from the walker to the TUI.

    Events:
        hop_start   — SSH connected, device identified, about to probe
        hop_done    — forwarding state gathered, verdict assigned
        trace_done  — BFS walk complete, final summary

    The walker emits these via a callback; the TUI consumes them.
    Log lines use Rich markup for coloring.
    """
    event: str                          # "hop_start", "hop_done", "trace_done"

    # Device context (hop_start / hop_done)
    device: str = ""                    # hostname from CLI prompt
    ip: str = ""                        # SSH target IP
    parent_device: Optional[str] = None # parent hostname (for tree placement)
    platform: str = ""                  # e.g. "cisco_ios", "arista_eos"

    # Verdict (hop_done only)
    verdict: Optional[TuiVerdict] = None
    checks: str = ""                    # "route ✓ fib ✓ nh ✓ link ✓"
    egress: str = ""                    # "Ethernet1 → 172.16.1.5"
    notes: list[str] = field(default_factory=list)

    # Log lines at three verbosity levels (Rich markup)
    log_basic: list[str] = field(default_factory=list)
    log_verbose: list[str] = field(default_factory=list)
    log_debug: list[str] = field(default_factory=list)

    # trace_done fields
    total_devices: int = 0
    ecmp_branches: int = 0
    duration: float = 0.0
    is_healthy: bool = True
    status: str = ""                    # "complete", "broken", "loop", "partial"


# Type alias for the event callback
EventCallback = Callable[[HopEvent], None]