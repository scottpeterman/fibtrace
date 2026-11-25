"""fibtrace — hop-by-hop forwarding chain validation.

Core library exports below. The TUI (fibtrace.tui) and web UI (fibtrace.web)
are optional components, gated behind the [tui] and [web] extras.
Importing fibtrace itself requires neither.
"""
from importlib.metadata import version as _version, PackageNotFoundError

from .events import HopEvent, TuiVerdict, LogLevel, VERDICT_STYLE

try:
    __version__ = _version("fibtrace")
except PackageNotFoundError:
    # Source checkout without installed metadata.
    __version__ = "0.0.0+dev"

__all__ = ["HopEvent", "TuiVerdict", "LogLevel", "VERDICT_STYLE", "__version__"]