"""
Forwarding Chain Validator — Diagnostic Framework

Every command, every parse, every decision — traceable.
Three levels:
  1. Chain-level summary (always, to TUI or stdout)
  2. Hop-level detail (--verbose, structured per-hop reports)
  3. Raw capture (--debug/--log, full command I/O and parser internals)

Philosophy: if a parser returns None, we need to know WHY.
  - Was the command output empty?
  - Did the regex match but capture groups were wrong?
  - Did JSON parse but the key path was unexpected?
  - Did the command itself error?
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
import json
import logging


# ============================================================
# Structured Diagnostic Records
# ============================================================
# Not just log lines — structured objects that can be
# serialized to JSON, displayed in TUI, or dumped to file.


class CommandStatus(Enum):
    SUCCESS = "success"             # command executed, got output
    EMPTY = "empty"                 # command executed, no output
    ERROR = "error"                 # device returned an error
    TIMEOUT = "timeout"             # no response within deadline
    AUTH_FAILURE = "auth-failure"   # SSH auth failed
    CONNECT_FAILURE = "connect-failure"  # couldn't reach device
    PARSE_ERROR = "parse-error"     # got output, parser choked


class ParseResult(Enum):
    OK = "ok"                       # parsed successfully
    PARTIAL = "partial"             # got some fields, missed others
    NO_MATCH = "no-match"           # pattern/key not found in output
    EMPTY_INPUT = "empty-input"     # nothing to parse
    JSON_ERROR = "json-error"       # JSON decode failed
    EXCEPTION = "exception"         # parser threw


@dataclass
class CommandRecord:
    """Complete record of a single command execution."""
    device: str                         # hostname or IP
    platform: str                       # identified platform
    command: str                        # exact command sent
    timestamp: datetime = field(default_factory=datetime.now)

    # What happened
    status: CommandStatus = CommandStatus.SUCCESS
    raw_output: str = ""                # FULL output, unmodified
    error_message: str = ""             # device error or exception text
    duration_ms: Optional[float] = None  # command round-trip time

    # Parsing
    parser_used: str = ""               # "json", "textfsm", "regex", "none"
    parse_result: ParseResult = ParseResult.OK
    parse_detail: str = ""              # what went wrong / what matched
    extracted_data: Optional[dict] = None  # structured data after parsing

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "platform": self.platform,
            "command": self.command,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "raw_output_lines": len(self.raw_output.splitlines()),
            "raw_output": self.raw_output,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "parser_used": self.parser_used,
            "parse_result": self.parse_result.value,
            "parse_detail": self.parse_detail,
            "extracted_data": self.extracted_data,
        }


@dataclass
class FingerprintRecord:
    """Record of the fingerprinting process."""
    device: str
    prompt_raw: str = ""
    prompt_guess: str = ""              # platform guess from prompt alone
    show_version_output: str = ""
    final_platform: str = ""
    confidence: str = ""                # "prompt", "show_version", "fallback"

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "prompt_raw": self.prompt_raw,
            "prompt_guess": self.prompt_guess,
            "show_version_lines": len(self.show_version_output.splitlines()),
            "show_version_output": self.show_version_output,
            "final_platform": self.final_platform,
            "confidence": self.confidence,
        }


@dataclass
class VerdictRecord:
    """Why a HopVerdict was assigned — the reasoning chain."""
    device: str
    prefix: str
    verdict: str                        # HopVerdict value

    # The four checks with pass/fail and why
    route_found: bool = False
    route_detail: str = ""              # "OSPF via 10.0.0.1 on Gi0/1" or "no entry"

    fib_programmed: bool = False
    fib_detail: str = ""                # "programmed, 2 paths" or "not in FIB"

    nh_resolved: bool = False
    nh_detail: str = ""                 # "10.0.0.1 → aa:bb:cc:dd:ee:ff on Gi0/1"

    link_healthy: bool = False
    link_detail: str = ""               # "up/up, 0 errors" or "3,241 CRC errors"

    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "prefix": self.prefix,
            "verdict": self.verdict,
            "checks": {
                "route": {"passed": self.route_found, "detail": self.route_detail},
                "fib": {"passed": self.fib_programmed, "detail": self.fib_detail},
                "next_hop": {"passed": self.nh_resolved, "detail": self.nh_detail},
                "link": {"passed": self.link_healthy, "detail": self.link_detail},
            },
            "notes": self.notes,
        }


# ============================================================
# Hop Diagnostic — everything about one device visit
# ============================================================

@dataclass
class HopDiagnostic:
    """All diagnostic records for a single hop in the chain."""
    device: str
    hop_index: int
    fingerprint: Optional[FingerprintRecord] = None
    commands: list[CommandRecord] = field(default_factory=list)
    verdict: Optional[VerdictRecord] = None

    def failed_commands(self) -> list[CommandRecord]:
        return [c for c in self.commands if c.status != CommandStatus.SUCCESS]

    def parse_failures(self) -> list[CommandRecord]:
        return [c for c in self.commands if c.parse_result not in (
            ParseResult.OK, ParseResult.PARTIAL
        )]

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "hop_index": self.hop_index,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "commands": [c.to_dict() for c in self.commands],
            "command_summary": {
                "total": len(self.commands),
                "failed": len(self.failed_commands()),
                "parse_failures": len(self.parse_failures()),
            },
            "verdict": self.verdict.to_dict() if self.verdict else None,
        }


# ============================================================
# Chain Diagnostic — the full walk
# ============================================================

@dataclass
class ChainDiagnostic:
    """Complete diagnostic record for the entire chain walk."""
    target_prefix: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    hops: list[HopDiagnostic] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_prefix": self.target_prefix,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": {
                "total_hops": len(self.hops),
                "total_commands": sum(len(h.commands) for h in self.hops),
                "failed_commands": sum(len(h.failed_commands()) for h in self.hops),
                "parse_failures": sum(len(h.parse_failures()) for h in self.hops),
            },
            "hops": [h.to_dict() for h in self.hops],
        }

    def dump_json(self, path: str):
        """Write full diagnostic to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)


# ============================================================
# Logger Setup
# ============================================================
#
# Three output modes, layered:
#
#   --quiet         : errors only (default for TUI mode)
#   --verbose / -v  : hop-level summaries to stderr or status bar
#   --debug         : everything, to file (--log FILE) or stderr
#
# The TUI status bar gets a compact feed:
#   "hop 3/7: eng-spine-1 | route ✓ fib ✓ arp ✓ link ✓ → HEALTHY"
#   "hop 4/7: eng-leaf-1  | route ✓ fib ✗ → RIB_ONLY"
#
# The log file gets the full CommandRecord JSON per command.
#

def setup_logging(
    log_file: Optional[str] = None,
    debug: bool = False,
    verbose: bool = False,
) -> logging.Logger:
    """
    Configure logging for chain walk.

    - log_file: write debug-level to file (TUI-safe)
    - debug: debug-level to stderr (non-TUI mode only)
    - verbose: info-level to stderr
    """
    logger = logging.getLogger("chainwalk")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # File handler — always debug level, always safe with TUI
    if log_file:
        fh = logging.FileHandler(log_file, mode="w")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Stderr handler — only in non-TUI or verbose mode
    if debug or verbose:
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG if debug else logging.INFO)
        sh.setFormatter(formatter)
        logger.addHandler(sh)

    # Null handler if nothing else — prevent "no handler" warnings
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    return logger


# ============================================================
# Diagnostic-Aware Parse Wrapper
# ============================================================
#
# Every parser call goes through this. It captures what happened
# and returns both the result and the diagnostic record.
#

def parse_with_diagnostics(
    device: str,
    platform: str,
    command: str,
    raw_output: str,
    parser_func: callable,
    parser_name: str = "unknown",
    logger: Optional[logging.Logger] = None,
) -> tuple[Any, CommandRecord]:
    """
    Wrap any parser function with full diagnostics.

    Returns:
        (parsed_result, command_record)
        parsed_result is None if parsing failed.
    """
    record = CommandRecord(
        device=device,
        platform=platform,
        command=command,
        raw_output=raw_output,
        parser_used=parser_name,
    )

    if not raw_output or not raw_output.strip():
        record.status = CommandStatus.EMPTY
        record.parse_result = ParseResult.EMPTY_INPUT
        record.parse_detail = "Empty or whitespace-only output"
        if logger:
            logger.warning(
                f"[{device}] Empty output for: {command}"
            )
        return None, record

    # Check for device-level errors in output
    error_indicators = [
        "% Invalid input",
        "% Incomplete command",
        "% Ambiguous command",
        "% Unknown command",
        "syntax error",
        "unknown command",
        "invalid command",
    ]
    for indicator in error_indicators:
        if indicator.lower() in raw_output.lower():
            record.status = CommandStatus.ERROR
            record.error_message = f"Device error detected: {indicator}"
            record.parse_result = ParseResult.NO_MATCH
            if logger:
                logger.error(
                    f"[{device}] Command error: {command}\n"
                    f"  Output: {raw_output[:200]}"
                )
            return None, record

    # Attempt parse
    try:
        result = parser_func(raw_output)

        if result is None:
            record.parse_result = ParseResult.NO_MATCH
            record.parse_detail = "Parser returned None"
            if logger:
                logger.warning(
                    f"[{device}] Parse returned None for: {command}\n"
                    f"  Parser: {parser_name}\n"
                    f"  Output ({len(raw_output)} chars):\n"
                    f"  {_indent(raw_output[:500])}"
                )
        else:
            record.parse_result = ParseResult.OK
            record.extracted_data = (
                result if isinstance(result, dict)
                else {"_repr": repr(result)}
            )
            if logger:
                logger.debug(
                    f"[{device}] Parsed OK: {command} → {parser_name}"
                )

        return result, record

    except json.JSONDecodeError as e:
        record.parse_result = ParseResult.JSON_ERROR
        record.parse_detail = f"JSON decode error at pos {e.pos}: {e.msg}"
        if logger:
            logger.error(
                f"[{device}] JSON parse failed: {command}\n"
                f"  Error: {e.msg} at position {e.pos}\n"
                f"  Raw output:\n{_indent(raw_output[:500])}"
            )
        return None, record

    except Exception as e:
        record.parse_result = ParseResult.EXCEPTION
        record.parse_detail = f"{type(e).__name__}: {str(e)}"
        if logger:
            logger.error(
                f"[{device}] Parser exception: {command}\n"
                f"  Parser: {parser_name}\n"
                f"  Exception: {type(e).__name__}: {e}\n"
                f"  Output:\n{_indent(raw_output[:500])}"
            )
        return None, record


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


# ============================================================
# Diagnostic Dump Formats
# ============================================================

def dump_hop_summary(diag: HopDiagnostic) -> str:
    """One-line summary for TUI status bar or verbose output."""
    v = diag.verdict
    if not v:
        return f"hop {diag.hop_index}: {diag.device} | no verdict"

    checks = []
    checks.append(f"route {'✓' if v.route_found else '✗'}")
    checks.append(f"fib {'✓' if v.fib_programmed else '✗'}")
    checks.append(f"nh {'✓' if v.nh_resolved else '✗'}")
    checks.append(f"link {'✓' if v.link_healthy else '✗'}")

    return (
        f"hop {diag.hop_index}: {diag.device} | "
        f"{' '.join(checks)} → {v.verdict}"
    )


def dump_hop_detail(diag: HopDiagnostic) -> str:
    """Multi-line detail for --verbose or drill-down."""
    lines = [f"═══ Hop {diag.hop_index}: {diag.device} ═══"]

    # Fingerprint
    if diag.fingerprint:
        fp = diag.fingerprint
        lines.append(f"  Platform: {fp.final_platform} (via {fp.confidence})")

    # Commands
    for cmd in diag.commands:
        status_icon = {
            CommandStatus.SUCCESS: "✓",
            CommandStatus.EMPTY: "○",
            CommandStatus.ERROR: "✗",
            CommandStatus.TIMEOUT: "⏱",
            CommandStatus.PARSE_ERROR: "⚠",
        }.get(cmd.status, "?")

        parse_icon = {
            ParseResult.OK: "✓",
            ParseResult.PARTIAL: "~",
            ParseResult.NO_MATCH: "✗",
            ParseResult.EMPTY_INPUT: "○",
            ParseResult.JSON_ERROR: "✗",
            ParseResult.EXCEPTION: "✗",
        }.get(cmd.parse_result, "?")

        time_str = f" ({cmd.duration_ms:.0f}ms)" if cmd.duration_ms else ""
        lines.append(
            f"  [{status_icon}] {cmd.command}{time_str} "
            f"parse:[{parse_icon}] via {cmd.parser_used}"
        )

        if cmd.error_message:
            lines.append(f"      error: {cmd.error_message}")
        if cmd.parse_result not in (ParseResult.OK, ParseResult.PARTIAL):
            lines.append(f"      detail: {cmd.parse_detail}")

    # Verdict
    if diag.verdict:
        v = diag.verdict
        lines.append(f"  ─── Verdict: {v.verdict} ───")
        lines.append(f"    route:  {v.route_detail}")
        lines.append(f"    fib:    {v.fib_detail}")
        lines.append(f"    nh:     {v.nh_detail}")
        lines.append(f"    link:   {v.link_detail}")
        for note in v.notes:
            lines.append(f"    ⚠ {note}")

    return "\n".join(lines)


def dump_chain_summary(diag: ChainDiagnostic) -> str:
    """Full chain summary — suitable for terminal or report output."""
    lines = [
        f"Chain Walk: {diag.target_prefix}",
        f"{'─' * 50}",
    ]

    for hop in diag.hops:
        lines.append(dump_hop_summary(hop))

    s = diag.to_dict()["summary"]
    lines.append(f"{'─' * 50}")
    lines.append(
        f"Hops: {s['total_hops']} | "
        f"Commands: {s['total_commands']} | "
        f"Failed: {s['failed_commands']} | "
        f"Parse errors: {s['parse_failures']}"
    )

    return "\n".join(lines)