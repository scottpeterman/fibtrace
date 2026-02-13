"""
Textual TUI for fibtrace — live forwarding chain visualization.

Two modes:
  Live:  FibTraceApp(walker_config=WalkerConfig(...))
         Walker runs in a thread worker, emits HopEvents via queue.
  Demo:  FibTraceApp(target_prefix=..., source_device=...)
         Mock walker replays the 6-hop ECMP trace from the README.
"""

from __future__ import annotations

import asyncio
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import RichLog, Static, Tree
from textual.widgets.tree import TreeNode

from .events import HopEvent, TuiVerdict, VERDICT_STYLE, LogLevel

CSS_PATH = Path(__file__).parent / "theme.tcss"


class TitleBar(Static):
    pass

class StatusBar(Static):
    pass


class FibTraceApp(App):
    """Fibtrace TUI — live forwarding chain visualization."""

    CSS_PATH = CSS_PATH
    TITLE = "fibtrace"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("b", "log_basic", "Basic"),
        Binding("v", "log_verbose", "Verbose"),
        Binding("d", "log_debug", "Debug"),
    ]

    def __init__(
        self,
        target_prefix: str = "",
        source_device: str = "",
        walker_config=None,
        walker_events: list[HopEvent] | None = None,
    ):
        super().__init__()
        self._walker_config = walker_config
        self._walker_events = walker_events

        if walker_config:
            self.target_prefix = walker_config.target_prefix
            self.source_device = walker_config.source_host
        else:
            self.target_prefix = target_prefix
            self.source_device = source_device

        self._log_level = LogLevel.BASIC
        self._device_nodes: dict[str, TreeNode] = {}
        self._all_logs: list[tuple[HopEvent, datetime]] = []
        self._hop_count = 0
        self._trace_done = False
        self._result: HopEvent | None = None
        self._trace_start = datetime.now()
        self._event_queue: queue.Queue[HopEvent | None] = queue.Queue()

    def compose(self) -> ComposeResult:
        yield TitleBar(
            f"  🔍 fibtrace: {self.target_prefix} from {self.source_device}",
            id="title-bar",
        )
        with Horizontal(id="main-split"):
            with Vertical(id="tree-pane"):
                tree: Tree[str] = Tree(f"🔍 {self.target_prefix}", id="hop-tree")
                tree.show_root = True
                tree.root.expand()
                tree.guide_depth = 3
                yield tree
            with Vertical(id="log-pane"):
                yield RichLog(id="log-view", highlight=True, markup=True,
                              wrap=True, auto_scroll=True)
        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        self._update_status()
        if self._walker_config:
            self.run_worker(self._run_live_trace(), exclusive=True, group="walk")
        elif self._walker_events:
            self.run_worker(self._replay_events(), exclusive=True, group="walk")
        else:
            self.run_worker(self._run_mock_trace(), exclusive=True, group="walk")

    # ── Live walker integration ─────────────────────────────────────────

    async def _run_live_trace(self) -> None:
        """
        Run the real walker in a background thread.
        Walker (sync/Paramiko) → queue.put(HopEvent) → async poll → TUI.
        """
        from .walker import ChainWalker

        config = self._walker_config
        config.event_callback = self._event_queue.put

        def _walker_thread():
            try:
                walker = ChainWalker(config)
                walker.walk()
            except Exception as e:
                self._event_queue.put(HopEvent(
                    event="trace_done", is_healthy=False, status="error",
                    log_basic=[f"[#ff4444]Walker error: {e}[/]"],
                ))
            finally:
                self._event_queue.put(None)

        thread = threading.Thread(target=_walker_thread, daemon=True)
        thread.start()

        while True:
            try:
                evt = self._event_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue
            if evt is None:
                break
            self._process_event(evt)
            if evt.event == "trace_done":
                break

        thread.join(timeout=5.0)

    # ── Event processing ────────────────────────────────────────────────

    async def _replay_events(self) -> None:
        for evt in self._walker_events:
            self._process_event(evt)
            await asyncio.sleep(0.05)

    def _process_event(self, evt: HopEvent) -> None:
        now = datetime.now()
        self._all_logs.append((evt, now))
        if evt.event == "hop_start":
            self._add_pending_node(evt)
            self._write_log_lines(evt, now)
            self._update_status()
        elif evt.event == "hop_done":
            self._update_node_verdict(evt)
            self._write_log_lines(evt, now)
            self._hop_count += 1
            self._update_status()
        elif evt.event == "trace_done":
            self._trace_done = True
            self._result = evt
            self._write_log_lines(evt, now)
            self._update_status()

    # ── Tree management ─────────────────────────────────────────────────

    def _add_pending_node(self, evt: HopEvent) -> None:
        tree = self.query_one("#hop-tree", Tree)
        label = Text()
        label.append("⟳ ", style="#00d4ff")
        label.append(evt.device, style="#00d4ff")
        label.append(f"  ({evt.ip})", style="#555555")
        parent = self._find_parent(evt, tree)
        node = parent.add(label, expand=True)
        self._device_nodes[evt.device] = node
        node.expand()
        tree.scroll_end(animate=False)

    def _update_node_verdict(self, evt: HopEvent) -> None:
        node = self._device_nodes.get(evt.device)
        if node is None:
            return
        color, icon = VERDICT_STYLE.get(evt.verdict, ("#888888", "?"))
        label = Text()
        label.append(f"{icon} ", style=color)
        label.append(evt.device, style="bold " + color)
        if evt.egress:
            label.append(f"  {evt.egress}", style="#888888")
        for note in evt.notes:
            label.append(f"  {note}", style="#ffcc00 italic")
        node.set_label(label)

    def _find_parent(self, evt: HopEvent, tree: Tree) -> TreeNode:
        if evt.parent_device and evt.parent_device in self._device_nodes:
            return self._device_nodes[evt.parent_device]
        return tree.root

    # ── Log pane ────────────────────────────────────────────────────────

    def _write_log_lines(self, evt: HopEvent, now: datetime) -> None:
        log = self.query_one("#log-view", RichLog)
        ts = now.strftime("%H:%M:%S")
        for line in self._get_lines_for_level(evt):
            log.write(Text.from_markup(f"[#555555]{ts}[/] {line}"))

    def _get_lines_for_level(self, evt: HopEvent) -> list[str]:
        if self._log_level == LogLevel.DEBUG:
            return evt.log_debug or evt.log_verbose or evt.log_basic
        elif self._log_level == LogLevel.VERBOSE:
            return evt.log_verbose or evt.log_basic
        return evt.log_basic

    def _rebuild_log(self) -> None:
        log = self.query_one("#log-view", RichLog)
        log.clear()
        for evt, ts in self._all_logs:
            ts_str = ts.strftime("%H:%M:%S")
            for line in self._get_lines_for_level(evt):
                log.write(Text.from_markup(f"[#555555]{ts_str}[/] {line}"))

    # ── Status bar ──────────────────────────────────────────────────────

    def _update_status(self) -> None:
        bar = self.query_one("#status-bar", StatusBar)
        elapsed = (datetime.now() - self._trace_start).total_seconds()
        level_str = self._log_level.value
        parts = []
        for key, label in [("basic", "basic"), ("verbose", "verbose"), ("debug", "debug")]:
            if level_str == key:
                parts.append(f"[bold]{label[0]}[/bold]{label[1:]}")
            else:
                parts.append(label)
        level_hints = "  ".join(parts)

        if self._trace_done and self._result:
            r = self._result
            health = "[#00ff88]✓ COMPLETE[/]" if r.is_healthy else "[#ff4444]✗ FAILED[/]"
            bar.update(Text.from_markup(
                f"  {health} │ {r.total_devices} devices │ "
                f"{r.ecmp_branches} ECMP │ {r.duration:.1f}s │ "
                f"{level_hints} │ q:quit"
            ))
        else:
            bar.update(Text.from_markup(
                f"  [#00d4ff]⟳[/] hop {self._hop_count} │ {elapsed:.0f}s │ "
                f"{level_hints} │ q:quit"
            ))

    # ── Key bindings ────────────────────────────────────────────────────

    def action_log_basic(self) -> None:
        self._log_level = LogLevel.BASIC
        self._rebuild_log()
        self._update_status()

    def action_log_verbose(self) -> None:
        self._log_level = LogLevel.VERBOSE
        self._rebuild_log()
        self._update_status()

    def action_log_debug(self) -> None:
        self._log_level = LogLevel.DEBUG
        self._rebuild_log()
        self._update_status()

    def action_quit(self) -> None:
        self.exit()

    # ── Mock trace ──────────────────────────────────────────────────────

    async def _run_mock_trace(self) -> None:
        hops = _build_mock_trace()
        for evt in hops:
            self._process_event(evt)
            if evt.event == "hop_start":
                await asyncio.sleep(1.2)
            elif evt.event == "hop_done":
                await asyncio.sleep(0.3)
            else:
                await asyncio.sleep(0.1)


def _build_mock_trace() -> list[HopEvent]:
    """6-hop ECMP example from the README."""
    V = TuiVerdict
    events: list[HopEvent] = []

    def _start(device, ip, parent, platform):
        return HopEvent(
            event="hop_start", device=device, ip=ip,
            parent_device=parent, platform=platform,
            log_basic=[f"[#00d4ff]Connecting to {device}[/] ({ip})"],
            log_verbose=[
                f"[#00d4ff]Connecting to {device}[/] ({ip})",
                f"  Platform detected: [bold]{platform}[/]",
            ],
            log_debug=[
                f"[#00d4ff]Connecting to {device}[/] ({ip})",
                f"  Platform: [bold]{platform}[/]",
            ],
        )

    # hop 0: usa-leaf-3 (IOS, default route)
    events.append(_start("usa-leaf-3", "172.16.1.4", None, "cisco_ios"))
    events.append(HopEvent(
        event="hop_done", device="usa-leaf-3", ip="172.16.1.4",
        verdict=V.HEALTHY, checks="route ✓ fib ✓ nh ✓ link ✓",
        egress="Vlan10 → 172.16.10.1", notes=["[via default]"],
        log_basic=["  [#00ff88]hop 0: usa-leaf-3 → HEALTHY[/]  Vlan10 → 172.16.10.1 [#ffcc00]\\[via default][/]"],
        log_verbose=[
            "  [#888888][✓] show ip route 172.16.11.41[/] parse:[#ff4444][✗][/]",
            "  [#888888][✓] show ip route 0.0.0.0 0.0.0.0[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show ip cef 0.0.0.0 detail[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show ip arp 172.16.10.1[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show interfaces Vlan10[/] parse:[#00ff88][✓][/]",
            "  ─── [#00ff88]Verdict: healthy[/] ───",
            "    route: [#ffcc00]\\[via default][/] static via 172.16.10.1", "",
        ],
        log_debug=[
            "  [#888888][✓] show ip route 172.16.11.41[/] parse:[#ff4444][✗][/]",
            "    [#444444]% Network not in table[/]",
            "  [#888888][✓] show ip route 0.0.0.0 0.0.0.0[/] parse:[#00ff88][✓][/]",
            "    [#444444]S* 0.0.0.0/0 \\[1/0] via 172.16.10.1 — pattern: static_bare[/]",
            "  [#888888][✓] show ip cef 0.0.0.0 detail[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show ip arp 172.16.10.1[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show interfaces Vlan10[/] parse:[#00ff88][✓][/]",
            "    [#444444]up/up, 0 errors[/]",
            "  ─── [#00ff88]Verdict: healthy[/] ───", "",
        ],
    ))

    # hop 1: usa-spine-2 (EOS)
    events.append(_start("usa-spine-2", "172.16.10.1", "usa-leaf-3", "arista_eos"))
    events.append(HopEvent(
        event="hop_done", device="usa-spine-2", ip="172.16.10.1",
        parent_device="usa-leaf-3", verdict=V.HEALTHY,
        checks="route ✓ fib ✓ nh ✓ link ✓", egress="Ethernet1 → 172.16.1.5",
        log_basic=["  [#00ff88]hop 1: usa-spine-2 → HEALTHY[/]  Ethernet1 → 172.16.1.5"],
        log_verbose=[
            "  [#888888][✓] show ip route | json[/] parse:[#00ff88][✓][/] JSON",
            "  [#888888][✓] show ip cef | json[/] parse:[#00ff88][✓][/] JSON",
            "  [#888888][✓] show arp | json[/] parse:[#00ff88][✓][/] JSON",
            "  [#888888][✓] show interfaces Ethernet1 | json[/] parse:[#00ff88][✓][/] JSON",
            "  ─── [#00ff88]Verdict: healthy[/] ───", "",
        ],
    ))

    # hop 2: usa-rtr-1 (IOS)
    events.append(_start("usa-rtr-1", "172.16.1.5", "usa-spine-2", "cisco_ios"))
    events.append(HopEvent(
        event="hop_done", device="usa-rtr-1", ip="172.16.1.5",
        parent_device="usa-spine-2", verdict=V.HEALTHY,
        checks="route ✓ fib ✓ nh ✓ link ✓", egress="Gi0/3 → 172.16.128.6",
        log_basic=["  [#00ff88]hop 2: usa-rtr-1 → HEALTHY[/]  Gi0/3 → 172.16.128.6"],
        log_verbose=[
            "  [#888888][✓] show ip route[/] parse:[#00ff88][✓][/] regex (full_from_via)",
            "  [#888888][✓] show ip cef detail[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show ip arp 172.16.128.6[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show interfaces Gi0/3[/] parse:[#00ff88][✓][/]",
            "  ─── [#00ff88]Verdict: healthy[/] ───", "",
        ],
    ))

    # hop 3: eng-rtr-1 (IOS, ECMP)
    events.append(_start("eng-rtr-1", "172.16.128.6", "usa-rtr-1", "cisco_ios"))
    events.append(HopEvent(
        event="hop_done", device="eng-rtr-1", ip="172.16.128.6",
        parent_device="usa-rtr-1", verdict=V.HEALTHY,
        checks="route ✓ fib ✓ nh ✓ link ✓",
        egress="Gi0/2 → 172.16.2.2, Gi0/3 → 172.16.2.6",
        notes=["ECMP: 2 paths"],
        log_basic=[
            "  [#00ff88]hop 3: eng-rtr-1 → HEALTHY[/]  [#00d4ff]ECMP: 2 paths[/]",
            "    Gi0/2 → 172.16.2.2", "    Gi0/3 → 172.16.2.6",
        ],
        log_verbose=[
            "  [#888888][✓] show ip route[/] parse:[#00ff88][✓][/]",
            "    [#00d4ff]⚡ ECMP: 2 next-hops[/]",
            "  [#888888][✓] show ip cef detail[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show ip arp ×2[/] parse:[#00ff88][✓][/]",
            "  [#888888][✓] show interfaces ×2[/] parse:[#00ff88][✓][/]",
            "  ─── [#00ff88]Verdict: healthy[/] ───", "",
        ],
    ))

    # hop 4 & 5: eng-spine-1/2 (EOS, connected)
    for i, (name, ip) in enumerate([("eng-spine-1", "172.16.2.2"),
                                     ("eng-spine-2", "172.16.2.6")]):
        events.append(_start(name, ip, "eng-rtr-1", "arista_eos"))
        events.append(HopEvent(
            event="hop_done", device=name, ip=ip,
            parent_device="eng-rtr-1", verdict=V.HEALTHY_CONNECTED,
            checks="route ✓ fib — nh — link —",
            egress="Vlan11", notes=["(connected)"],
            log_basic=[f"  [#00ff88]hop {4+i}: {name} → HEALTHY[/] (connected)  Vlan11"],
            log_verbose=[
                f"  [#888888][✓] show ip route | json[/] parse:[#00ff88][✓][/] ← connected",
                "  ─── [#00ff88]Verdict: healthy (connected)[/] — end of path ───", "",
            ],
        ))

    # trace complete
    events.append(HopEvent(
        event="trace_done",
        total_devices=6, ecmp_branches=1, duration=95.4, is_healthy=True,
        log_basic=[
            "", "[#00ff88]━━━ Trace complete ━━━[/]",
            "  Status: [#00ff88]COMPLETE[/] │ 6 devices │ 1 ECMP │ 95.4s",
        ],
        log_verbose=[
            "", "[#00ff88]━━━ Trace complete ━━━[/]",
            "  Status: [#00ff88]COMPLETE[/] │ 6 devices │ 1 ECMP │ 95.4s",
            "  All paths healthy — forwarding chain validated end-to-end",
        ],
        log_debug=[
            "", "[#00ff88]━━━ Trace complete ━━━[/]",
            "  Status: [#00ff88]COMPLETE[/] │ 6 devices │ 1 ECMP │ 95.4s",
            "  All paths healthy",
            "  [#444444]visited: {usa-leaf-3, usa-spine-2, usa-rtr-1, eng-rtr-1, eng-spine-1, eng-spine-2}[/]",
            "  [#444444]SSH sessions: 6, commands: 24[/]",
        ],
    ))

    return events


def main():
    import argparse
    import sys
    from ipaddress import ip_address, IPv6Address, AddressValueError

    parser = argparse.ArgumentParser(description="fibtrace TUI")
    parser.add_argument("--demo", action="store_true", help="Run mock trace")
    parser.add_argument("-p", "--prefix", default=None)
    parser.add_argument("-s", "--source", default=None)
    parser.add_argument("-u", "--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--max-depth", type=int, default=15)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--legacy-ssh", action="store_true")
    parser.add_argument("--error-threshold", type=int, default=100)
    parser.add_argument("--skip-mac", action="store_true")
    parser.add_argument("--domain", default=None)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    if args.demo or (not args.prefix and not args.source):
        app = FibTraceApp(target_prefix="172.16.11.41/32", source_device="usa-leaf-3")
        app.run()
        return

    if not args.prefix or not args.source or not args.username:
        parser.error("Live mode requires -p, -s, and -u")

    prefix_str = args.prefix
    if '/' not in prefix_str:
        try:
            addr = ip_address(prefix_str)
            prefix_str += '/128' if isinstance(addr, IPv6Address) else '/32'
        except (ValueError, AddressValueError) as e:
            parser.error(f"Invalid prefix: {e}")

    from .walker import WalkerConfig
    config = WalkerConfig(
        target_prefix=prefix_str, source_host=args.source,
        username=args.username, password=args.password,
        key_file=args.key_file, max_depth=args.max_depth,
        command_timeout=args.timeout, legacy_ssh=args.legacy_ssh,
        interface_error_threshold=args.error_threshold,
        skip_mac_lookup=args.skip_mac, dns_domain=args.domain,
        log_file=args.log,
    )
    app = FibTraceApp(walker_config=config)
    app.run()


if __name__ == "__main__":
    main()
