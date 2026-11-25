"""TUI tree: a convergence adds a marker under the second parent and leaves the walked node's verdict alone."""

import asyncio

from fibtrace.events import HopEvent, TuiVerdict
from fibtrace.tui import FibTraceApp


def _hop(device, parent, verdict=TuiVerdict.HEALTHY):
    return [HopEvent(event="hop_start", device=device, ip="192.0.2.1", parent_device=parent),
            HopEvent(event="hop_done", device=device, ip="192.0.2.1", parent_device=parent, verdict=verdict)]


def _labels(node, depth=0, out=None):
    out = [] if out is None else out
    for child in node.children:
        out.append(("  " * depth) + child.label.plain)
        _labels(child, depth + 1, out)
    return out


def test_convergence_marker_under_second_parent():
    events = (_hop("tor", None) + _hop("agg1", "tor") + _hop("agg2", "tor") + _hop("edge", "agg1")
              + [HopEvent(event="hop_done", device="edge", ip="192.0.2.9", parent_device="agg2",
                          verdict=TuiVerdict.CONVERGENCE, notes=["(converges)"])]
              + [HopEvent(event="trace_done", is_healthy=True, status="complete")])

    async def run():
        app = FibTraceApp(target_prefix="192.0.2.0/24", source_device="tor", walker_events=events)
        async with app.run_test() as pilot:
            await asyncio.sleep(len(events) * 0.05 + 0.5)
            await pilot.pause()
            return _labels(app.query_one("#hop-tree").root)

    labels = asyncio.run(run())
    assert labels[0].startswith("✓ tor")
    assert labels[1].strip().startswith("✓ agg1")
    assert labels[2].strip().startswith("✓ edge")            # walked node keeps its verdict
    assert labels[3].strip().startswith("✓ agg2")
    assert labels[4].strip() == "↪ edge  (converges)"         # marker under the second parent
    assert labels[4].startswith("    ")                       # nested under agg2


def test_live_trace_saves_graph_and_reports(tmp_path, monkeypatch):
    from fibtrace import walker as W

    class FakeGraph:
        def save(self, path):
            open(path, "w").write("{}")

        def to_dot(self):
            return "digraph {}"

    class FakeWalker:
        def __init__(self, config):
            self.config = config
            self.graph = FakeGraph()

        def walk(self):
            for e in _hop("tor", None):
                self.config.event_callback(e)
            self.config.event_callback(HopEvent(event="trace_done", is_healthy=True, status="complete"))

    monkeypatch.setattr(W, "ChainWalker", FakeWalker)
    cfg = W.WalkerConfig(target_prefix="192.0.2.1/32", source_host="192.0.2.1", username="u", password="p")
    graph, dot = tmp_path / "g.json", tmp_path / "g.dot"

    async def run():
        app = FibTraceApp(walker_config=cfg, graph_file=str(graph), dot_file=str(dot))
        async with app.run_test() as pilot:
            await asyncio.sleep(1.0)
            await pilot.pause()
            return [e.log_basic for e, _ in app._all_logs if e.event == "saved"]

    saved = asyncio.run(run())
    assert graph.read_text() == "{}" and dot.read_text() == "digraph {}"
    assert any(str(graph) in line for line in saved[0])
