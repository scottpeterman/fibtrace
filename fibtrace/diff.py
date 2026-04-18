"""
fibtrace-diff — compare two fibtrace forwarding graphs.

Accepts either raw forwarding-graph JSON (output of `--graph`) or the full
trace JSON (output of `--json`, with the graph nested under `"graph"`).

Usage:
    fibtrace-diff a.json b.json                    # one-line summary (default)
    fibtrace-diff a.json b.json --json             # structured delta
    fibtrace-diff a.json b.json --markdown         # MOP-ready report
    fibtrace-diff a.json b.json --markdown -o out.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

# Node fields that matter for diff. Derived/positional fields (depth,
# children, parents, is_loop_member) are excluded — they fall out of the
# edge diff naturally.
COMPARED_NODE_FIELDS = [
    "verdict",
    "reachable",
    "platform",
    "route_summary",
    "fib_summary",
    "is_terminal",
    "is_connected",
    "is_ecmp_branch",
    "is_convergence",
]
# Treated as sets, not ordered lists
SET_NODE_FIELDS = ["egress_interfaces"]

# Edge identity: (from, to, next_hop_ip, egress_interface)
# next_hop_ip and egress_interface are in the tuple because the same
# from/to pair can have multiple ECMP-sibling edges with different NHs.
EDGE_KEY_FIELDS = ("from", "to", "next_hop_ip", "egress_interface")


# ──────────────────────────────────────────────────────────────
# Input loading
# ──────────────────────────────────────────────────────────────

def load_graph(path: str) -> dict:
    """
    Load a fibtrace graph. Accepts both raw graph dumps and full trace
    output (where the graph is nested under "graph").
    """
    with open(path) as f:
        data = json.load(f)

    if "graph" in data and isinstance(data["graph"], dict) and "nodes" in data["graph"]:
        data = data["graph"]

    for required in ("meta", "nodes", "edges"):
        if required not in data:
            raise ValueError(
                f"{path}: not a fibtrace graph (missing '{required}'). "
                "Expected output of `fibtrace --graph` or `fibtrace --json`."
            )
    return data


# ──────────────────────────────────────────────────────────────
# Diff core
# ──────────────────────────────────────────────────────────────

def _node_field_diff(a: dict, b: dict) -> list[dict]:
    """Return the list of field-level changes between two node dicts."""
    changes = []
    for field in COMPARED_NODE_FIELDS:
        av, bv = a.get(field), b.get(field)
        if av != bv:
            changes.append({"field": field, "from": av, "to": bv})
    for field in SET_NODE_FIELDS:
        a_set = set(a.get(field) or [])
        b_set = set(b.get(field) or [])
        if a_set != b_set:
            changes.append({
                "field": field,
                "removed": sorted(a_set - b_set),
                "added": sorted(b_set - a_set),
            })
    return changes


def _edge_key(e: dict) -> tuple:
    return tuple(e.get(f) for f in EDGE_KEY_FIELDS)


def _severity_of_node_change(change: dict) -> str:
    """
    Rank a single field change on a modified node.
    critical | warning | info
    """
    field = change["field"]
    if field == "verdict":
        frm, to = change["from"], change["to"]
        bad = {"warning", "critical", "unreachable"}
        good = {"healthy"}
        if frm in good and to in bad:
            return "critical"
        if frm in bad and to in good:
            return "info"
        return "warning"
    if field == "reachable":
        if change["from"] is True and change["to"] is False:
            return "critical"
        if change["from"] is False and change["to"] is True:
            return "info"
        return "warning"
    if field == "is_ecmp_branch":
        # ECMP collapse is a warning; widening is info
        return "warning" if change["from"] and not change["to"] else "info"
    if field == "fib_summary":
        return "warning"
    if field == "egress_interfaces":
        return "warning"
    if field == "route_summary":
        return "warning"
    return "info"


def _max_severity(severities: list[str]) -> str:
    order = {"critical": 3, "warning": 2, "info": 1}
    return max(severities, key=lambda s: order.get(s, 0)) if severities else "info"


# ──────────────────────────────────────────────────────────────
# Impairment (continuous capacity metric)
# ──────────────────────────────────────────────────────────────
#
# Impairment is computed as net change in forwarding capacity, not count
# of individual changes. A MOP that reroutes 4 paths onto 4 new paths
# produces zero path impairment with high churn — the forwarding capability
# survived, even though a lot moved.
#
# All values are signed floats in the range [-1.0, +inf):
#   negative = capacity lost (impaired)
#   zero     = net capacity unchanged
#   positive = capacity gained (improved)
#
# Churn is separate — it measures how much of the path set was replaced,
# regardless of net direction.

IMPAIRMENT_CRITICAL_PCT = -0.50   # >=50% capacity loss → critical
IMPAIRMENT_WARNING_PCT  = -0.25   # >=25% capacity loss → warning


def compute_impairment(a: dict, b: dict, a_paths: set, b_paths: set,
                       removed_edges: list, added_edges: list) -> dict:
    """Signed capacity deltas across paths, edges, and ECMP fan-out width."""
    a_nodes, b_nodes = a["nodes"], b["nodes"]

    def _pct(before: int, after: int):
        if before == 0:
            return None  # undefined baseline
        return (after - before) / before

    # Path impairment — net, not count-of-moves
    paths_pct = _pct(len(a_paths), len(b_paths))

    # Edge impairment — net
    a_edge_count = len(a["edges"])
    b_edge_count = len(b["edges"])
    edges_pct = _pct(a_edge_count, b_edge_count)

    # ECMP-width impairment — sum of outgoing-edge counts across nodes
    # that were ECMP branch points in A, compared to their outgoing count
    # in B (0 if the node no longer exists in B).
    a_outgoing: dict[str, int] = {}
    for e in a["edges"]:
        a_outgoing[e["from"]] = a_outgoing.get(e["from"], 0) + 1
    b_outgoing: dict[str, int] = {}
    for e in b["edges"]:
        b_outgoing[e["from"]] = b_outgoing.get(e["from"], 0) + 1

    ecmp_branches_in_a = [h for h, n in a_nodes.items() if n.get("is_ecmp_branch")]
    width_a = sum(a_outgoing.get(h, 0) for h in ecmp_branches_in_a)
    width_b = sum(b_outgoing.get(h, 0) for h in ecmp_branches_in_a)
    ecmp_width_pct = _pct(width_a, width_b)

    # Churn — Jaccard distance on the path set. 0 = identical, 1 = disjoint.
    union = a_paths | b_paths
    intersection = a_paths & b_paths
    churn_pct = (len(union) - len(intersection)) / len(union) if union else 0.0

    return {
        "paths_pct": paths_pct,
        "edges_pct": edges_pct,
        "ecmp_width_pct": ecmp_width_pct,
        "churn_pct": churn_pct,
        "paths_before": len(a_paths),
        "paths_after": len(b_paths),
        "ecmp_width_before": width_a,
        "ecmp_width_after": width_b,
    }


def compute_verdict(impairment: dict, severity_counts: dict,
                    has_verdict_worsened: bool, has_reachability_loss: bool) -> dict:
    """
    Roll the whole diff up to one of: unchanged | info | warning | critical.

    Two escalation paths:
      1. Any individual change that is itself critical (verdict worsened,
         reachability lost) — regardless of aggregate impairment.
      2. Aggregate impairment crossing the critical or warning threshold.
    """
    reasons: list[str] = []

    def crosses(pct, threshold):
        return pct is not None and pct <= threshold

    # Critical escalations
    if has_verdict_worsened:
        reasons.append("verdict worsened on one or more devices")
    if has_reachability_loss:
        reasons.append("device became unreachable")
    if crosses(impairment["paths_pct"], IMPAIRMENT_CRITICAL_PCT):
        reasons.append(f"path impairment {impairment['paths_pct']:+.0%}")
    if crosses(impairment["ecmp_width_pct"], IMPAIRMENT_CRITICAL_PCT):
        reasons.append(f"ECMP width impairment {impairment['ecmp_width_pct']:+.0%}")

    if reasons:
        return {"level": "critical", "reasons": reasons}

    # Warning escalations
    if crosses(impairment["paths_pct"], IMPAIRMENT_WARNING_PCT):
        reasons.append(f"path impairment {impairment['paths_pct']:+.0%}")
    if crosses(impairment["edges_pct"], IMPAIRMENT_WARNING_PCT):
        reasons.append(f"edge impairment {impairment['edges_pct']:+.0%}")
    if crosses(impairment["ecmp_width_pct"], IMPAIRMENT_WARNING_PCT):
        reasons.append(f"ECMP width impairment {impairment['ecmp_width_pct']:+.0%}")
    if severity_counts["warning"] > 0 and not reasons:
        reasons.append(f"{severity_counts['warning']} warning-level changes")

    if reasons:
        return {"level": "warning", "reasons": reasons}

    # Anything at all changed?
    total = sum(severity_counts.values())
    if total > 0 or impairment["churn_pct"] > 0:
        return {"level": "info", "reasons": ["changes present, no capacity impairment"]}

    return {"level": "unchanged", "reasons": []}


def diff_graphs(a: dict, b: dict) -> dict:
    """
    Compute the delta between two forwarding graphs.

    Returns a dict with schema_version, meta_delta, nodes{added,removed,
    modified}, edges{added,removed}, paths{added,removed}, and a
    sorted severity_summary.
    """
    a_nodes, b_nodes = a["nodes"], b["nodes"]
    a_keys, b_keys = set(a_nodes), set(b_nodes)

    # Node-level
    removed_nodes = sorted(a_keys - b_keys)
    added_nodes = sorted(b_keys - a_keys)
    modified_nodes = []
    for h in sorted(a_keys & b_keys):
        changes = _node_field_diff(a_nodes[h], b_nodes[h])
        if changes:
            node_severity = _max_severity([_severity_of_node_change(c) for c in changes])
            modified_nodes.append({
                "hostname": h,
                "severity": node_severity,
                "changes": changes,
            })

    # Edge-level — dedup by identity key
    a_edges = {_edge_key(e): e for e in a["edges"]}
    b_edges = {_edge_key(e): e for e in b["edges"]}
    removed_edge_keys = sorted(a_edges.keys() - b_edges.keys())
    added_edge_keys = sorted(b_edges.keys() - a_edges.keys())
    removed_edges = [a_edges[k] for k in removed_edge_keys]
    added_edges = [b_edges[k] for k in added_edge_keys]

    # Path-level — set semantics (ECMP ordering is not stable between runs)
    a_paths = {tuple(p) for p in a["meta"].get("paths", [])}
    b_paths = {tuple(p) for p in b["meta"].get("paths", [])}
    removed_paths = sorted(a_paths - b_paths)
    added_paths = sorted(b_paths - a_paths)
    preserved_paths = sorted(a_paths & b_paths)

    # Meta summary
    def m(g, k, default=0):
        v = g["meta"].get(k, default)
        return len(v) if isinstance(v, list) else v

    meta_delta = {
        "devices": m(b, "total_devices") - m(a, "total_devices"),
        "edges": m(b, "total_edges") - m(a, "total_edges"),
        "paths": len(b_paths) - len(a_paths),
        "ecmp_branches": m(b, "ecmp_branch_points") - m(a, "ecmp_branch_points"),
        "convergence_points": m(b, "convergence_points") - m(a, "convergence_points"),
    }

    # Roll up overall severity + track critical-flavored individual changes
    severity_counts = {"critical": 0, "warning": 0, "info": 0}
    has_verdict_worsened = False
    has_reachability_loss = False

    # Removed nodes that were on a surviving path of A are critical;
    # otherwise warning. Cheap heuristic: any removed node is at least
    # warning because it changed the topology.
    for h in removed_nodes:
        was_on_path = any(h in p for p in a_paths)
        severity_counts["critical" if was_on_path else "warning"] += 1
    for h in added_nodes:
        severity_counts["info"] += 1
    for n in modified_nodes:
        severity_counts[n["severity"]] += 1
        # Check the individual field changes for critical-flavored ones
        for c in n["changes"]:
            if c["field"] == "verdict":
                bad = {"warning", "critical", "unreachable"}
                good = {"healthy"}
                if c.get("from") in good and c.get("to") in bad:
                    has_verdict_worsened = True
            elif c["field"] == "reachable":
                if c.get("from") is True and c.get("to") is False:
                    has_reachability_loss = True
    for _ in removed_edges:
        severity_counts["warning"] += 1
    for _ in added_edges:
        severity_counts["info"] += 1
    for _ in removed_paths:
        severity_counts["warning"] += 1
    for _ in added_paths:
        severity_counts["info"] += 1

    # Continuous capacity metrics
    impairment = compute_impairment(a, b, a_paths, b_paths,
                                    removed_edges, added_edges)
    verdict = compute_verdict(impairment, severity_counts,
                              has_verdict_worsened, has_reachability_loss)

    return {
        "schema_version": SCHEMA_VERSION,
        "a": {
            "target_prefix": a["meta"].get("target_prefix"),
            "source_host": a["meta"].get("source_host"),
            "completed_at": a["meta"].get("completed_at"),
            "total_devices": a["meta"].get("total_devices"),
            "total_edges": a["meta"].get("total_edges"),
            "total_paths": len(a_paths),
        },
        "b": {
            "target_prefix": b["meta"].get("target_prefix"),
            "source_host": b["meta"].get("source_host"),
            "completed_at": b["meta"].get("completed_at"),
            "total_devices": b["meta"].get("total_devices"),
            "total_edges": b["meta"].get("total_edges"),
            "total_paths": len(b_paths),
        },
        "meta_delta": meta_delta,
        "impairment": impairment,
        "verdict": verdict,
        "severity_counts": severity_counts,
        "nodes": {
            "removed": removed_nodes,
            "added": added_nodes,
            "modified": modified_nodes,
        },
        "edges": {
            "removed": removed_edges,
            "added": added_edges,
        },
        "paths": {
            "removed": [list(p) for p in removed_paths],
            "added": [list(p) for p in added_paths],
            "preserved": [list(p) for p in preserved_paths],
        },
    }


# ──────────────────────────────────────────────────────────────
# Renderers
# ──────────────────────────────────────────────────────────────

def _fmt_pct(p) -> str:
    if p is None:
        return "n/a"
    return f"{p:+.0%}"


def render_summary(delta: dict, name_a: str, name_b: str) -> str:
    """One-line-ish summary for pipelines and quick sanity checks."""
    imp = delta["impairment"]
    verdict = delta["verdict"]
    sc = delta["severity_counts"]
    md = delta["meta_delta"]

    def signed(n):
        return f"+{n}" if n > 0 else str(n)

    level = verdict["level"]
    level_display = level.upper() if level == "critical" else level
    reasons = ", ".join(verdict["reasons"]) if verdict["reasons"] else "no changes"

    lines = [
        f"{name_a}  ->  {name_b}",
        f"  target:  {delta['a'].get('target_prefix')}  ->  {delta['b'].get('target_prefix')}",
        f"  devices: {delta['a']['total_devices']} -> {delta['b']['total_devices']} ({signed(md['devices'])})   "
        f"edges: {delta['a']['total_edges']} -> {delta['b']['total_edges']} ({signed(md['edges'])})   "
        f"paths: {delta['a']['total_paths']} -> {delta['b']['total_paths']} ({signed(md['paths'])})",
        f"  impairment: paths {_fmt_pct(imp['paths_pct'])}  "
        f"edges {_fmt_pct(imp['edges_pct'])}  "
        f"ecmp-width {_fmt_pct(imp['ecmp_width_pct'])}  "
        f"churn {_fmt_pct(imp['churn_pct'])}",
        f"  changes:    critical={sc['critical']}  warning={sc['warning']}  info={sc['info']}",
        f"  verdict: {level_display}  ({reasons})",
    ]
    return "\n".join(lines)


def _fmt_change(change: dict) -> str:
    field = change["field"]
    if field in SET_NODE_FIELDS or "removed" in change:
        parts = []
        if change.get("removed"):
            parts.append(f"-{{{', '.join(change['removed'])}}}")
        if change.get("added"):
            parts.append(f"+{{{', '.join(change['added'])}}}")
        return f"{field}: {' '.join(parts)}"
    return f"{field}: {change['from']!r} -> {change['to']!r}"


def render_markdown(delta: dict, name_a: str, name_b: str) -> str:
    """MOP-ready markdown report."""
    sc = delta["severity_counts"]
    md = delta["meta_delta"]
    imp = delta["impairment"]
    verdict = delta["verdict"]
    a, b = delta["a"], delta["b"]

    lines = []
    lines.append("# Forwarding Chain Diff")
    lines.append("")
    lines.append(f"**A:** `{name_a}`  ")
    lines.append(f"**B:** `{name_b}`  ")
    lines.append("")

    # Verdict callout — the top line a reviewer should see
    level = verdict["level"]
    level_display = "**CRITICAL**" if level == "critical" else f"**{level}**"
    reasons = "; ".join(verdict["reasons"]) if verdict["reasons"] else "no changes detected"
    lines.append(f"**Verdict:** {level_display} — {reasons}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | A | B | Delta |")
    lines.append("|---|---|---|---|")

    def signed(n):
        return f"+{n}" if n > 0 else str(n)

    lines.append(f"| Target prefix | `{a.get('target_prefix')}` | `{b.get('target_prefix')}` | — |")
    lines.append(f"| Source host | `{a.get('source_host')}` | `{b.get('source_host')}` | — |")
    lines.append(f"| Devices | {a['total_devices']} | {b['total_devices']} | {signed(md['devices'])} |")
    lines.append(f"| Edges | {a['total_edges']} | {b['total_edges']} | {signed(md['edges'])} |")
    lines.append(f"| Paths | {a['total_paths']} | {b['total_paths']} | {signed(md['paths'])} |")
    lines.append(
        f"| ECMP fan-out width | {imp['ecmp_width_before']} | {imp['ecmp_width_after']} | "
        f"{signed(imp['ecmp_width_after'] - imp['ecmp_width_before'])} |"
    )
    lines.append("")
    lines.append("### Impairment")
    lines.append("")
    lines.append("| Dimension | Impairment |")
    lines.append("|---|---|")
    lines.append(f"| Paths | {_fmt_pct(imp['paths_pct'])} |")
    lines.append(f"| Edges | {_fmt_pct(imp['edges_pct'])} |")
    lines.append(f"| ECMP width | {_fmt_pct(imp['ecmp_width_pct'])} |")
    lines.append(f"| Path churn | {_fmt_pct(imp['churn_pct'])} |")
    lines.append("")
    lines.append(
        f"**Change counts:** critical={sc['critical']}, "
        f"warning={sc['warning']}, info={sc['info']}"
    )
    lines.append("")

    # Modified nodes, sorted by severity
    sev_order = {"critical": 0, "warning": 1, "info": 2}
    mods_by_sev = sorted(delta["nodes"]["modified"], key=lambda n: (sev_order[n["severity"]], n["hostname"]))

    critical_mods = [n for n in mods_by_sev if n["severity"] == "critical"]
    warning_mods = [n for n in mods_by_sev if n["severity"] == "warning"]
    info_mods = [n for n in mods_by_sev if n["severity"] == "info"]

    if critical_mods:
        lines.append("## Critical changes")
        lines.append("")
        for n in critical_mods:
            lines.append(f"### `{n['hostname']}`")
            lines.append("")
            for c in n["changes"]:
                if _severity_of_node_change(c) == "critical":
                    lines.append(f"- **{_fmt_change(c)}**")
                else:
                    lines.append(f"- {_fmt_change(c)}")
            lines.append("")

    # Preserved paths — the surviving forwarding routes through the live
    # fabric. This is the MOP reassurance section: "here's what's still
    # carrying traffic after the change." Rendered even when there are no
    # critical changes, because it's the primary validation artifact.
    preserved = delta["paths"].get("preserved", [])
    if preserved:
        lines.append("## Paths preserved")
        lines.append("")
        lines.append(
            f"{len(preserved)} of {delta['a']['total_paths']} forwarding "
            f"paths survived the change. These routes were present in both "
            f"snapshots and continue to carry traffic."
        )
        lines.append("")
        for p in preserved:
            lines.append(f"- {' -> '.join(p)}")
        lines.append("")

    if delta["nodes"]["removed"]:
        lines.append("## Nodes removed in B")
        lines.append("")
        for h in delta["nodes"]["removed"]:
            lines.append(f"- `{h}`")
        lines.append("")

    if delta["paths"]["removed"]:
        lines.append("## Paths removed in B")
        lines.append("")
        for p in delta["paths"]["removed"]:
            lines.append(f"- {' -> '.join(p)}")
        lines.append("")

    if delta["edges"]["removed"]:
        lines.append("## Edges removed in B")
        lines.append("")
        for e in delta["edges"]["removed"]:
            lines.append(
                f"- `{e['from']}` -> `{e['to']}` via "
                f"`{e.get('egress_interface') or '—'}` "
                f"(nh `{e.get('next_hop_ip') or '—'}`)"
            )
        lines.append("")

    if warning_mods:
        lines.append("## Warnings")
        lines.append("")
        for n in warning_mods:
            lines.append(f"### `{n['hostname']}`")
            lines.append("")
            for c in n["changes"]:
                lines.append(f"- {_fmt_change(c)}")
            lines.append("")

    if delta["nodes"]["added"]:
        lines.append("## Nodes added in B")
        lines.append("")
        for h in delta["nodes"]["added"]:
            lines.append(f"- `{h}`")
        lines.append("")

    if delta["paths"]["added"]:
        lines.append("## Paths added in B")
        lines.append("")
        for p in delta["paths"]["added"]:
            lines.append(f"- {' -> '.join(p)}")
        lines.append("")

    if delta["edges"]["added"]:
        lines.append("## Edges added in B")
        lines.append("")
        for e in delta["edges"]["added"]:
            lines.append(
                f"- `{e['from']}` -> `{e['to']}` via "
                f"`{e.get('egress_interface') or '—'}` "
                f"(nh `{e.get('next_hop_ip') or '—'}`)"
            )
        lines.append("")

    if info_mods:
        lines.append("## Informational changes")
        lines.append("")
        for n in info_mods:
            lines.append(f"### `{n['hostname']}`")
            lines.append("")
            for c in n["changes"]:
                lines.append(f"- {_fmt_change(c)}")
            lines.append("")

    if not any([critical_mods, warning_mods, info_mods,
                delta["nodes"]["removed"], delta["nodes"]["added"],
                delta["edges"]["removed"], delta["edges"]["added"],
                delta["paths"]["removed"], delta["paths"]["added"]]):
        lines.append("## No changes detected")
        lines.append("")
        lines.append("Both forwarding graphs are structurally and functionally equivalent.")
        lines.append("")

    return "\n".join(lines)


def render_json(delta: dict) -> str:
    return json.dumps(delta, indent=2, sort_keys=True)


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fibtrace diff",
        description="Compare two fibtrace forwarding graphs.",
    )
    ap.add_argument("file_a", help="Baseline graph JSON (pre-change)")
    ap.add_argument("file_b", help="Comparison graph JSON (post-change)")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--summary", action="store_true",
                      help="One-line summary to stdout (default)")
    mode.add_argument("--json", action="store_true",
                      help="Structured delta as JSON to stdout")
    mode.add_argument("--markdown", action="store_true",
                      help="MOP-ready markdown report to stdout")

    ap.add_argument("-o", "--output", help="Write output to file instead of stdout")
    ap.add_argument("--exit-nonzero-on-critical", action="store_true",
                    help="Exit 2 if any critical-severity change detected (for pipelines)")

    args = ap.parse_args(argv)

    try:
        a = load_graph(args.file_a)
        b = load_graph(args.file_b)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    delta = diff_graphs(a, b)

    name_a = Path(args.file_a).name
    name_b = Path(args.file_b).name

    if args.json:
        out = render_json(delta)
    elif args.markdown:
        out = render_markdown(delta, name_a, name_b)
    else:
        out = render_summary(delta, name_a, name_b)

    if args.output:
        Path(args.output).write_text(out + ("\n" if not out.endswith("\n") else ""))
    else:
        print(out)

    if args.exit_nonzero_on_critical and delta["verdict"]["level"] == "critical":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())