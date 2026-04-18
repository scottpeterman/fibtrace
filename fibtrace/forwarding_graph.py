"""
Forwarding Graph — DAG representation of the traced forwarding path.

The flat list[Hop] in ForwardingChain can't represent ECMP fan-out and
convergence. This module provides a proper directed acyclic graph where:

  - Nodes  = devices (keyed by hostname)
  - Edges  = forwarding decisions (parent → child via interface/next-hop)
  - ECMP   = node with multiple outgoing edges
  - Convergence = node with multiple incoming edges

Built incrementally during BFS traversal. Each walker event maps to
exactly one graph mutation:

  Walker event                  Graph mutation
  ─────────────────────────────────────────────
  New hop gathered              add_node() + add_edge()
  ECMP convergence detected     add_edge() (node already exists)
  Unreachable next-hop          add_node(reachable=False) + add_edge()
  Loop detected                 add_edge(is_loop=True)

The graph is JSON-serializable for diagnostics, and provides helpers
for tree rendering, DOT export, and path enumeration.

Usage in walker.py:

    # In __init__:
    self._graph = ForwardingGraph(target_prefix, source_host)

    # After _gather_forwarding_state:
    node_id = self._graph.add_node(...)

    # After enqueuing next-hops:
    for next_ip in hop.next_device_ips:
        self._graph.add_edge(...)

    # On convergence:
    self._graph.add_edge(parent, converged_hostname, ...)

    # After walk:
    self._graph.to_dict()   → JSON-safe dict
    self._graph.to_json()   → JSON string
    self._graph.to_dot()    → Graphviz DOT
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
import json as json_mod


# ────────────────────────────────────────────────────────
# Graph Elements
# ────────────────────────────────────────────────────────

@dataclass
class PathNode:
    """A device in the forwarding path."""
    hostname: str
    ssh_target: str                         # IP used to reach this device
    platform: str = "unknown"
    depth: int = 0                          # BFS depth (first visit)

    # Forwarding state (populated after gather)
    verdict: str = "pending"
    is_terminal: bool = False
    is_connected: bool = False              # route is connected/local
    reachable: bool = True                  # SSH succeeded

    # Route summary for diagnostics
    route_summary: Optional[str] = None     # e.g. "OSPF/10 metric 12"
    fib_summary: Optional[str] = None       # e.g. "programmed, 2 path(s)"
    egress_interfaces: list[str] = field(default_factory=list)

    # Structural properties (computed by graph)
    is_ecmp_branch: bool = False            # >1 outgoing edges
    is_convergence: bool = False            # >1 incoming edges
    is_loop_member: bool = False            # part of a detected loop

    # Raw hop data — optional, for deep diagnostics
    hop_data: Optional[dict] = None


@dataclass
class PathEdge:
    """A forwarding decision from one device to another."""
    from_hostname: str
    to_hostname: str

    # Forwarding details
    egress_interface: Optional[str] = None  # interface on from_device
    next_hop_ip: Optional[str] = None       # FIB/RIB next-hop address
    address_family: str = "ipv4"            # ipv4 or ipv6

    # Edge classification
    is_ecmp_sibling: bool = False           # part of ECMP fan-out
    is_convergence: bool = False            # edge to an already-visited node
    is_loop: bool = False                   # edge creating a forwarding loop

    # BFS metadata
    depth: int = 0                          # depth of from_device
    enqueue_order: int = 0                  # global ordering for replay


# ────────────────────────────────────────────────────────
# Forwarding Graph (DAG)
# ────────────────────────────────────────────────────────

class ForwardingGraph:
    """
    Directed acyclic graph of the forwarding path.

    Nodes are keyed by hostname. Edges are ordered by BFS discovery.
    Incrementally built during the walker's BFS traversal.
    """

    def __init__(self, target_prefix: str, source_host: str):
        self.target_prefix = target_prefix
        self.source_host = source_host
        self.root_hostname: Optional[str] = None

        self._nodes: dict[str, PathNode] = {}       # hostname → PathNode
        self._edges: list[PathEdge] = []
        self._edge_index: int = 0                    # monotonic counter

        # Adjacency for fast lookup
        self._children: dict[str, list[str]] = {}    # hostname → [child hostnames]
        self._parents: dict[str, list[str]] = {}     # hostname → [parent hostnames]

        # Timing
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

    # ────────────────────────────────────────────
    # Build API — called during BFS
    # ────────────────────────────────────────────

    def add_node(
        self,
        hostname: str,
        ssh_target: str,
        platform: str = "unknown",
        depth: int = 0,
        verdict: str = "pending",
        is_terminal: bool = False,
        is_connected: bool = False,
        reachable: bool = True,
        route_summary: Optional[str] = None,
        fib_summary: Optional[str] = None,
        egress_interfaces: Optional[list[str]] = None,
        hop_data: Optional[dict] = None,
    ) -> PathNode:
        """
        Add or update a device node. Safe to call multiple times
        for the same hostname — later calls update fields.
        """
        if hostname in self._nodes:
            # Update existing — convergence or re-evaluation
            node = self._nodes[hostname]
            if verdict != "pending":
                node.verdict = verdict
            if route_summary:
                node.route_summary = route_summary
            if fib_summary:
                node.fib_summary = fib_summary
            return node

        node = PathNode(
            hostname=hostname,
            ssh_target=ssh_target,
            platform=platform,
            depth=depth,
            verdict=verdict,
            is_terminal=is_terminal,
            is_connected=is_connected,
            reachable=reachable,
            route_summary=route_summary,
            fib_summary=fib_summary,
            egress_interfaces=egress_interfaces or [],
            hop_data=hop_data,
        )
        self._nodes[hostname] = node

        if hostname not in self._children:
            self._children[hostname] = []
        if hostname not in self._parents:
            self._parents[hostname] = []

        # First node added is root
        if self.root_hostname is None:
            self.root_hostname = hostname

        return node

    def add_edge(
        self,
        from_hostname: str,
        to_hostname: str,
        egress_interface: Optional[str] = None,
        next_hop_ip: Optional[str] = None,
        address_family: str = "ipv4",
        depth: int = 0,
        is_convergence: bool = False,
        is_loop: bool = False,
    ) -> PathEdge:
        """
        Add a forwarding edge. Automatically detects ECMP siblings
        and updates node structural flags.
        """
        # Dedup — don't add the same edge twice
        for existing in self._edges:
            if (existing.from_hostname == from_hostname
                    and existing.to_hostname == to_hostname
                    and existing.egress_interface == egress_interface):
                return existing

        edge = PathEdge(
            from_hostname=from_hostname,
            to_hostname=to_hostname,
            egress_interface=egress_interface,
            next_hop_ip=next_hop_ip,
            address_family=address_family,
            is_convergence=is_convergence,
            is_loop=is_loop,
            depth=depth,
            enqueue_order=self._edge_index,
        )
        self._edge_index += 1
        self._edges.append(edge)

        # Update adjacency
        if from_hostname not in self._children:
            self._children[from_hostname] = []
        if to_hostname not in self._parents:
            self._parents[to_hostname] = []

        if to_hostname not in self._children[from_hostname]:
            self._children[from_hostname].append(to_hostname)
        if from_hostname not in self._parents[to_hostname]:
            self._parents[to_hostname].append(from_hostname)

        # Recompute structural flags
        self._update_flags(from_hostname)
        self._update_flags(to_hostname)

        # Mark ECMP siblings — all edges from same parent are siblings
        # when there are 2+ outgoing edges
        if len(self._children.get(from_hostname, [])) > 1:
            for e in self._edges:
                if e.from_hostname == from_hostname:
                    e.is_ecmp_sibling = True

        return edge

    def _update_flags(self, hostname: str):
        """Recompute structural flags for a node."""
        node = self._nodes.get(hostname)
        if node is None:
            return

        out_count = len(self._children.get(hostname, []))
        in_count = len(self._parents.get(hostname, []))

        node.is_ecmp_branch = out_count > 1
        node.is_convergence = in_count > 1
        node.is_loop_member = any(
            e.is_loop for e in self._edges
            if e.from_hostname == hostname or e.to_hostname == hostname
        )

    # ────────────────────────────────────────────
    # Query API
    # ────────────────────────────────────────────

    @property
    def nodes(self) -> dict[str, PathNode]:
        return self._nodes

    @property
    def edges(self) -> list[PathEdge]:
        return self._edges

    @property
    def ecmp_branch_points(self) -> list[str]:
        """Hostnames where ECMP fan-out occurs."""
        return [h for h, node in self._nodes.items() if node.is_ecmp_branch]

    @property
    def ecmp_branch_count(self) -> int:
        return len(self.ecmp_branch_points)

    @property
    def convergence_points(self) -> list[str]:
        """Hostnames where ECMP paths reconverge."""
        return [h for h, node in self._nodes.items() if node.is_convergence]

    @property
    def total_devices(self) -> int:
        return len(self._nodes)

    @property
    def total_edges(self) -> int:
        return len(self._edges)

    def children_of(self, hostname: str) -> list[str]:
        return self._children.get(hostname, [])

    def parents_of(self, hostname: str) -> list[str]:
        return self._parents.get(hostname, [])

    def edges_from(self, hostname: str) -> list[PathEdge]:
        """All outgoing edges from a device."""
        return [e for e in self._edges if e.from_hostname == hostname]

    def edges_to(self, hostname: str) -> list[PathEdge]:
        """All incoming edges to a device."""
        return [e for e in self._edges if e.to_hostname == hostname]

    def enumerate_paths(self) -> list[list[str]]:
        """
        Enumerate all unique source-to-terminal paths.
        Returns list of [hostname, hostname, ...] paths.
        Useful for validating ECMP symmetry.
        """
        if self.root_hostname is None:
            return []

        paths: list[list[str]] = []

        def _dfs(current: str, path: list[str], visited: set[str]):
            path.append(current)
            visited.add(current)

            children = self._children.get(current, [])
            node = self._nodes.get(current)

            # Terminal: no children or node is terminal
            if not children or (node and node.is_terminal):
                paths.append(list(path))
            else:
                for child in children:
                    if child not in visited:  # avoid loops
                        _dfs(child, path, visited.copy())

            path.pop()

        _dfs(self.root_hostname, [], set())
        return paths

    # ────────────────────────────────────────────
    # Serialization
    # ────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe dictionary of the full graph."""
        return {
            "meta": {
                "target_prefix": self.target_prefix,
                "source_host": self.source_host,
                "root_hostname": self.root_hostname,
                "total_devices": self.total_devices,
                "total_edges": self.total_edges,
                "ecmp_branch_points": self.ecmp_branch_points,
                "convergence_points": self.convergence_points,
                "paths": self.enumerate_paths(),
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            },
            "nodes": {
                hostname: {
                    "hostname": n.hostname,
                    "ssh_target": n.ssh_target,
                    "platform": n.platform,
                    "depth": n.depth,
                    "verdict": n.verdict,
                    "is_terminal": n.is_terminal,
                    "is_connected": n.is_connected,
                    "reachable": n.reachable,
                    "route_summary": n.route_summary,
                    "fib_summary": n.fib_summary,
                    "egress_interfaces": n.egress_interfaces,
                    "is_ecmp_branch": n.is_ecmp_branch,
                    "is_convergence": n.is_convergence,
                    "is_loop_member": n.is_loop_member,
                    "children": self._children.get(hostname, []),
                    "parents": self._parents.get(hostname, []),
                }
                for hostname, n in self._nodes.items()
            },
            "edges": [
                {
                    "from": e.from_hostname,
                    "to": e.to_hostname,
                    "egress_interface": e.egress_interface,
                    "next_hop_ip": e.next_hop_ip,
                    "address_family": e.address_family,
                    "is_ecmp_sibling": e.is_ecmp_sibling,
                    "is_convergence": e.is_convergence,
                    "is_loop": e.is_loop,
                    "depth": e.depth,
                    "order": e.enqueue_order,
                }
                for e in self._edges
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize graph to JSON string."""
        return json_mod.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str):
        """Write graph JSON to file."""
        with open(path, 'w') as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> ForwardingGraph:
        """Reconstruct graph from saved JSON."""
        with open(path) as f:
            data = json_mod.load(f)

        meta = data["meta"]
        graph = cls(
            target_prefix=meta["target_prefix"],
            source_host=meta["source_host"],
        )

        # Rebuild nodes
        for hostname, ndata in data["nodes"].items():
            graph.add_node(
                hostname=ndata["hostname"],
                ssh_target=ndata["ssh_target"],
                platform=ndata.get("platform", "unknown"),
                depth=ndata.get("depth", 0),
                verdict=ndata.get("verdict", "unknown"),
                is_terminal=ndata.get("is_terminal", False),
                is_connected=ndata.get("is_connected", False),
                reachable=ndata.get("reachable", True),
                route_summary=ndata.get("route_summary"),
                fib_summary=ndata.get("fib_summary"),
                egress_interfaces=ndata.get("egress_interfaces", []),
            )

        # Rebuild edges
        for edata in data["edges"]:
            graph.add_edge(
                from_hostname=edata["from"],
                to_hostname=edata["to"],
                egress_interface=edata.get("egress_interface"),
                next_hop_ip=edata.get("next_hop_ip"),
                address_family=edata.get("address_family", "ipv4"),
                depth=edata.get("depth", 0),
                is_convergence=edata.get("is_convergence", False),
                is_loop=edata.get("is_loop", False),
            )

        return graph

    # ────────────────────────────────────────────
    # Export: Graphviz DOT
    # ────────────────────────────────────────────

    def to_dot(self) -> str:
        """
        Export as Graphviz DOT for visualization.
        ECMP branches highlighted, convergence points marked.
        """
        lines = [
            'digraph forwarding_path {',
            '    rankdir=TB;',
            '    node [shape=box, style=rounded, fontname="Helvetica"];',
            '    edge [fontname="Helvetica", fontsize=10];',
            '',
        ]

        for hostname, node in self._nodes.items():
            label_parts = [hostname]

            if node.platform != "unknown":
                label_parts.append(f"({node.platform})")
            if node.verdict:
                label_parts.append(node.verdict.upper())

            # Color coding
            label = "\\n".join(label_parts)
            attr_strs = [f'label="{label}"']
            if not node.reachable:
                attr_strs += ['fillcolor="#ff4444"', 'style="rounded,filled"']
            elif node.is_terminal and node.is_connected:
                attr_strs += ['fillcolor="#00cc66"', 'style="rounded,filled"']
            elif node.is_ecmp_branch:
                attr_strs += ['fillcolor="#00d4ff"', 'style="rounded,filled"']
            elif node.is_convergence:
                attr_strs += ['fillcolor="#ffcc00"', 'style="rounded,filled"']

            safe_name = hostname.replace('-', '_').replace('.', '_')
            lines.append(f'    {safe_name} [{", ".join(attr_strs)}];')

        lines.append('')

        for edge in self._edges:
            from_safe = edge.from_hostname.replace('-', '_').replace('.', '_')
            to_safe = edge.to_hostname.replace('-', '_').replace('.', '_')

            label_parts = []
            if edge.egress_interface:
                label_parts.append(edge.egress_interface)
            if edge.next_hop_ip:
                label_parts.append(str(edge.next_hop_ip))
            label = "\\n".join(label_parts)

            attrs = [f'label="{label}"']
            if edge.is_loop:
                attrs.append('color="red"')
                attrs.append('style=bold')
            elif edge.is_convergence:
                attrs.append('style=dashed')
                attrs.append('color="#888888"')
            elif edge.is_ecmp_sibling:
                attrs.append('color="#00d4ff"')

            lines.append(f'    {from_safe} -> {to_safe} [{", ".join(attrs)}];')

        lines.append('}')
        return '\n'.join(lines)

    # ────────────────────────────────────────────
    # Export: DrawIO CSV (for Scott's preference)
    # ────────────────────────────────────────────

    def to_drawio_csv(self) -> str:
        """
        Export as CSV importable by DrawIO's "Insert → Advanced → CSV".
        Produces a network-style diagram with device shapes.
        """
        lines = [
            '## ForwardingGraph: {prefix}'.format(prefix=self.target_prefix),
            '# label: %hostname%',
            '# style: shape=mxgraph.cisco19.rect;',
            '# connect: {"from": "children", "to": "hostname", '
            '"style": "curved=1;endArrow=blockThin;endFill=1;"}',
            '# width: 120',
            '# height: 60',
            '# padding: 20',
            '# ignore: children,ssh_target,depth',
            '## ',
            'hostname,platform,verdict,children,ssh_target,depth',
        ]

        for hostname, node in self._nodes.items():
            children_str = ",".join(self._children.get(hostname, []))
            lines.append(
                f'{hostname},{node.platform},{node.verdict},'
                f'"{children_str}",{node.ssh_target},{node.depth}'
            )

        return '\n'.join(lines)

    # ────────────────────────────────────────────
    # Pretty Print (terminal)
    # ────────────────────────────────────────────

    def print_tree(self, use_rich: bool = False) -> str:
        """
        Render as an indented tree with ECMP branches shown.
        Convergence nodes marked with ↪.
        """
        if self.root_hostname is None:
            return "(empty graph)"

        lines: list[str] = []
        lines.append(f"🔍 {self.target_prefix}")

        def _render(hostname: str, prefix: str, is_last: bool,
                    visited: set[str]):
            connector = "└── " if is_last else "├── "
            node = self._nodes.get(hostname)
            if node is None:
                lines.append(f"{prefix}{connector}? {hostname}")
                return

            # Node label
            verdict_icon = "✓" if node.verdict == "healthy" else "✗"
            if node.verdict == "pending":
                verdict_icon = "?"

            egress = ""
            edges_in = self.edges_to(hostname)
            if edges_in:
                # Show interface from parent's edge
                last_edge = edges_in[-1]
                parts = []
                if last_edge.egress_interface:
                    parts.append(last_edge.egress_interface)
                if last_edge.next_hop_ip:
                    parts.append(f"→ {last_edge.next_hop_ip}")
                egress = "  ".join(parts)

            ecmp_tag = ""
            if node.is_ecmp_branch:
                out_count = len(self._children.get(hostname, []))
                ecmp_tag = f"  ECMP: {out_count} paths"

            convergence_tag = ""
            if hostname in visited:
                lines.append(
                    f"{prefix}{connector}↪ {hostname}  (converges)"
                )
                return
            if node.is_convergence:
                convergence_tag = "  (convergence point)"

            connected_tag = "  (connected)" if node.is_connected else ""

            label = (f"{prefix}{connector}{verdict_icon} {hostname}"
                     f"  {egress}{ecmp_tag}{convergence_tag}{connected_tag}")
            lines.append(label)

            visited.add(hostname)

            # Recurse children
            children = self._children.get(hostname, [])
            child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(children):
                _render(child, child_prefix, i == len(children) - 1,
                        visited.copy())  # copy so parallel branches work

        _render(self.root_hostname, "", True, set())

        summary = (
            f"\n{self.total_devices} devices │ "
            f"{self.total_edges} edges │ "
            f"{self.ecmp_branch_count} ECMP branches │ "
            f"{len(self.convergence_points)} convergence points"
        )
        lines.append(summary)

        paths = self.enumerate_paths()
        if paths:
            lines.append(f"{len(paths)} unique paths:")
            for i, path in enumerate(paths):
                lines.append(f"  path {i}: {' → '.join(path)}")

        return '\n'.join(lines)