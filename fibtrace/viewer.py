"""
Forwarding Graph Viewer — open the packaged HTML visualizer in a browser.

The viewer handles file loading via drag-drop, paste, or browse.
Graph JSON files come from:
    fibtrace-cli ... --json > trace.json
    fibtrace-cli ... --graph trace.graph.json

Usage:
    fibtrace-view                  # launch the viewer
    fibtrace-view -o viewer.html   # copy the HTML to a local path
"""

from __future__ import annotations
import os
import shutil
import sys
import tempfile
import webbrowser
from pathlib import Path


def _get_template_path() -> Path:
    """Locate the packaged HTML template."""
    template = Path(__file__).parent / "fibtrace_viewer.html"
    if not template.exists():
        raise FileNotFoundError(
            f"Viewer template not found at {template}. "
            f"Ensure fibtrace_viewer.html is in the fibtrace package directory."
        )
    return template


def launch_viewer(output_path: str | None = None) -> str:
    """
    Open the graph viewer in the default browser.

    Args:
        output_path: If set, copy the HTML here (useful for sharing).

    Returns:
        Path to the HTML file that was opened.
    """
    template = _get_template_path()

    if output_path:
        dest = Path(output_path)
        shutil.copy2(template, dest)
        html_path = str(dest.resolve())
    else:
        fd, html_path = tempfile.mkstemp(suffix=".html", prefix="fibtrace_")
        os.close(fd)
        shutil.copy2(template, html_path)

    webbrowser.open(f"file://{os.path.abspath(html_path)}")
    return html_path


def main(argv=None):
    """CLI entry point: fibtrace view"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="fibtrace view",
        description=(
            "Open the fibtrace forwarding graph viewer in a browser. "
            "Load graph files via drag-drop, paste, or the Load button."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Copy the viewer HTML to this path instead of a temp file",
    )
    args = parser.parse_args(argv)

    html_path = launch_viewer(output_path=args.output)
    print(html_path, file=sys.stderr)


if __name__ == "__main__":
    main()