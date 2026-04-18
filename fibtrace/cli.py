"""Unified CLI dispatcher for fibtrace.

Invoked via the `fibtrace` console script or `python -m fibtrace`.

Subcommands forward argv to each module's own argparse — so
`fibtrace walk --help` prints walker's help, `fibtrace diff --help`
prints diff's help, etc. Imports are deferred per-subcommand so that
`fibtrace walk` doesn't pull in textual, `fibtrace diff` doesn't pull
in paramiko, and neither pulls in fastapi.
"""
from __future__ import annotations

import sys
from typing import Callable, Optional, Sequence


_USAGE = """\
usage: fibtrace <subcommand> [options]

subcommands:
  walk        walk the forwarding chain (headless)
  diff        compare two forwarding graph JSON files
  view        open the HTML graph viewer in a browser
  tui         textual TUI — live forwarding chain visualization
  web         run the FastAPI web dashboard

options:
  -h, --help      show this message
  -V, --version   show the fibtrace version

Run 'fibtrace <subcommand> --help' for subcommand-specific options.
"""


def _run_walk(argv: Sequence[str]) -> int:
    from .walker import main as walker_main
    return walker_main(list(argv)) or 0


def _run_diff(argv: Sequence[str]) -> int:
    from .diff import main as diff_main
    return diff_main(list(argv)) or 0


def _run_view(argv: Sequence[str]) -> int:
    from .viewer import main as viewer_main
    return viewer_main(list(argv)) or 0


def _run_tui(argv: Sequence[str]) -> int:
    from .tui import main as tui_main
    return tui_main(list(argv)) or 0


def _run_web(argv: Sequence[str]) -> int:
    from .web.__main__ import main as web_main
    return web_main(list(argv)) or 0


_SUBCOMMANDS: dict[str, Callable[[Sequence[str]], int]] = {
    "walk": _run_walk,
    "diff": _run_diff,
    "view": _run_view,
    "tui":  _run_tui,
    "web":  _run_web,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0

    if argv[0] in ("-V", "--version", "version"):
        from . import __version__
        print(f"fibtrace {__version__}")
        return 0

    subcommand, sub_argv = argv[0], argv[1:]

    handler = _SUBCOMMANDS.get(subcommand)
    if handler is None:
        sys.stderr.write(f"fibtrace: unknown subcommand '{subcommand}'\n\n")
        sys.stderr.write(_USAGE)
        return 2

    return handler(sub_argv)


if __name__ == "__main__":
    raise SystemExit(main())