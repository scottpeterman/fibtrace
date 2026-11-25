"""python -m fibtrace.web — run the FastAPI dashboard.

Also invoked by the unified CLI as `fibtrace web`. Requires `fibtrace[web]`.
"""
from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fibtrace web",
        description="Run the fibtrace web dashboard (FastAPI + uvicorn).",
    )
    p.add_argument("--host", default="0.0.0.0",
                   help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8100,
                   help="Port (default: 8100)")
    p.add_argument("--reload", action="store_true",
                   help="Auto-reload on code changes (dev only)")
    p.add_argument("--log-level", default="info",
                   choices=["critical", "error", "warning", "info", "debug"],
                   help="uvicorn log level (default: info)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "fibtrace web requires the [web] extra:\n"
            "    pip install 'fibtrace[web]'",
            file=sys.stderr,
        )
        return 1

    # reload mode requires an import string rather than an app object so
    # uvicorn's supervisor can re-import after file changes.
    if args.reload:
        uvicorn.run(
            "fibtrace.web.app:app",
            host=args.host,
            port=args.port,
            reload=True,
            log_level=args.log_level,
        )
    else:
        from .app import app
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level=args.log_level,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())