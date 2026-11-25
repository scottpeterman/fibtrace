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
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8100,
                   help="Port (default: 8100)")
    p.add_argument("--reload", action="store_true",
                   help="Auto-reload on code changes (dev only)")
    p.add_argument("--auth-config", default=None,
                   help="YAML/JSON auth config (provider, LDAP); default: $FIBTRACE_AUTH_CONFIG")
    p.add_argument("--hash-password", action="store_true",
                   help="prompt for a password, print its scrypt hash for FIBTRACE_USERS, and exit")
    p.add_argument("--log-level", default="info",
                   choices=["critical", "error", "warning", "info", "debug"],
                   help="uvicorn log level (default: info)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.hash_password:
        import getpass
        from .hashing import hash_password
        pw = getpass.getpass("password: ")
        if not pw or pw != getpass.getpass("again: "):
            print("passwords empty or do not match", file=sys.stderr)
            return 1
        print(hash_password(pw))
        return 0

    import ipaddress
    import os
    if args.auth_config:
        os.environ["FIBTRACE_AUTH_CONFIG"] = os.path.abspath(args.auth_config)

    # Build the chain once here so config errors fail fast, before uvicorn starts
    from .auth import AuthManager, load_auth_config
    try:
        auth = AuthManager(load_auth_config())
    except Exception as e:
        print(f"auth config error: {e}", file=sys.stderr)
        return 2

    try:
        loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        loopback = args.host == "localhost"
    problem = auth.exposure_problem()
    if problem and not loopback:
        print(
            f"refusing to bind {args.host}: {problem}.\n"
            "Set FIBTRACE_USERS to hashed accounts (fibtrace web --hash-password)\n"
            "or configure LDAP with --auth-config, or bind 127.0.0.1.",
            file=sys.stderr,
        )
        return 2
    print(f"fibtrace web: auth {auth.describe()}", file=sys.stderr)

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