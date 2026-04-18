"""
fibtrace-web — FastAPI front-end for fibtrace chain walker.

Run:
    uvicorn app:app --host 0.0.0.0 --port 8100 --reload

Requires:
    pip install fastapi uvicorn[standard] python-multipart itsdangerous jinja2 websockets
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import signal
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Request, Response,
    Depends, HTTPException, Form, status,
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ════════════════════════════════════════
# Configuration
# ════════════════════════════════════════

SECRET_KEY = os.environ.get("FIBTRACE_SECRET_KEY", secrets.token_hex(32))
SESSION_MAX_AGE = 86400  # 24 hours
FIBTRACE_MODULE = os.environ.get("FIBTRACE_MODULE", "fibtrace.walker")
FIBTRACE_PYTHON = os.environ.get("FIBTRACE_PYTHON", "python")
MAX_CONCURRENT_TRACES = int(os.environ.get("FIBTRACE_MAX_TRACES", "5"))

# Simple user store — override via environment or replace with your own auth.
# Format: FIBTRACE_USERS='{"admin":"changeme","scott":"hunter2"}'
_default_users = '{"admin": "fibtrace"}'
USERS: dict[str, str] = json.loads(
    os.environ.get("FIBTRACE_USERS", _default_users)
)

logger = logging.getLogger("fibtrace-web")

# ════════════════════════════════════════
# App Setup
# ════════════════════════════════════════

_PACKAGE_DIR = Path(__file__).parent
_STATIC_DIR = _PACKAGE_DIR / "static"

# Wheels and sdists don't preserve empty directories, so _STATIC_DIR may be
# absent on a pip-installed copy even though it exists in the source tree.
# Static assets are CDN-served today (xterm.js, fonts) so the directory is
# mainly a hook for future local assets — best-effort create, skip mount if
# the filesystem is read-only (some container / system-package installs).
try:
    _STATIC_DIR.mkdir(exist_ok=True)
except OSError:
    pass

app = FastAPI(title="fibtrace-web", docs_url=None, redoc_url=None)
if _STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
templates = Jinja2Templates(directory=_PACKAGE_DIR / "templates")
serializer = URLSafeTimedSerializer(SECRET_KEY)


# ════════════════════════════════════════
# Session Management
# ════════════════════════════════════════

def create_session(username: str) -> str:
    """Create a signed session token."""
    return serializer.dumps({"user": username, "sid": uuid.uuid4().hex[:8]})


def get_session(request: Request) -> Optional[dict]:
    """Validate session cookie. Returns session dict or None."""
    token = request.cookies.get("fibtrace_session")
    if not token:
        return None
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def require_session(request: Request) -> dict:
    """Dependency: require valid session or raise 401."""
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session


# ════════════════════════════════════════
# Trace Session Manager
# ════════════════════════════════════════

@dataclass
class TraceRun:
    """Tracks a running or completed fibtrace subprocess."""
    trace_id: str
    username: str
    prefix: str
    source: str
    started_at: datetime = field(default_factory=datetime.now)
    process: Optional[asyncio.subprocess.Process] = None
    graph_json: Optional[dict] = None
    completed: bool = False
    exit_code: Optional[int] = None


# Active traces keyed by trace_id
_traces: dict[str, TraceRun] = {}


def active_trace_count() -> int:
    return sum(1 for t in _traces.values() if not t.completed)


# ════════════════════════════════════════
# Routes — Auth
# ════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    session = get_session(request)
    if session:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if username in USERS and USERS[username] == password:
        token = create_session(username)
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            "fibtrace_session", token,
            httponly=True, samesite="lax", max_age=SESSION_MAX_AGE,
        )
        return response

    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": "Invalid credentials"},
        status_code=401,
    )


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("fibtrace_session")
    return response


# ════════════════════════════════════════
# Routes — Dashboard
# ════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", {
        "username": session["user"],
    })


# ════════════════════════════════════════
# Routes — Graph Viewer
# ════════════════════════════════════════

@app.get("/graph/{trace_id}", response_class=HTMLResponse)
async def graph_viewer(request: Request, trace_id: str):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)

    trace = _traces.get(trace_id)
    if not trace or not trace.graph_json:
        raise HTTPException(404, "Graph not found")

    return templates.TemplateResponse(request, "graph.html", {
        "trace_id": trace_id,
        "graph_json": json.dumps(trace.graph_json),
    })


@app.get("/viewer", response_class=HTMLResponse)
async def standalone_viewer(request: Request):
    """Standalone graph viewer — load saved .graph.json files without running a trace."""
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "viewer.html")


@app.get("/diff", response_class=HTMLResponse)
async def diff_viewer(request: Request):
    """Forwarding-graph diff viewer — drop two graph JSONs, see the delta.
    All diff computation runs client-side; no backend state required."""
    session = get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "diff_viewer.html")


@app.get("/api/graph/{trace_id}")
async def graph_json_api(request: Request, trace_id: str):
    session = get_session(request)
    if not session:
        raise HTTPException(401)
    trace = _traces.get(trace_id)
    if not trace or not trace.graph_json:
        raise HTTPException(404)
    return JSONResponse(trace.graph_json)


# ════════════════════════════════════════
# WebSocket — Trace Execution
# ════════════════════════════════════════

@app.websocket("/ws/trace")
async def ws_trace(websocket: WebSocket):
    await websocket.accept()

    # Validate session from cookie
    token = websocket.cookies.get("fibtrace_session")
    session = None
    if token:
        try:
            session = serializer.loads(token, max_age=SESSION_MAX_AGE)
        except (BadSignature, SignatureExpired):
            pass

    if not session:
        await websocket.send_json({"type": "error", "data": "Not authenticated"})
        await websocket.close()
        return

    username = session["user"]

    try:
        # Wait for trace parameters
        msg = await websocket.receive_json()
        if msg.get("type") != "start_trace":
            await websocket.send_json({"type": "error", "data": "Expected start_trace"})
            return

        params = msg.get("params", {})

        # Guard: concurrent trace limit
        if active_trace_count() >= MAX_CONCURRENT_TRACES:
            await websocket.send_json({
                "type": "error",
                "data": f"Max concurrent traces ({MAX_CONCURRENT_TRACES}) reached. "
                        f"Please wait for a running trace to complete.",
            })
            return

        # Build command
        trace_id = uuid.uuid4().hex[:12]
        graph_path = os.path.join(tempfile.gettempdir(), f"fibtrace_{trace_id}.graph.json")

        cmd = [
            FIBTRACE_PYTHON, "-m", FIBTRACE_MODULE,
            "--prefix", params["prefix"],
            "--source", params["source"],
            "--username", params["username"],
        ]

        if params.get("password"):
            cmd += ["--password", params["password"]]
        if params.get("key_file"):
            cmd += ["--key-file", params["key_file"]]
        if params.get("max_depth"):
            cmd += ["--max-depth", str(params["max_depth"])]
        if params.get("timeout"):
            cmd += ["--timeout", str(params["timeout"])]
        if params.get("legacy_ssh"):
            cmd.append("--legacy-ssh")
        if params.get("error_threshold"):
            cmd += ["--error-threshold", str(params["error_threshold"])]
        if params.get("skip_mac"):
            cmd.append("--skip-mac")
        if params.get("nh_source") and params["nh_source"] != "fib":
            cmd += ["--nh-source", params["nh_source"]]
        if params.get("domain"):
            cmd += ["--domain", params["domain"]]
        if params.get("verbose"):
            cmd.append("--verbose")
        if params.get("debug"):
            cmd.append("--debug")

        # Always capture JSON + graph for the viewer
        cmd.append("--json")
        cmd += ["--graph", graph_path]

        trace = TraceRun(
            trace_id=trace_id,
            username=username,
            prefix=params["prefix"],
            source=params["source"],
        )
        _traces[trace_id] = trace

        await websocket.send_json({
            "type": "trace_started",
            "trace_id": trace_id,
        })

        # Spawn subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        trace.process = process

        json_buffer = []

        async def stream_pipe(pipe, stream_name):
            """Read lines from pipe and send to WebSocket."""
            while True:
                line = await pipe.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace")

                # stderr = progress output → send to terminal
                # stdout = JSON result → buffer for graph + send to terminal
                if stream_name == "stdout":
                    json_buffer.append(decoded)

                await websocket.send_json({
                    "type": "output",
                    "stream": stream_name,
                    "data": decoded,
                })

        # Stream both stdout and stderr concurrently
        await asyncio.gather(
            stream_pipe(process.stdout, "stdout"),
            stream_pipe(process.stderr, "stderr"),
        )

        exit_code = await process.wait()
        trace.exit_code = exit_code
        trace.completed = True

        # Load graph JSON if it was written
        graph_loaded = False
        if os.path.exists(graph_path):
            try:
                with open(graph_path) as f:
                    trace.graph_json = json.load(f)
                graph_loaded = True
            except Exception as e:
                logger.warning(f"Failed to load graph: {e}")
            finally:
                try:
                    os.unlink(graph_path)
                except OSError:
                    pass

        # If graph file wasn't written, try parsing stdout JSON
        if not graph_loaded and json_buffer:
            try:
                full_output = "".join(json_buffer)
                parsed = json.loads(full_output)
                if "graph" in parsed and parsed["graph"]:
                    trace.graph_json = parsed["graph"]
                    graph_loaded = True
            except (json.JSONDecodeError, KeyError):
                pass

        await websocket.send_json({
            "type": "trace_done",
            "exit_code": exit_code,
            "trace_id": trace_id,
            "has_graph": graph_loaded,
        })

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for {username}")
        # Kill subprocess if still running
        if trace and trace.process and trace.process.returncode is None:
            try:
                trace.process.terminate()
                await asyncio.sleep(0.5)
                if trace.process.returncode is None:
                    trace.process.kill()
            except ProcessLookupError:
                pass
            trace.completed = True

    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass


# ════════════════════════════════════════
# Cleanup stale traces periodically
# ════════════════════════════════════════

@app.on_event("startup")
async def startup_cleanup():
    async def cleanup_loop():
        while True:
            await asyncio.sleep(300)
            cutoff = time.time() - 3600  # 1 hour
            stale = [
                tid for tid, t in _traces.items()
                if t.completed and t.started_at.timestamp() < cutoff
            ]
            for tid in stale:
                del _traces[tid]
    asyncio.create_task(cleanup_loop())


# ════════════════════════════════════════
# Health check
# ════════════════════════════════════════

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "active_traces": active_trace_count(),
        "total_traces": len(_traces),
    }