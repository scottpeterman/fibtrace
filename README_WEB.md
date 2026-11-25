# fibtrace web dashboard

FastAPI front-end for fibtrace — forwarding chain validation with live terminal streaming and interactive graph visualization.

This is the deep-dive reference for the web dashboard. See the main [README.md](README.md) for the overall fibtrace project.

## Quick Start

```bash
# Install with the [web] extra
pip install 'fibtrace[web]'

# Run with default settings (admin/fibtrace)
fibtrace web --host 0.0.0.0 --port 8100

# Open http://localhost:8100
```

Equivalent invocations:

```bash
fibtrace web --port 8100              # preferred
python -m fibtrace.web --port 8100    # direct module entry
uvicorn fibtrace.web.app:app --port 8100  # if you need uvicorn's own flags
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `FIBTRACE_SECRET_KEY` | (random) | Session signing key. Set explicitly for persistence across restarts. |
| `FIBTRACE_USERS` | `{"admin":"fibtrace"}` | JSON dict of username→password pairs. |
| `FIBTRACE_MODULE` | `fibtrace.walker` | Python module path for the walker CLI (used for subprocess invocation). |
| `FIBTRACE_PYTHON` | `python` | Python interpreter path (use venv python if needed). |
| `FIBTRACE_MAX_TRACES` | `5` | Max concurrent traces across all users. |

### Example: Custom Users

```bash
export FIBTRACE_USERS='{"scott":"hunter2","ops":"readonly"}'
export FIBTRACE_SECRET_KEY='my-persistent-secret-key'
export FIBTRACE_PYTHON='/home/scott/fibtrace/.venv/bin/python'
fibtrace web --host 0.0.0.0 --port 8100
```

## Architecture

```
Browser                    FastAPI (fibtrace.web.app)   fibtrace.walker
  │                           │                              │
  ├── GET /login ────────────►│                              │
  ├── POST /login ───────────►│ (session cookie)             │
  ├── GET / ─────────────────►│ (dashboard.html)             │
  │                           │                              │
  ├── WS /ws/trace ──────────►│                              │
  │   ├── {start_trace} ─────►│── subprocess.exec ──────────►│
  │   │◄── {output,stderr} ──│◄── stderr (progress) ───────│
  │   │◄── {output,stdout} ──│◄── stdout (JSON) ───────────│
  │   │◄── {trace_done} ─────│◄── exit ────────────────────│
  │                           │                              │
  ├── GET /graph/{id} ───────►│ (graph.html + JSON)          │
  ├── GET /viewer ───────────►│ (standalone graph viewer)    │
  ├── GET /diff ─────────────►│ (diff_viewer.html, client-   │
  │                           │  side only — no backend)     │
```

### Key Design Decisions

- **Subprocess isolation**: Each trace runs as a child process via `python -m fibtrace.walker`. No import-time coupling — the web app doesn't import fibtrace internals. This means the web app works with any fibtrace version that speaks the same CLI interface.

- **WebSocket streaming**: stderr (progress output) streams live to xterm.js. stdout (JSON result) is buffered for graph extraction. Both streams are tagged so the frontend knows what to display.

- **Session auth**: Signed cookies via itsdangerous. No database, no JWT complexity. Session tokens expire after 24h. Users defined in an environment variable today; pluggable backends (LDAP3, SSH-proxy) stubbed in `fibtrace.web.auth` for future wiring.

- **Graph viewer**: After trace completes, the graph JSON is held in memory (keyed by trace_id). The viewer page loads it server-side via Jinja2 template injection — no extra API call needed for initial render. Stale traces are cleaned up after 1 hour.

- **Diff viewer (client-side only)**: The `/diff` route serves a self-contained HTML page that runs all diff computation in the browser. Users drag two graph JSONs (preflight/postflight, pre-MOP/post-MOP, etc.) onto the page and see the delta rendered as side-by-side graphs with hover-synchronized node highlighting and click-to-trace path overlays. No backend state, no trace IDs, no session coupling beyond the login gate — the page is just a viewer, and the two JSON files never leave the browser. This mirrors the `fibtrace diff` CLI exactly: same delta schema, same impairment metrics, same verdict rules. The CLI is the pipeline/MOP-doc path; the viewer is the change-window/review-meeting path.

## File Structure

Web-specific files live inside the `fibtrace` package so they ship in the wheel:

```
fibtrace/
└── web/
    ├── __init__.py
    ├── __main__.py            # `fibtrace web` / `python -m fibtrace.web` entry point
    ├── app.py                 # FastAPI application
    ├── auth.py                # Auth backend protocol + env/LDAP/SSH stubs
    ├── templates/
    │   ├── login.html         # Login page
    │   ├── dashboard.html     # Main UI: form + xterm.js terminal
    │   ├── graph.html         # Forwarding graph viewer
    │   ├── viewer.html        # Standalone graph viewer (load .graph.json)
    │   └── diff_viewer.html   # Side-by-side forwarding graph diff viewer
    └── static/                # (empty — CDN for xterm.js and fonts)
```

## Auth Backends

The login route delegates credential checks to a backend selected by `FIBTRACE_AUTH_BACKEND` (default `env`). Backends live in `fibtrace.web.auth`:

| Backend | Env value | Status | Notes |
|---|---|---|---|
| `EnvUsersBackend` | `env` (default) | Implemented | Reads `FIBTRACE_USERS` JSON dict |
| `Ldap3Backend` | `ldap3` | Stubbed | Needs `pip install 'fibtrace[ldap]'` |
| `SshProxyBackend` | `ssh` | Stubbed | Authenticates by attempting SSH against a network device — paramiko is already a base dep |

SSH-proxy auth is useful where the network itself is the source of truth for who should have operator access: if a user can SSH into a designated network device with their credentials, they can use the dashboard.

## Security Notes

- Credentials entered in the form are sent over WebSocket to the server, which passes them as CLI arguments to the subprocess. **Run behind HTTPS in production** (nginx/caddy reverse proxy).
- The `--password` argument will be visible in the process list (`ps aux`). For production use, consider extending fibtrace to read credentials from stdin or a file.
- Session cookies are httponly and signed, but not encrypted. HTTPS is required for real security.

## Development

```bash
# Auto-reload on code changes (dev only)
fibtrace web --reload --port 8100

# Or directly with uvicorn, for its full flag surface
uvicorn fibtrace.web.app:app --reload --host 0.0.0.0 --port 8100
```