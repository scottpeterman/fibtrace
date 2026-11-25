# fibtrace web dashboard

FastAPI front-end for fibtrace — forwarding chain validation with live terminal streaming and interactive graph visualization.

This is the deep-dive reference for the web dashboard. See the main [README.md](README.md) for the overall fibtrace project.

## Quick Start

```bash
# Install with the [web] extra
pip install 'fibtrace[web]'

# Run locally with the built-in admin/fibtrace login (loopback only)
fibtrace web --port 8100

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
| `FIBTRACE_USERS` | `{"admin":"fibtrace"}` | JSON dict of username → scrypt hash (from `fibtrace web --hash-password`). Plaintext values still work but log a warning. |
| `FIBTRACE_AUTH_CONFIG` | (unset) | YAML/JSON auth config (provider, LDAP). Same as `--auth-config`. |
| `FIBTRACE_MODULE` | `fibtrace.walker` | Python module path for the walker CLI (used for subprocess invocation). |
| `FIBTRACE_PYTHON` | `python` | Python interpreter path (use venv python if needed). |
| `FIBTRACE_MAX_TRACES` | `5` | Max concurrent traces across all users. |

`fibtrace web` binds 127.0.0.1 by default. It refuses any other address while the built-in admin/fibtrace login or LDAP mock mode is active.

### Example: Custom Users

```bash
fibtrace web --hash-password
export FIBTRACE_USERS='{"scott":"scrypt$16384$8$1$...","ops":"scrypt$16384$8$1$..."}'
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

## Authentication

Ported from netlapse. `auth.provider` selects the chain:

| Provider | Behavior |
|---|---|
| `local` (default) | Accounts from `FIBTRACE_USERS`. |
| `ldap` | Directory only: service bind → locate user → bind as the user → `allowed_groups` gate. |
| `ldap+local` | Directory first; local accounts as break-glass when the directory is down or the user isn't in it. |

LDAP needs `pip install 'fibtrace[web,ldap]'`. Example `auth.yaml`:

```yaml
auth:
  provider: ldap+local
  ldap:
    servers:                        # tried in order, failover
      - ldaps://dc1.corp.example.com
      - ldaps://dc2.corp.example.com
    use_ssl: true                   # or start_tls: true on 389, never both
    validate: true
    ca_certs_file: /etc/ssl/certs/corp-ca.pem
    bind_dn: "CN=svc-fibtrace,OU=Service,DC=corp,DC=example,DC=com"
    bind_password_env: FIBTRACE_LDAP_BIND_PASSWORD
    user_search_base: "OU=Users,DC=corp,DC=example,DC=com"
    user_filter: "(&(objectClass=user)(sAMAccountName={username}))"
    allowed_groups: [neteng]        # CN or full DN; any-of; direct memberOf only
```

```bash
export FIBTRACE_LDAP_BIND_PASSWORD='...'
fibtrace web --host 0.0.0.0 --auth-config auth.yaml
```

For a demo with no directory, `mock: {enabled: true}` under `ldap` simulates one in memory (admin/admin, user/user, denied/denied). Mock mode is loopback-only.

When every DC is unreachable, an `ldap+local` login falls through to local accounts after about 10 seconds (one pass over the server list plus ldap3's pool retry pause).

## Security Notes

- Device credentials entered in the form are sent over WebSocket to the server, which hands the password to the walker subprocess in its environment (`FIBTRACE_PASSWORD`), not on the command line. **Run behind HTTPS in production** (nginx/caddy reverse proxy).
- Web users always supply their own SSH username and password. The server rejects a missing password or a `key_file`, and launches the walker with `--no-default-key`, so a dashboard login never reaches the server account's `~/.ssh` keys.
- Session cookies are httponly and signed, but not encrypted. HTTPS is required for real security.

## Development

```bash
# Auto-reload on code changes (dev only)
fibtrace web --reload --port 8100

# Or directly with uvicorn, for its full flag surface
uvicorn fibtrace.web.app:app --reload --host 0.0.0.0 --port 8100
```