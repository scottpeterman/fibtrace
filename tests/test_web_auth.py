"""fibtrace web auth: local accounts, the LDAP provider (mock directory and a real
LDAPv3 listener from tests/support/ldapd.py), the provider chain, and the login route."""
import importlib
import json
import sys

import pytest

from fibtrace.web.auth import AuthManager, LdapAuthProvider, LocalAuthProvider
from fibtrace.web.hashing import hash_password

ldap3 = pytest.importorskip("ldap3")

needs_310 = pytest.mark.skipif(sys.version_info < (3, 10), reason="ldapd fixture needs 3.10+")

BASE = "dc=netlab,dc=internal"
USERS = f"ou=users,{BASE}"
SERVICE_DN = f"cn=svc-directory,{BASE}"


# ── local ────────────────────────────────────────────────────────────────

def test_local_hashed_and_plaintext_users():
    p = LocalAuthProvider({"scott": hash_password("s3cret-pw"), "legacy": "plain-pw"})
    assert p.authenticate("scott", "s3cret-pw").ok
    assert not p.authenticate("scott", "wrong").ok
    assert p.authenticate("legacy", "plain-pw").ok
    assert not p.authenticate("nobody", "s3cret-pw").ok
    assert not p.authenticate("scott", "").ok


def test_default_login_only_allowed_on_loopback(monkeypatch):
    monkeypatch.delenv("FIBTRACE_USERS", raising=False)
    assert "admin/fibtrace" in AuthManager({}).exposure_problem()
    monkeypatch.setenv("FIBTRACE_USERS", json.dumps({"scott": hash_password("x" * 10)}))
    assert AuthManager({}).exposure_problem() is None


def test_mock_ldap_is_never_exposed():
    mgr = AuthManager({"provider": "ldap", "ldap": {"mock": {"enabled": True}}})
    assert "mock" in mgr.exposure_problem()


def test_bad_provider_name_fails_fast():
    with pytest.raises(ValueError):
        AuthManager({"provider": "kerberos"})


# ── LDAP, mock directory ─────────────────────────────────────────────────

def mock_mgr(provider="ldap"):
    return AuthManager({"provider": provider, "ldap": {"mock": {"enabled": True}}},
                       users={"breakglass": hash_password("glass-pw-1")})


def test_mock_directory_flow():
    mgr = mock_mgr()
    r = mgr.authenticate("admin", "admin")
    assert r.ok and r.user == {"username": "admin", "display": "Mock Admin", "source": "ldap"}
    assert mgr.authenticate("denied", "denied").reason == "not authorized (group membership)"
    assert not mgr.authenticate("admin", "wrong").ok
    assert not mgr.authenticate("admin", "").ok
    assert not mgr.authenticate("breakglass", "glass-pw-1").ok      # ldap only: no local


def test_ldap_plus_local_falls_through_to_local():
    mgr = mock_mgr("ldap+local")
    assert mgr.authenticate("admin", "admin").user["source"] == "ldap"
    assert mgr.authenticate("breakglass", "glass-pw-1").user["source"] == "local"


# ── LDAP, real wire (ldapd) ──────────────────────────────────────────────

def wire_cfg(*servers, **extra):
    cfg = {"servers": list(servers), "use_ssl": False, "timeout": 2,
           "bind_dn": SERVICE_DN, "bind_password": "svc-pw",
           "user_search_base": USERS, "allowed_groups": ["lab-users"]}
    cfg.update(extra)
    return cfg


@pytest.fixture
def ldapd():
    from support.ldapd import ThreadedLdapServer
    with ThreadedLdapServer() as srv:
        yield srv


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    pytest.importorskip("cryptography")
    from support.ldapd import make_certificate
    return make_certificate(str(tmp_path_factory.mktemp("ca")), common_name="127.0.0.1")


@needs_310
def test_wire_login_and_group_gate(ldapd):
    p = LdapAuthProvider(wire_cfg(ldapd.url))
    r = p.authenticate("plain-user", "user-pw")
    assert r.ok and r.user["display"] == "Lab Viewer"
    assert p.authenticate("outside-user", "out-pw").reason == "not authorized (group membership)"
    assert p.authenticate("plain-user", "nope").reason == "invalid credentials"
    assert p.authenticate("ghost", "user-pw").reason == "invalid credentials"


@needs_310
def test_wire_filter_injection_is_escaped(ldapd):
    p = LdapAuthProvider(wire_cfg(ldapd.url))
    assert not p.authenticate("*)(sAMAccountName=*", "user-pw").ok
    assert any("\\2a" in f for f in ldapd.received_filters)


@needs_310
def test_wire_ad_sub_code_is_a_plain_failure(ldapd):
    ldapd.faults.fail_user_bind("775")          # account locked
    assert LdapAuthProvider(wire_cfg(ldapd.url)).authenticate("plain-user", "user-pw").reason \
        == "invalid credentials"


@needs_310
def test_wire_ambiguous_match_is_refused(ldapd):
    ldapd.faults.duplicate_entries = 2
    assert not LdapAuthProvider(wire_cfg(ldapd.url)).authenticate("plain-user", "user-pw").ok


@needs_310
def test_wire_failover_to_second_dc(ldapd):
    from support.ldapd import ThreadedLdapServer
    dead = ThreadedLdapServer().start()
    dead_url = dead.url
    dead.stop()
    assert LdapAuthProvider(wire_cfg(dead_url, ldapd.url)).authenticate("plain-user", "user-pw").ok


@needs_310
def test_wire_directory_down_falls_through_to_break_glass():
    from support.ldapd import ThreadedLdapServer
    dead = ThreadedLdapServer().start()
    dead_url = dead.url
    dead.stop()
    mgr = AuthManager({"provider": "ldap+local", "ldap": wire_cfg(dead_url)},
                      users={"breakglass": hash_password("glass-pw-1")})
    assert mgr.ldap.authenticate("plain-user", "user-pw").reason == "directory unavailable"
    assert mgr.authenticate("breakglass", "glass-pw-1").ok


@needs_310
def test_wire_ldaps_with_ca(certs):
    from support.ldapd import ThreadedLdapServer, server_ssl_context
    ca, cert, key = certs
    with ThreadedLdapServer(ssl_context=server_ssl_context(cert, key)) as srv:
        cfg = wire_cfg(f"ldaps://127.0.0.1:{srv.port}", use_ssl=True, ca_certs_file=ca)
        assert LdapAuthProvider(cfg).authenticate("plain-user", "user-pw").ok


@needs_310
def test_wire_ldaps_untrusted_ca_is_refused(certs, tmp_path):
    from support.ldapd import ThreadedLdapServer, make_certificate, server_ssl_context
    ca, cert, key = certs
    other_ca, _, _ = make_certificate(str(tmp_path), common_name="127.0.0.1")
    with ThreadedLdapServer(ssl_context=server_ssl_context(cert, key)) as srv:
        cfg = wire_cfg(f"ldaps://127.0.0.1:{srv.port}", use_ssl=True, ca_certs_file=other_ca)
        r = LdapAuthProvider(cfg).authenticate("plain-user", "user-pw")
        assert not r.ok and srv.bind_log == []          # no credential reached the server


@needs_310
def test_wire_start_tls(certs):
    from support.ldapd import ThreadedLdapServer, server_ssl_context
    ca, cert, key = certs
    with ThreadedLdapServer(start_tls_context=server_ssl_context(cert, key)) as srv:
        cfg = wire_cfg(srv.url, start_tls=True, ca_certs_file=ca)
        assert LdapAuthProvider(cfg).authenticate("plain-user", "user-pw").ok
        srv.faults.reject_start_tls = True
        srv.bind_log.clear()
        r = LdapAuthProvider(cfg).authenticate("plain-user", "user-pw")
        assert r.reason == "directory unavailable" and srv.bind_log == []   # no cleartext bind


def test_ssl_and_start_tls_together_is_a_config_error():
    with pytest.raises(ValueError):
        LdapAuthProvider(wire_cfg("ldap://127.0.0.1:1", use_ssl=True, start_tls=True))


# ── login route ──────────────────────────────────────────────────────────

def test_login_route_uses_the_chain(monkeypatch, tmp_path):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    cfg = tmp_path / "auth.json"
    cfg.write_text(json.dumps({"auth": {"provider": "ldap", "ldap": {"mock": {"enabled": True}}}}))
    monkeypatch.setenv("FIBTRACE_AUTH_CONFIG", str(cfg))
    import fibtrace.web.app as webapp
    webapp = importlib.reload(webapp)
    client = TestClient(webapp.app)
    bad = client.post("/login", data={"username": "denied", "password": "denied"},
                      follow_redirects=False)
    assert bad.status_code == 401
    ok = client.post("/login", data={"username": "admin", "password": "admin"},
                     follow_redirects=False)
    assert ok.status_code == 302 and "fibtrace_session" in ok.cookies
    monkeypatch.delenv("FIBTRACE_AUTH_CONFIG")
    importlib.reload(webapp)


# ── web users bring their own device credentials ─────────────────────────

def _logged_in_client(monkeypatch):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    monkeypatch.delenv("FIBTRACE_AUTH_CONFIG", raising=False)
    monkeypatch.setenv("FIBTRACE_USERS", json.dumps({"scott": hash_password("dash-pw-1")}))
    import fibtrace.web.app as webapp
    webapp = importlib.reload(webapp)
    client = TestClient(webapp.app)
    assert client.post("/login", data={"username": "scott", "password": "dash-pw-1"},
                       follow_redirects=False).status_code == 302
    return webapp, client


TRACE = {"prefix": "192.0.2.24/32", "source": "192.0.2.1", "username": "neteng"}


@pytest.mark.parametrize("extra, why", [
    ({}, "password are required"),
    ({"password": "", "key_file": "/root/.ssh/id_ed25519"}, "password are required"),
    ({"password": "dev-pw", "key_file": "/root/.ssh/id_ed25519"}, "key_file is not accepted"),
])
def test_web_trace_rejects_server_side_credentials(monkeypatch, extra, why):
    webapp, client = _logged_in_client(monkeypatch)
    spawned = []
    monkeypatch.setattr(webapp.asyncio, "create_subprocess_exec",
                        lambda *a, **k: spawned.append(a))
    with client.websocket_connect("/ws/trace") as ws:
        ws.send_json({"type": "start_trace", "params": {**TRACE, **extra}})
        msg = ws.receive_json()
    assert msg["type"] == "error" and why in msg["data"]
    assert spawned == []


def test_web_trace_passes_password_by_env_and_never_server_keys(monkeypatch):
    webapp, client = _logged_in_client(monkeypatch)
    seen = {}

    async def fake_exec(*cmd, **kw):
        seen["cmd"], seen["env"] = list(cmd), kw.get("env") or {}
        raise RuntimeError("stop after spawn")

    monkeypatch.setattr(webapp.asyncio, "create_subprocess_exec", fake_exec)
    with client.websocket_connect("/ws/trace") as ws:
        ws.send_json({"type": "start_trace", "params": {**TRACE, "password": "dev-pw"}})
        try:
            while "cmd" not in seen:
                ws.receive_json()
        except Exception:
            pass
    assert "--no-default-key" in seen["cmd"]
    assert "--key-file" not in seen["cmd"] and "dev-pw" not in seen["cmd"]
    assert seen["env"]["FIBTRACE_PASSWORD"] == "dev-pw"


def test_walker_no_default_key_ignores_home_keys(tmp_path, monkeypatch, capsys):
    from fibtrace import walker
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("not a real key")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("FIBTRACE_PASSWORD", raising=False)
    with pytest.raises(SystemExit):
        walker.main(["-p", "192.0.2.24", "-s", "192.0.2.1", "-u", "u", "--no-default-key"])
    assert "no --password" in capsys.readouterr().err
