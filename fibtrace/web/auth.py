"""Authentication for the fibtrace web UI.

Providers (ported from netlapse's auth layer, minus its user database and roles):

  local       FIBTRACE_USERS JSON, {"user": "<scrypt hash>"}. Plaintext values
              are still accepted for compatibility and logged as a warning.
              Generate a hash with:  fibtrace web --hash-password
              Unset, it falls back to admin/fibtrace, which the launcher only
              allows on a loopback bind.
  ldap        Directory bind (Active Directory or any RFC 4511 server):
              service bind -> locate user -> bind as the user -> group gate.
  ldap+local  Directory first, local accounts as break-glass when the
              directory is unreachable or the user is not in it.

The provider and LDAP settings come from a YAML (or JSON) file named by
--auth-config or FIBTRACE_AUTH_CONFIG, same shape as netlapse's auth block:

    auth:
      provider: ldap+local
      ldap:
        servers: [ldaps://dc1.corp.example.com, ldaps://dc2.corp.example.com]
        use_ssl: true
        ca_certs_file: /etc/ssl/certs/corp-ca.pem
        bind_dn: "CN=svc-fibtrace,OU=Service,DC=corp,DC=example,DC=com"
        bind_password_env: FIBTRACE_LDAP_BIND_PASSWORD
        user_search_base: "OU=Users,DC=corp,DC=example,DC=com"
        allowed_groups: [neteng]

No config file means provider 'local'.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Callable, List, Optional

from .hashing import hash_password, verify_password

logger = logging.getLogger("fibtrace-web.auth")

ENV_USERS = "FIBTRACE_USERS"
ENV_AUTH_CONFIG = "FIBTRACE_AUTH_CONFIG"
# Set only by `fibtrace web` after it has confirmed a loopback bind. Without it
# the built-in admin/fibtrace login and LDAP mock mode refuse every login, so
# starting the app another way (uvicorn directly, behind a proxy) cannot expose them.
ENV_LOOPBACK_OK = "FIBTRACE_LOOPBACK_CONFIRMED"
DEFAULT_USERS = {"admin": "fibtrace"}
VALID_PROVIDERS = ("local", "ldap", "ldap+local")


class AuthResult:
    """Outcome of an authentication attempt."""

    __slots__ = ("ok", "user", "reason")

    def __init__(self, ok: bool, user: Optional[dict] = None, reason: str = ""):
        self.ok = ok
        self.user = user
        self.reason = reason

    @classmethod
    def success(cls, user: dict) -> "AuthResult":
        return cls(True, user=user)

    @classmethod
    def failure(cls, reason: str) -> "AuthResult":
        return cls(False, reason=reason)


# ─────────────────────────────────────────────────────────────────────────────
# Local
# ─────────────────────────────────────────────────────────────────────────────

# Spent on unknown usernames so a miss costs the same as a wrong password.
_DUMMY_HASH = hash_password("fibtrace-timing-equalizer")


class LocalAuthProvider:
    """Users from FIBTRACE_USERS: scrypt hashes, or plaintext (legacy)."""

    name = "local"

    def __init__(self, users: Optional[dict] = None):
        self.from_env = users is None and bool(os.environ.get(ENV_USERS))
        if users is None:
            raw = os.environ.get(ENV_USERS)
            users = json.loads(raw) if raw else dict(DEFAULT_USERS)
        if not isinstance(users, dict):
            raise ValueError(f"{ENV_USERS} must be a JSON object of username -> password hash")
        self.users = {str(k): str(v) for k, v in users.items()}
        self.using_defaults = not self.from_env and users == DEFAULT_USERS
        plain = sorted(u for u, v in self.users.items() if not v.startswith("scrypt$"))
        if plain and not self.using_defaults:
            logger.warning(
                "%s holds plaintext passwords for: %s - replace them with hashes "
                "from `fibtrace web --hash-password`", ENV_USERS, ", ".join(plain))

    def authenticate(self, username: str, password: str) -> AuthResult:
        import hmac

        if not username or not password:
            return AuthResult.failure("invalid credentials")
        stored = self.users.get(username)
        if stored is None:
            verify_password(password, _DUMMY_HASH)
            return AuthResult.failure("invalid credentials")
        if stored.startswith("scrypt$"):
            ok = verify_password(password, stored)
        else:
            ok = hmac.compare_digest(stored.encode(), password.encode())
        if not ok:
            return AuthResult.failure("invalid credentials")
        return AuthResult.success({"username": username, "display": username, "source": "local"})


# ─────────────────────────────────────────────────────────────────────────────
# LDAP / Active Directory
# ─────────────────────────────────────────────────────────────────────────────

try:
    from ldap3 import ALL, NONE, SUBTREE, Connection, Server, ServerPool, Tls
    from ldap3.utils.conv import escape_filter_chars
    _HAVE_LDAP3 = True
except Exception:  # pragma: no cover - only without the [ldap] extra
    _HAVE_LDAP3 = False


def _norm_group(g: str) -> str:
    """Full DNs compare whole and case-insensitively; a bare token is a CN."""
    return (g or "").strip().lower()


def _cn_of(dn: str) -> str:
    """First RDN value of a DN (the CN of a typical group DN)."""
    first = (dn or "").split(",", 1)[0]
    return first.split("=", 1)[1].strip().lower() if "=" in first else first.lower()


def _dc_suffix(dn: str) -> str:
    parts = [p.strip() for p in (dn or "").split(",")]
    dcs = [p for p in parts if p.lower().startswith("dc=")]
    return ",".join(dcs) if dcs else (dn or "")


def _swap_first_ou(dn: str, new_ou: str) -> Optional[str]:
    parts = [p.strip() for p in (dn or "").split(",")]
    if parts and parts[0].lower().startswith("ou="):
        parts[0] = f"ou={new_ou}"
        return ",".join(parts)
    return None


# Mock-mode seed: admin/admin and user/user are in the allowed group,
# denied/denied authenticates but is in no allowed group.
_DEMO_USERS = [
    {"username": "admin", "password": "admin", "display": "Mock Admin",
     "groups": ["fibtrace-users"]},
    {"username": "user", "password": "user", "display": "Mock User",
     "groups": ["fibtrace-users"]},
    {"username": "denied", "password": "denied", "display": "Mock Outsider",
     "groups": ["some-other-team"]},
]


class LdapAuthProvider:
    """Service bind -> locate -> proxy bind -> any-of allowed_groups gate.

    Never raises: bad credentials and directory failures both come back as
    AuthResult.failure, so an ldap+local chain falls through instead of
    500-ing the login route. connection_factory(user_dn, password) is the
    test seam; mock.enabled swaps in an in-memory directory for demos.
    """

    name = "ldap"

    def __init__(self, config: dict,
                 connection_factory: Optional[Callable[[str, str], "Connection"]] = None):
        c = self.config = config or {}
        self._explicit_factory = connection_factory

        self.servers: List[str] = c.get("servers") or ([c["server"]] if c.get("server") else [])
        self.use_ssl = bool(c.get("use_ssl", True))
        self.start_tls = bool(c.get("start_tls", False))
        self.ca_certs_file = c.get("ca_certs_file")
        self.validate_cert = bool(c.get("validate", True))
        self.port = c.get("port")
        self.timeout = int(c.get("timeout", 8))

        self.bind_dn = c.get("bind_dn", "")
        self.bind_password = self._resolve_bind_password(c)

        self.user_search_base = c.get("user_search_base", "")
        self.user_filter = c.get("user_filter", "(&(objectClass=user)(sAMAccountName={username}))")
        self.group_attr = c.get("group_attr", "memberOf")
        self.username_attr = c.get("username_attr", "sAMAccountName")
        self.display_name_attr = c.get("display_name_attr", "displayName")
        self.allowed_groups = [_norm_group(g) for g in (c.get("allowed_groups") or [])]

        self.mock_cfg = c.get("mock") or {}
        self.mock_enabled = bool(self.mock_cfg.get("enabled"))

        self._validate_transport()

        if self._explicit_factory is not None:
            self._factory = self._explicit_factory
        elif self.mock_enabled:
            self._factory = self._build_mock_factory()
        else:
            self._factory = self._default_factory

        if not _HAVE_LDAP3 and self._explicit_factory is None:
            logger.warning("auth provider includes 'ldap' but ldap3 is not installed - "
                           "LDAP logins will fail. pip install 'fibtrace2[ldap]'")
        if not self.allowed_groups and not self.mock_enabled:
            logger.warning("auth.ldap.allowed_groups is empty - ANY account that can bind "
                           "to the directory can log in to fibtrace")

    # -- config helpers ---------------------------------------------------
    @staticmethod
    def _resolve_bind_password(c: dict) -> str:
        env_key = c.get("bind_password_env")
        if env_key:
            val = os.environ.get(env_key)
            if val:
                return val
            logger.warning("bind_password_env %s is unset/empty", env_key)
        if c.get("bind_password"):
            logger.warning("auth.ldap.bind_password is inline in the config file - "
                           "prefer bind_password_env")
            return c["bind_password"]
        return ""

    def _validate_transport(self) -> None:
        if self.mock_enabled or self._explicit_factory is not None:
            return
        if self.use_ssl and self.start_tls:
            raise ValueError("auth.ldap: use_ssl (ldaps, 636) and start_tls (389 upgraded "
                             "in-band) are mutually exclusive - set exactly one")
        if not self.use_ssl and not self.start_tls:
            logger.warning("auth.ldap: neither use_ssl nor start_tls is set - the service "
                           "bind password and every user password cross the network in "
                           "CLEARTEXT")

    def _build_tls(self):
        if not self.use_ssl and not self.start_tls:
            return None
        import ssl
        validate = ssl.CERT_REQUIRED if self.validate_cert else ssl.CERT_NONE
        return Tls(ca_certs_file=self.ca_certs_file, validate=validate)

    def _build_server_pool(self):
        tls = self._build_tls()
        # get_info=NONE: ALL would pull the root DSE and full schema from the
        # DC on every login, and nothing here needs it.
        servers = [Server(host, port=self.port, use_ssl=self.use_ssl, tls=tls,
                          get_info=NONE, connect_timeout=self.timeout)
                   for host in self.servers]
        if not servers:
            raise RuntimeError("no LDAP servers configured")
        # active=1: one pass over the DCs, then LDAPServerPoolExhaustedError (after
        # ldap3's POOLING_LOOP_TIMEOUT pause, 10s). active=True retries forever when
        # every DC is down, which hangs the login and starves the ldap+local fallback.
        return ServerPool(servers, pool_strategy="FIRST", active=1, exhaust=True)

    def _default_factory(self, user: str, password: str) -> "Connection":
        conn = Connection(self._build_server_pool(), user=user or None,
                          password=password or None, auto_bind=False,
                          receive_timeout=self.timeout, raise_exceptions=False)
        # StartTLS before the bind, or the credentials go out in cleartext.
        # A directory that refuses the upgrade is an error, never a fallback.
        if self.start_tls and not conn.start_tls():
            raise RuntimeError(f"StartTLS negotiation failed, refusing to bind in cleartext: {conn.result}")
        return conn

    def _build_mock_factory(self):
        from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2
        from ldap3 import Connection as _C
        from ldap3 import Server as _S

        person_oc = ["top", "person", "organizationalPerson", "user"]
        base = self.user_search_base or "ou=users,dc=fibtrace,dc=local"
        self.user_search_base = base
        dc = _dc_suffix(base)
        groups_base = (self.mock_cfg.get("groups_base")
                       or _swap_first_ou(base, "groups") or f"ou=groups,{dc}")
        svc_dn = self.bind_dn or f"cn=svc-fibtrace,{dc}"
        svc_pw = self.bind_password or "mock-service"
        self.bind_dn, self.bind_password = svc_dn, svc_pw
        if not self.allowed_groups and not self.mock_cfg.get("users"):
            self.allowed_groups = ["fibtrace-users"]

        users = self.mock_cfg.get("users") or _DEMO_USERS
        entries = [(svc_dn, {"objectClass": person_oc, "sAMAccountName": _cn_of(svc_dn),
                             "userPassword": svc_pw})]
        group_dns = {}
        for u in users:
            gdns = []
            for g in (u.get("groups") or []):
                gdn = g if "=" in g else f"cn={g},{groups_base}"
                gdns.append(gdn)
                group_dns[gdn] = _cn_of(gdn)
            entries.append((f"cn={u['username']},{base}", {
                "objectClass": person_oc, "sAMAccountName": u["username"],
                "displayName": u.get("display", u["username"]),
                "userPassword": u.get("password", ""), "memberOf": gdns}))
        for gdn, gcn in group_dns.items():
            entries.append((gdn, {"objectClass": ["top", "group"], "cn": gcn}))

        logger.warning("fibtrace LDAP is in MOCK MODE - the directory is simulated in memory. "
                       "Not for production. Seeded users: %s",
                       ", ".join(f"{u['username']}/{u.get('password', '')}" for u in users))
        server = _S("fibtrace-mock", get_info=OFFLINE_AD_2012_R2)

        def factory(user, password):
            conn = _C(server, user=user or None, password=password or None,
                      client_strategy=MOCK_SYNC, raise_exceptions=False)
            for dn, attrs in entries:
                try:
                    conn.strategy.add_entry(dn, attrs)
                except Exception:
                    pass
            return conn

        return factory

    # -- the contract -----------------------------------------------------
    def authenticate(self, username: str, password: str) -> AuthResult:
        # A DN with an empty password is an anonymous bind on many servers,
        # and anonymous binds succeed.
        if not username or not password:
            return AuthResult.failure("invalid credentials")
        try:
            return self._authenticate(username, password)
        except Exception as e:
            logger.warning("LDAP auth error for %r: %s", username, e)
            return AuthResult.failure("directory unavailable")

    def _authenticate(self, username: str, password: str) -> AuthResult:
        svc = self._factory(self.bind_dn, self.bind_password)
        if not svc.bind():
            logger.error("LDAP service-account bind failed: %s", svc.result)
            return AuthResult.failure("directory unavailable")

        flt = self.user_filter.format(username=escape_filter_chars(username))
        svc.search(search_base=self.user_search_base, search_filter=flt, search_scope=SUBTREE,
                   attributes=[self.group_attr, self.display_name_attr, self.username_attr])
        entries = list(svc.entries)
        svc.unbind()
        if not entries:
            return AuthResult.failure("invalid credentials")
        if len(entries) > 1:
            logger.error("LDAP filter matched %d entries for %r - refusing an ambiguous login",
                         len(entries), username)
            return AuthResult.failure("invalid credentials")
        entry = entries[0]
        user_dn = entry.entry_dn
        groups = self._read_groups(entry)
        display = self._attr(entry, self.display_name_attr) or username
        account = self._attr(entry, self.username_attr) or username

        user_conn = self._factory(user_dn, password)
        if not user_conn.bind():
            return AuthResult.failure("invalid credentials")
        user_conn.unbind()

        if self.allowed_groups and not self._in_any(groups, self.allowed_groups):
            logger.info("LDAP user %r authenticated but is in no allowed group", account)
            return AuthResult.failure("not authorized (group membership)")
        return AuthResult.success({"username": str(account), "display": str(display),
                                   "source": "ldap"})

    def _read_groups(self, entry) -> List[str]:
        raw = getattr(entry, self.group_attr, None)
        if raw is None:
            return []
        try:
            vals = list(raw.values)
        except AttributeError:
            vals = raw if isinstance(raw, (list, tuple)) else [raw]
        return [str(v) for v in vals]

    @staticmethod
    def _in_any(user_groups: List[str], wanted: List[str]) -> bool:
        if not wanted:
            return False
        dns = {(g or "").strip().lower() for g in user_groups}
        cns = {_cn_of(g) for g in user_groups}
        return any((w in dns) if "=" in w else (w in cns) for w in wanted)

    @staticmethod
    def _attr(entry, name: str):
        a = getattr(entry, name, None)
        if a is None:
            return None
        try:
            return a.value
        except AttributeError:
            return a


# ─────────────────────────────────────────────────────────────────────────────
# Chain + config
# ─────────────────────────────────────────────────────────────────────────────

def load_auth_config(path: Optional[str] = None) -> dict:
    """Read the auth block from YAML/JSON; {} when no file is configured."""
    path = path or os.environ.get(ENV_AUTH_CONFIG)
    if not path:
        return {}
    text = Path(path).expanduser().read_text()
    if path.endswith(".json"):
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError("YAML auth config needs PyYAML (pip install 'fibtrace2[ldap]') "
                               "or use a .json file") from e
        data = yaml.safe_load(text) or {}
    return data.get("auth", data)


class AuthManager:
    """Runs the configured provider chain; first success wins."""

    def __init__(self, config: Optional[dict] = None, users: Optional[dict] = None,
                 connection_factory=None, loopback_confirmed: Optional[bool] = None):
        self.config = config or {}
        self.loopback_confirmed = (os.environ.get(ENV_LOOPBACK_OK) == "1"
                                   if loopback_confirmed is None else loopback_confirmed)
        self.provider_name = (self.config.get("provider") or "local").lower()
        if self.provider_name not in VALID_PROVIDERS:
            raise ValueError(f"auth.provider must be one of {', '.join(VALID_PROVIDERS)}, "
                             f"not {self.provider_name!r}")
        self.local = None
        self.ldap = None
        self.providers: list = []
        if "ldap" in self.provider_name:
            self.ldap = LdapAuthProvider(self.config.get("ldap") or {}, connection_factory)
            self.providers.append(self.ldap)
        if "local" in self.provider_name:
            self.local = LocalAuthProvider(users)
            self.providers.append(self.local)

    def authenticate(self, username: str, password: str) -> AuthResult:
        problem = self.exposure_problem()
        if problem and not self.loopback_confirmed:
            logger.warning("login refused: %s and the app was not started by `fibtrace web` "
                           "on a loopback address", problem)
            return AuthResult.failure("login disabled: configure FIBTRACE_USERS or LDAP")
        result = AuthResult.failure("no provider")
        for provider in self.providers:
            result = provider.authenticate(username or "", password or "")
            if result.ok:
                logger.info("login ok: %s (%s)", result.user["username"], provider.name)
                return result
        logger.info("login failed for %r: %s", username, result.reason)
        return result

    def exposure_problem(self) -> Optional[str]:
        """Why this config must not listen beyond loopback, or None if it may."""
        if self.ldap is not None and self.ldap.mock_enabled:
            return "LDAP mock mode seeds well-known demo passwords"
        if self.local is not None and self.local.using_defaults:
            return f"the built-in admin/fibtrace login is active ({ENV_USERS} is unset)"
        return None

    def describe(self) -> str:
        if self.ldap is not None and self.ldap.mock_enabled:
            return f"{self.provider_name} (LDAP mock)"
        if self.ldap is not None:
            return f"{self.provider_name} ({', '.join(self.ldap.servers) or 'no servers'})"
        return self.provider_name
