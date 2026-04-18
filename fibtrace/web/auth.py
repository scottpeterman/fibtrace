"""Pluggable auth backend for the fibtrace web UI.

Selected via the FIBTRACE_AUTH_BACKEND env var. Default: 'env'.

Backends:
  env       — dict from FIBTRACE_USERS JSON env var (current behavior)
  ldap3     — LDAP bind (requires `pip install fibtrace[ldap]`)
  ssh       — attempt SSH against a network device as the credential check

TODO(content-phase):
  - Move current USERS/FIBTRACE_USERS logic from app.py into EnvUsersBackend
  - Wire get_backend() factory to read FIBTRACE_AUTH_BACKEND
  - Replace the login route's direct dict lookup with backend.authenticate()
  - Implement Ldap3Backend (deferred — behind [ldap] extra)
  - Implement SshProxyBackend using paramiko (already a base dep)
"""
from __future__ import annotations
from typing import Protocol


class AuthBackend(Protocol):
    def authenticate(self, username: str, password: str) -> bool: ...


class EnvUsersBackend:
    """JSON dict of username→password from FIBTRACE_USERS env var."""

    def __init__(self, users: dict[str, str]):
        self._users = users

    def authenticate(self, username: str, password: str) -> bool:
        return self._users.get(username) == password


class Ldap3Backend:
    """LDAP bind auth. Requires `pip install fibtrace[ldap]`."""

    def __init__(self, server_url: str, base_dn: str, **kwargs):
        raise NotImplementedError

    def authenticate(self, username: str, password: str) -> bool:
        raise NotImplementedError


class SshProxyBackend:
    """Authenticate by attempting SSH against a network device.

    Useful where the network itself is the source of truth for who should
    have operator access. Accepts password and key auth.
    """

    def __init__(self, target_host: str, port: int = 22, key_file: str | None = None):
        raise NotImplementedError

    def authenticate(self, username: str, password: str) -> bool:
        raise NotImplementedError


def get_backend() -> AuthBackend:
    """Factory reading FIBTRACE_AUTH_BACKEND env var. Default: 'env'."""
    raise NotImplementedError
