"""Legacy SSH algorithms apply per connection, never to paramiko.Transport globally."""

import paramiko

from fibtrace.client import LegacyTransport, SSHClient, SSHClientConfig


def test_legacy_does_not_touch_global_transport():
    before = (paramiko.Transport._preferred_kex, paramiko.Transport._preferred_ciphers,
              paramiko.Transport._preferred_keys)
    assert issubclass(LegacyTransport, paramiko.Transport)
    assert LegacyTransport._preferred_kex[0] == "diffie-hellman-group1-sha1"
    assert (paramiko.Transport._preferred_kex, paramiko.Transport._preferred_ciphers,
            paramiko.Transport._preferred_keys) == before


def test_legacy_lists_only_implemented_algorithms():
    assert all(k in paramiko.Transport._kex_info for k in LegacyTransport._preferred_kex)
    assert all(c in paramiko.Transport._cipher_info for c in LegacyTransport._preferred_ciphers)
    assert "ssh-dss" not in LegacyTransport._preferred_keys


def test_legacy_mode_passes_transport_factory(monkeypatch):
    seen = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda self, **kw: seen.append(kw))
    monkeypatch.setattr(SSHClient, "_create_shell", lambda self: None)
    SSHClient(SSHClientConfig(host="192.0.2.1", username="u", password="p", legacy_mode=True)).connect()
    SSHClient(SSHClientConfig(host="192.0.2.1", username="u", password="p")).connect()
    assert seen[0]["transport_factory"] is LegacyTransport
    assert "transport_factory" not in seen[1]


def test_unreachable_host_is_not_retried(monkeypatch):
    import socket
    calls = []

    def connect(self, **kw):
        calls.append(kw)
        raise socket.timeout("timed out")

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    client = SSHClient(SSHClientConfig(host="192.0.2.1", username="u", password="p"))
    try:
        client.connect()
    except Exception:
        pass
    assert len(calls) == 1


def test_negotiation_failure_is_retried(monkeypatch):
    calls = []

    def connect(self, **kw):
        calls.append(kw)
        if len(calls) == 1:
            raise paramiko.SSHException("no matching host key type")

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    monkeypatch.setattr(SSHClient, "_create_shell", lambda self: None)
    SSHClient(SSHClientConfig(host="192.0.2.1", username="u", password="p")).connect()
    assert len(calls) == 2
