"""fibtrace final-host probe: the real walk() loop over a simulated lab topology.

The device-facing steps (connect, identify, fingerprint, gather) are replaced with a table, so the BFS,
convergence, endpoint and loop logic run unchanged. Topology (the GNS3 lab):

    wan-core-1 172.16.1.2 -> eng-rtr-1 172.16.128.2 -> eng-spine-1 172.16.2.2 \\
                                                    -> eng-spine-2 172.16.2.6  -> Vlan50 (connected) -> 172.16.50.5
"""

from ipaddress import ip_address, ip_network

import pytest

from fibtrace import walker as W
from fibtrace.commands_and_parsers import Platform
from fibtrace.diagnostics import HopDiagnostic
from fibtrace.models import DeviceInfo, Hop, HopVerdict, Prefix, RouteEntry, RouteNextHop, RouteProtocol

HOSTS = {"172.16.1.2": "wan-core-1", "172.16.128.2": "eng-rtr-1", "172.16.2.2": "eng-spine-1",
         "172.16.2.6": "eng-spine-2", "172.16.50.5": "eng-leaf-2"}


def lab(target):
    """hostname -> (protocol, next-hop IPs) for a route to target."""
    t = ip_address(target.split("/")[0])
    local = {"eng-leaf-2": "172.16.50.5", "eng-spine-1": "172.16.2.2", "wan-core-1": "172.16.1.2"}
    def route(host):
        if local.get(host) == str(t):
            return RouteProtocol.CONNECTED, []
        if t in ip_network("172.16.50.0/24"):
            return {"wan-core-1": (RouteProtocol.DYNAMIC, ["172.16.128.2"]),
                    "eng-rtr-1": (RouteProtocol.DYNAMIC, ["172.16.2.2", "172.16.2.6"]),
                    "eng-spine-1": (RouteProtocol.CONNECTED, []),
                    "eng-spine-2": (RouteProtocol.CONNECTED, [])}[host]
        if t in ip_network("172.16.2.0/30"):
            return {"wan-core-1": (RouteProtocol.DYNAMIC, ["172.16.128.2"]),
                    "eng-rtr-1": (RouteProtocol.CONNECTED, [])}[host]
        raise KeyError(host)
    return route


class FakeClient:
    def __init__(self, ip): self.ip = ip
    def disconnect(self): pass


def run(target, ssh_ok=frozenset(HOSTS), probe=True):
    route = lab(target)
    cfg = W.WalkerConfig(target_prefix=target, source_host="172.16.1.2", username="u", password="p",
                         probe_target_host=probe, event_callback=None)
    events = []
    cfg.event_callback = events.append
    w = W.ChainWalker(cfg)
    w._progress = staticmethod(lambda *a, **k: None)
    w._connect = lambda ip: FakeClient(ip) if ip in ssh_ok and ip in HOSTS else None
    w._resolve_via_neighbors = lambda item: []

    def identify(client, ip):
        host = HOSTS[ip]
        ident = w._identity_cache.get(host) or W.DeviceIdentity(ssh_target=ip, prompt_raw=host + "#", hostname=host)
        w._identity_cache[host] = ident
        w._ip_to_hostname[ip] = host
        return ident
    w._identify_device = identify
    w._fingerprint_device = lambda client, ident: (Platform.ARISTA_EOS, None)

    def gather(client, ident, idx):
        proto, nhs = route(ident.hostname)
        r = RouteEntry(prefix=Prefix(network=ip_network(target, strict=False)), protocol=proto,
                       next_hops=[RouteNextHop(address=ip_address(n)) for n in nhs])
        hop = Hop(device=DeviceInfo(hostname=ident.hostname, ip_address=ip_address(client.ip)),
                  target_prefix=r.prefix, route=r, verdict=HopVerdict.HEALTHY,
                  next_device_ips=[ip_address(n) for n in nhs])
        return hop, HopDiagnostic(device=ident.hostname, hop_index=idx)
    w._gather_forwarding_state = gather
    chain = w.walk()
    return chain, w.graph.to_dict(), events


def test_target_host_answers_ssh():
    chain, g, ev = run("172.16.50.5/32")
    assert chain.status.value == "complete"
    assert set(g["nodes"]) == {"wan-core-1", "eng-rtr-1", "eng-spine-1", "eng-spine-2", "eng-leaf-2"}
    into_leaf = sorted(e["from"] for e in g["edges"] if e["to"] == "eng-leaf-2")
    assert into_leaf == ["eng-spine-1", "eng-spine-2"]          # both ECMP paths deliver to the leaf
    assert sorted(map(tuple, g["meta"]["paths"])) == [
        ("wan-core-1", "eng-rtr-1", "eng-spine-1", "eng-leaf-2"),
        ("wan-core-1", "eng-rtr-1", "eng-spine-2", "eng-leaf-2")]


def test_target_host_without_ssh_is_an_endpoint_not_a_break():
    chain, g, ev = run("172.16.50.5/32", ssh_ok=frozenset(HOSTS) - {"172.16.50.5"})
    assert chain.status.value == "complete" and chain.is_healthy
    assert g["nodes"]["172.16.50.5"]["verdict"] == "endpoint"
    assert sorted(e["from"] for e in g["edges"] if e["to"] == "172.16.50.5") == ["eng-spine-1", "eng-spine-2"]
    done = [e for e in ev if e.event == "hop_done" and e.device == "172.16.50.5"]
    assert done[0].verdict.value == "endpoint" and done[1].verdict.value == "convergence"


def test_target_owned_by_a_delivering_device_is_not_a_loop():
    # eng-rtr-1 delivers 172.16.2.2 connected; the probe lands on eng-spine-1, walked as the final hop
    chain, g, ev = run("172.16.2.2/32")
    assert chain.status.value == "complete"
    assert "eng-spine-1" in g["nodes"] and not any(e["is_loop"] for e in g["edges"])


def test_target_on_the_source_itself():
    chain, g, ev = run("172.16.1.2/32")
    assert chain.status.value == "complete" and set(g["nodes"]) == {"wan-core-1"}


def test_prefix_targets_and_opt_out_do_not_probe():
    chain, g, ev = run("172.16.50.0/24")
    assert "eng-leaf-2" not in g["nodes"]
    chain, g, ev = run("172.16.50.5/32", probe=False)
    assert "eng-leaf-2" not in g["nodes"]
