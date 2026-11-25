import time
from types import SimpleNamespace

from fibtrace.client import SSHClient, SSHClientConfig
from fibtrace.parsers import JunosParser


class FakeShell:
    """Answers a newline with a prompt after a short delay."""

    def __init__(self, prompt="admin@tor411.lab> "):
        self.prompt = prompt
        self.pending = b""
        self.ready_at = 0.0

    def send(self, data):
        self.pending += ("\r\n" + self.prompt).encode()
        self.ready_at = time.time() + 0.05

    def recv_ready(self):
        return bool(self.pending) and time.time() >= self.ready_at

    def recv(self, n):
        out, self.pending = self.pending[:n], self.pending[n:]
        return out


def test_find_prompt_returns_quickly():
    c = SSHClient(SSHClientConfig(host="192.0.2.1", username="u", password="p"))
    c._shell = FakeShell()
    t0 = time.time()
    prompt = c.find_prompt()
    assert "tor411.lab" in prompt
    assert time.time() - t0 < 1.5


def test_junos_local_route_interface():
    xml = """<rpc-reply><route-information><route-table><table-name>inet.0</table-name>
    <rt><rt-destination>192.0.2.24/32</rt-destination><rt-entry><protocol-name>Local</protocol-name>
    <nh><nh-local-interface>irb.127</nh-local-interface></nh></rt-entry></rt></route-table>
    </route-information></rpc-reply>"""
    route = JunosParser.parse_route(xml, "192.0.2.24/32")
    assert route is not None and route.is_connected
    assert route.next_hops[0].interface == "irb.127"
