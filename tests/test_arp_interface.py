"""ARP interface field → the interface fibtrace checks, on real EOS / Junos shapes."""

import pytest

from fibtrace.parsers import AristaEOSParser, JunosParser
from fibtrace.walker import arp_interface_port


@pytest.mark.parametrize("raw,port", [
    ("Vlan127, not learned", "Vlan127"),
    ("Vlan127, Ethernet10", "Ethernet10"),
    ("Vlan127, Port-Channel1", "Port-Channel1"),
    ("irb.127 [ge-0/0/47.0]", "ge-0/0/47.0"),
    ("irb.127 [ae6.0]", "ae6.0"),
    ("xe-14/0/35.0", "xe-14/0/35.0"),
    ("Ethernet10/1", "Ethernet10/1"),
    (None, None),
])
def test_arp_interface_port(raw, port):
    assert arp_interface_port(raw) == port


def test_eos_arp_not_learned():
    raw = """sh ip arp 10.0.5.101 | json
{
    "dynamicEntries": 1,
    "ipV4Neighbors": [
        {"hwAddress": "001c.7378.e851", "address": "10.0.5.101", "interface": "Vlan127, not learned", "age": 0}
    ],
    "notLearnedEntries": 1, "totalEntries": 1, "staticEntries": 0
}
sw#"""
    e = AristaEOSParser.parse_arp(raw, "10.0.5.101")
    assert e.mac.address == "00:1c:73:78:e8:51" and e.interface == "Vlan127, not learned"


def test_junos_qfx_arp_routed_port():
    raw = """<rpc-reply xmlns:junos="http://xml.juniper.net/junos/14.1X53/junos">
    <arp-table-information xmlns="http://xml.juniper.net/junos/14.1X53/junos-arp" junos:style="no-resolve">
        <arp-table-entry>
            <mac-address>00:24:38:17:5d:4e</mac-address>
            <ip-address>192.0.2.252</ip-address>
            <interface-name>xe-14/0/35.0</interface-name>
            <arp-table-entry-flags><none/></arp-table-entry-flags>
        </arp-table-entry>
    </arp-table-information>
    <cli><banner>{master:0}</banner></cli>
</rpc-reply>"""
    e = JunosParser.parse_arp(raw, "192.0.2.252")
    assert e.mac.address == "00:24:38:17:5d:4e" and e.interface == "xe-14/0/35.0"


def test_unfiltered_arp_commands():
    from fibtrace.walker import _unfiltered, _cli_rejected
    assert _unfiltered("show arp no-resolve hostname {next_hop}") == "show arp no-resolve"
    assert _unfiltered("show ip arp {next_hop}") == "show ip arp"
    assert _cli_rejected("show arp no-resolve hostname 10.0.0.1\n                            ^\nsyntax error, expecting <command>.")
    assert not _cli_rejected("<rpc-reply><arp-table-information/></rpc-reply>")
