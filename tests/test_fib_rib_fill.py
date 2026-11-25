"""EX/QFX FIB next hops that carry a MAC, not an IP: the walk takes the address from the RIB."""

from ipaddress import ip_address

from fibtrace.models import FibState
from fibtrace.parsers import JunosParser
from fibtrace.walker import fill_fib_addresses

EX_FIB = """<rpc-reply xmlns:junos="http://xml.juniper.net/junos/18.2R3/junos">
    <forwarding-table-information xmlns="http://xml.juniper.net/junos/18.2R3/junos-rtinfo">
        <route-table>
            <table-name>default.inet</table-name>
            <address-family>Internet</address-family>
            <enabled-protocols>Bridging, </enabled-protocols>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <destination-type>user</destination-type>
                <route-reference-count>1</route-reference-count>
                <nh>
                    <to>
                        0:0:5e:0:1:1
                    </to>
                    <nh-type>ucst</nh-type>
                    <nh-index>1781</nh-index>
                    <nh-reference-count>4</nh-reference-count>
                    <via>ge-0/0/47.0</via>
                </nh>
            </rt-entry>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <destination-type>perm</destination-type>
                <nh><to></to><nh-type>rjct</nh-type><nh-index>51</nh-index><via></via></nh>
            </rt-entry>
        </route-table>
        <route-table>
        </route-table>
        <route-table>
            <table-name>__juniper_services__.inet</table-name>
            <address-family>Internet</address-family>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <destination-type>perm</destination-type>
                <nh><to></to><nh-type>dscd</nh-type><via></via></nh>
            </rt-entry>
        </route-table>
        <route-table>
            <table-name>default-switch.inet</table-name>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <nh><to></to><nh-type>rjct</nh-type><via></via></nh>
            </rt-entry>
        </route-table>
    </forwarding-table-information>
    <cli><banner>{master:0}</banner></cli>
</rpc-reply>"""


def test_ex_fib_mac_next_hop():
    fib = JunosParser.parse_fib(EX_FIB, "10.7.255.11/32")
    assert fib.state == FibState.PROGRAMMED
    assert [(n.address, n.interface) for n in fib.next_hops] == [(None, "ge-0/0/47.0")]


def test_fill_from_rib_by_interface():
    a, b = ip_address("100.64.4.174"), ip_address("100.64.4.176")
    fib = [(None, "et-0/0/49.0"), (None, "et-0/0/50.0")]
    rib = [(b, "et-0/0/50.0"), (a, "et-0/0/49.0")]
    assert fill_fib_addresses(fib, rib) == [(a, "et-0/0/49.0"), (b, "et-0/0/50.0")]


def test_fill_single_rib_address_and_fallback():
    gw = ip_address("10.0.127.1")
    assert fill_fib_addresses([(None, "ge-0/0/47.0")], [(gw, "irb.127")]) == [(gw, "ge-0/0/47.0")]
    two = [(ip_address("10.0.0.1"), "xe-0/0/1.0"), (ip_address("10.0.0.3"), "xe-0/0/2.0")]
    assert fill_fib_addresses([(None, "ge-0/0/47.0")], two) == two          # nothing matches: use the RIB
    full = [(gw, "ge-0/0/47.0")]
    assert fill_fib_addresses(full, two) == full                             # FIB already has addresses
