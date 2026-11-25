"""Junos FIB lookup that lands on the default route: 'default' as the destination, a permanent reject entry
beside the routed one, and internal tables in the same reply."""

from fibtrace.models import FibState
from fibtrace.parsers import JunosParser

XML = """show route forwarding-table destination 10.7.255.11 | display xml
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.1R0/junos">
    <forwarding-table-information xmlns="http://xml.juniper.net/junos/21.1R0/junos-rtinfo">
        <route-table>
            <table-name>default.inet</table-name>
            <address-family>Internet</address-family>
            <enabled-protocols></enabled-protocols>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <destination-type>user</destination-type>
                <route-reference-count>0</route-reference-count>
                <nh>
                    <nh-type>ulst</nh-type>
                    <nh-index>524287</nh-index>
                    <nh-reference-count>2</nh-reference-count>
                    <nh>
                        <to>100.64.4.174</to>
                        <nh-type>ucst</nh-type>
                        <via>et-0/0/49.0</via>
                    </nh>
                    <nh>
                        <to>100.64.4.176</to>
                        <nh-type>ucst</nh-type>
                        <via>et-0/0/50.0</via>
                    </nh>
                </nh>
            </rt-entry>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <destination-type>perm</destination-type>
                <nh>
                    <nh-type>rjct</nh-type>
                    <nh-index>36</nh-index>
                </nh>
            </rt-entry>
        </route-table>
        <route-table>
            <table-name>__juniper_private1__.inet</table-name>
            <address-family>Internet</address-family>
            <rt-entry junos:style="brief">
                <rt-destination>default</rt-destination>
                <nh><nh-type>rjct</nh-type></nh>
            </rt-entry>
        </route-table>
    </forwarding-table-information>
</rpc-reply>
tor424.iad2>"""


def test_default_route_fib():
    fib = JunosParser.parse_fib(XML, "10.7.255.11/32")
    assert fib is not None
    assert str(fib.prefix.network) == "0.0.0.0/0"
    assert fib.state == FibState.PROGRAMMED and fib.resolved
    assert [(str(n.address), n.interface) for n in fib.next_hops] == [
        ("100.64.4.174", "et-0/0/49.0"), ("100.64.4.176", "et-0/0/50.0")]


def test_only_reject_is_drop():
    xml = """<rpc-reply><forwarding-table-information><route-table>
        <table-name>default.inet</table-name><address-family>Internet</address-family>
        <rt-entry><rt-destination>default</rt-destination><nh><nh-type>rjct</nh-type></nh></rt-entry>
    </route-table></forwarding-table-information></rpc-reply>"""
    fib = JunosParser.parse_fib(xml, "10.7.255.11/32")
    assert fib is not None and fib.state == FibState.DROP and not fib.resolved
