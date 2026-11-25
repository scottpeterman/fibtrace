"""MAC table parsing: Junos ELS (EX/QFX) XML and EOS JSON."""

from fibtrace.parsers import AristaEOSParser, JunosParser

JUNOS = """show ethernet-switching table 00:25:90:ff:9d:27 | display xml
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/18.2R3/junos">
    <l2ng-l2ald-rtb-macdb>
        <l2ng-l2ald-mac-entry-vlan junos:style="brief-rtb">
            <mac-count-global>279</mac-count-global>
            <learnt-mac-count>279</learnt-mac-count>
            <l2ng-l2-mac-routing-instance>default-switch</l2ng-l2-mac-routing-instance>
            <l2ng-l2-vlan-id>127</l2ng-l2-vlan-id>
            <l2ng-mac-entry>
                <l2ng-l2-mac-vlan-name>oob</l2ng-l2-mac-vlan-name>
                <l2ng-l2-mac-address>00:25:90:ff:9d:27</l2ng-l2-mac-address>
                <l2ng-l2-mac-flags>D</l2ng-l2-mac-flags>
                <l2ng-l2-mac-age>-</l2ng-l2-mac-age>
                <l2ng-l2-mac-logical-interface>ge-0/0/47.0</l2ng-l2-mac-logical-interface>
                <l2ng-l2-mac-fwd-next-hop>0</l2ng-l2-mac-fwd-next-hop>
                <l2ng-l2-mac-rtr-id>0</l2ng-l2-mac-rtr-id>
            </l2ng-mac-entry>
        </l2ng-l2ald-mac-entry-vlan>
    </l2ng-l2ald-rtb-macdb>
    <cli>
        <banner>{master:0}</banner>
    </cli>
</rpc-reply>

{master:0}
user@sw1>"""

EOS = """show mac address-table address 0c:c4:7a:3c:82:02 | json
{
    "multicastTable": {"tableEntries": []},
    "unicastTable": {"tableEntries": [
        {"macAddress": "0c:c4:7a:3c:82:02", "lastMove": 1705451840.9, "interface": "Ethernet10",
         "moves": 31, "entryType": "dynamic", "vlanId": 127}]},
    "disabledMacLearningVlans": []
}
sw2#"""


def test_junos_els_mac():
    e = JunosParser.parse_mac_table(JUNOS)
    assert (e.mac.address, e.vlan, e.interface, e.entry_type) == ("00:25:90:ff:9d:27", 127, "ge-0/0/47.0", "dynamic")


def test_junos_mac_not_found_and_router_error():
    empty = JUNOS[:JUNOS.index("<l2ng-mac-entry>")] + "</l2ng-l2ald-mac-entry-vlan></l2ng-l2ald-rtb-macdb></rpc-reply>"
    assert JunosParser.parse_mac_table(empty) is None
    assert JunosParser.parse_mac_table("show ethernet-switching table 00:25:90:ff:9d:27 | display xml\n"
                                       "                    ^\nsyntax error.\nuser@mx1>") is None


def test_eos_mac():
    e = AristaEOSParser.parse_mac_table(EOS)
    assert (e.mac.address, e.vlan, e.interface) == ("0c:c4:7a:3c:82:02", 127, "Ethernet10")


QFX = """<rpc-reply xmlns:junos="http://xml.juniper.net/junos/14.1X53/junos">
    <l2ng-l2ald-rtb-macdb>
        <l2ng-l2ald-mac-entry-vlan junos:style="brief-rtb">
            <l2ng-l2-mac-routing-instance>default-switch</l2ng-l2-mac-routing-instance>
            <l2ng-l2-vlan-id>645</l2ng-l2-vlan-id>
            <l2ng-mac-entry>
                <l2ng-l2-mac-vlan-name>cust-a</l2ng-l2-mac-vlan-name>
                <l2ng-l2-mac-address>00:24:38:17:5d:4e</l2ng-l2-mac-address>
                <l2ng-l2-mac-flags>D</l2ng-l2-mac-flags>
                <l2ng-l2-mac-logical-interface>ae7.0</l2ng-l2-mac-logical-interface>
            </l2ng-mac-entry>
        </l2ng-l2ald-mac-entry-vlan>
        <l2ng-l2ald-mac-entry-vlan junos:style="brief-rtb">
            <l2ng-l2-mac-routing-instance>default-switch</l2ng-l2-mac-routing-instance>
            <l2ng-l2-vlan-id>127</l2ng-l2-vlan-id>
            <l2ng-mac-entry>
                <l2ng-l2-mac-vlan-name>oob</l2ng-l2-mac-vlan-name>
                <l2ng-l2-mac-address>00:24:38:17:5d:4e</l2ng-l2-mac-address>
                <l2ng-l2-mac-flags>D</l2ng-l2-mac-flags>
                <l2ng-l2-mac-logical-interface>ae6.0</l2ng-l2-mac-logical-interface>
            </l2ng-mac-entry>
        </l2ng-l2ald-mac-entry-vlan>
    </l2ng-l2ald-rtb-macdb>
</rpc-reply>"""


def test_same_mac_in_two_vlans_uses_the_svi_vlan():
    assert JunosParser.parse_mac_table(QFX, 127).interface == "ae6.0"
    assert JunosParser.parse_mac_table(QFX, 645).interface == "ae7.0"
    assert JunosParser.parse_mac_table(QFX, 99) is None        # IRB unit that is not the VLAN id: no guess
    assert JunosParser.parse_mac_table(QFX) is None            # two VLANs, none named: no guess


def test_eos_vlan_filter():
    assert AristaEOSParser.parse_mac_table(EOS, 127).interface == "Ethernet10"
    assert AristaEOSParser.parse_mac_table(EOS, 200) is None
