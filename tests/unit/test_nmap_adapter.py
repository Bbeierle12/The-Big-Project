"""Test Nmap adapter XML parsing."""
from netsec.adapters.nmap import Adapter

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1234567890" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
    </os>
  </host>
  <runstats>
    <finished elapsed="2.50" summary="1 host up"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""


def test_parse_nmap_xml():
    adapter = Adapter()
    result = adapter._parse_xml(SAMPLE_XML)

    assert len(result["hosts"]) == 1
    host = result["hosts"][0]
    assert host["status"] == "up"
    assert host["addresses"]["ipv4"] == "192.168.1.1"
    assert host["addresses"]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert host["addresses"]["vendor"] == "TestVendor"
    assert host["hostnames"][0]["name"] == "router.local"
    assert len(host["ports"]) == 2
    assert host["ports"][0]["port"] == 22
    assert host["ports"][0]["service"] == "ssh"
    assert host["os"]["name"] == "Linux 5.x"
    assert result["stats"]["hosts_up"] == 1
