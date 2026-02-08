"""Test Nmap adapter XML parsing."""
import os
from netsec.adapters.nmap import Adapter

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'fixtures')

def _load_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name), 'r') as f:
        return f.read()


def test_parse_nmap_xml():
    adapter = Adapter()
    result = adapter._parse_xml(_load_fixture('nmap_single_host.xml'))

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


def test_parse_nmap_empty_scan():
    adapter = Adapter()
    result = adapter._parse_xml(_load_fixture('nmap_empty.xml'))

    assert len(result["hosts"]) == 0


def test_parse_nmap_host_zero_ports():
    """Host with no open ports should parse without errors."""
    xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished elapsed="1.00" summary="1 host up"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""
    adapter = Adapter()
    result = adapter._parse_xml(xml)

    assert len(result["hosts"]) == 1
    assert len(result["hosts"][0]["ports"]) == 0
