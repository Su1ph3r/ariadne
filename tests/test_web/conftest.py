"""Fixtures for web API tests."""

import pytest
from fastapi.testclient import TestClient

from ariadne.web.app import app


@pytest.fixture
def client() -> TestClient:
    """Create test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def nmap_xml_content() -> str:
    """Sample Nmap XML content."""
    return """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1234567890">
<host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="server01" type="PTR"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.0"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4"/>
        </port>
    </ports>
</host>
</nmaprun>"""


@pytest.fixture
def bloodhound_json_content() -> str:
    """Sample BloodHound JSON content."""
    return """{
    "users": [
        {
            "ObjectIdentifier": "S-1-5-21-123-456-789-500",
            "Properties": {
                "name": "ADMIN@CORP.LOCAL",
                "domain": "CORP.LOCAL",
                "enabled": true,
                "admincount": true
            }
        },
        {
            "ObjectIdentifier": "S-1-5-21-123-456-789-1001",
            "Properties": {
                "name": "USER@CORP.LOCAL",
                "domain": "CORP.LOCAL",
                "enabled": true
            }
        }
    ],
    "computers": [
        {
            "ObjectIdentifier": "S-1-5-21-123-456-789-1000",
            "Properties": {
                "name": "DC01.CORP.LOCAL",
                "domain": "CORP.LOCAL"
            }
        }
    ]
}"""
