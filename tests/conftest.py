"""Pytest configuration and comprehensive fixtures for Ariadne tests."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import networkx as nx
import pytest

from ariadne.config import AriadneConfig
from ariadne.models.asset import Host, Service, User, CloudResource
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship, RelationType
from ariadne.models.attack_path import AttackPath, AttackStep, AttackTechnique
from ariadne.models.playbook import Playbook, PlaybookStep, PlaybookCommand


# =============================================================================
# Directory Fixtures
# =============================================================================


@pytest.fixture
def sample_data_dir() -> Path:
    """Return path to sample data directory."""
    return Path(__file__).parent / "fixtures" / "sample_data"


@pytest.fixture
def parser_fixtures_dir() -> Path:
    """Return path to parser fixtures directory."""
    return Path(__file__).parent / "fixtures" / "parsers"


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# =============================================================================
# Sample File Fixtures
# =============================================================================


@pytest.fixture
def sample_nmap_xml(sample_data_dir: Path) -> Path:
    """Return path to sample Nmap XML file."""
    return sample_data_dir / "sample_nmap.xml"


@pytest.fixture
def sample_nuclei_json(sample_data_dir: Path) -> Path:
    """Return path to sample Nuclei JSON file."""
    return sample_data_dir / "sample_nuclei.json"


# =============================================================================
# Asset Model Fixtures
# =============================================================================


@pytest.fixture
def sample_host() -> Host:
    """Create a sample Host entity."""
    return Host(
        ip="192.168.1.100",
        hostname="dc01.corp.local",
        os="Windows Server 2019",
        domain="CORP",
        is_dc=True,
        enabled=True,
        ports=[88, 389, 445, 636, 3389],
        source="nmap",
    )


@pytest.fixture
def sample_workstation() -> Host:
    """Create a sample workstation Host entity."""
    return Host(
        ip="192.168.1.50",
        hostname="ws01.corp.local",
        os="Windows 10",
        domain="CORP",
        is_dc=False,
        enabled=True,
        ports=[445, 3389],
        source="nmap",
    )


@pytest.fixture
def sample_linux_host() -> Host:
    """Create a sample Linux Host entity."""
    return Host(
        ip="192.168.1.10",
        hostname="web01.corp.local",
        os="Ubuntu 22.04",
        ports=[22, 80, 443],
        source="nmap",
    )


@pytest.fixture
def sample_service() -> Service:
    """Create a sample Service entity."""
    return Service(
        port=445,
        protocol="tcp",
        name="microsoft-ds",
        product="Windows",
        version="10",
        host_id="host:192.168.1.100",
        source="nmap",
    )


@pytest.fixture
def sample_ssh_service() -> Service:
    """Create a sample SSH Service entity."""
    return Service(
        port=22,
        protocol="tcp",
        name="ssh",
        product="OpenSSH",
        version="8.9p1",
        host_id="host:192.168.1.10",
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
        source="nmap",
    )


@pytest.fixture
def sample_web_service() -> Service:
    """Create a sample HTTP Service entity."""
    return Service(
        port=443,
        protocol="tcp",
        name="https",
        product="nginx",
        version="1.18.0",
        host_id="host:192.168.1.10",
        ssl=True,
        source="nmap",
    )


@pytest.fixture
def sample_user() -> User:
    """Create a sample User entity."""
    return User(
        username="jsmith",
        domain="CORP",
        display_name="John Smith",
        email="jsmith@corp.local",
        enabled=True,
        is_admin=False,
        groups=["Domain Users", "IT Support"],
        source="bloodhound",
    )


@pytest.fixture
def sample_admin_user() -> User:
    """Create a sample admin User entity."""
    return User(
        username="admin",
        domain="CORP",
        display_name="Administrator",
        enabled=True,
        is_admin=True,
        groups=["Domain Admins", "Enterprise Admins", "Administrators"],
        source="bloodhound",
    )


@pytest.fixture
def sample_service_account() -> User:
    """Create a sample service account User entity."""
    return User(
        username="svc_sql",
        domain="CORP",
        display_name="SQL Service Account",
        enabled=True,
        is_admin=False,
        password_never_expires=True,
        groups=["Domain Users"],
        source="bloodhound",
    )


@pytest.fixture
def sample_cloud_resource() -> CloudResource:
    """Create a sample CloudResource entity."""
    return CloudResource(
        resource_id="i-0123456789abcdef0",
        resource_type="EC2",
        name="web-server-prod",
        provider="aws",
        account_id="123456789012",
        region="us-east-1",
        permissions=["ec2:DescribeInstances", "s3:GetObject"],
        source="aws_scout",
    )


@pytest.fixture
def sample_azure_resource() -> CloudResource:
    """Create a sample Azure CloudResource entity."""
    return CloudResource(
        resource_id="00000000-0000-0000-0000-000000000001",
        resource_type="VirtualMachine",
        name="vm-prod-01",
        provider="azure",
        tenant_id="11111111-1111-1111-1111-111111111111",
        subscription_id="22222222-2222-2222-2222-222222222222",
        region="eastus",
        source="azurehound",
    )


# =============================================================================
# Finding Model Fixtures
# =============================================================================


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample Vulnerability entity."""
    return Vulnerability(
        title="EternalBlue SMB Remote Code Execution",
        description="The SMBv1 server allows remote attackers to execute arbitrary code.",
        cve_id="CVE-2017-0144",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="critical",
        exploit_available=True,
        metasploit_module="exploit/windows/smb/ms17_010_eternalblue",
        affected_asset_id="host:192.168.1.100",
        source="nessus",
    )


@pytest.fixture
def sample_medium_vuln() -> Vulnerability:
    """Create a sample medium severity Vulnerability."""
    return Vulnerability(
        title="SSL Certificate Expired",
        description="The SSL certificate for this service has expired.",
        severity="medium",
        cvss_score=5.3,
        affected_asset_id="service:host:192.168.1.10:443/tcp",
        source="testssl",
    )


@pytest.fixture
def sample_info_vuln() -> Vulnerability:
    """Create a sample informational Vulnerability."""
    return Vulnerability(
        title="Server Version Disclosed",
        description="The server discloses its version in HTTP headers.",
        severity="info",
        affected_asset_id="service:host:192.168.1.10:443/tcp",
        source="nuclei",
    )


@pytest.fixture
def sample_misconfiguration() -> Misconfiguration:
    """Create a sample Misconfiguration entity."""
    return Misconfiguration(
        title="SMB Signing Not Required",
        description="SMB signing is not required, allowing relay attacks.",
        check_id="smb-signing-disabled",
        severity="high",
        rationale="Allows NTLM relay attacks against this host.",
        remediation="Enable SMB signing via Group Policy.",
        affected_asset_id="host:192.168.1.100",
        source="crackmapexec",
    )


@pytest.fixture
def sample_ad_misconfiguration() -> Misconfiguration:
    """Create a sample AD Misconfiguration entity."""
    return Misconfiguration(
        title="Kerberos Delegation Enabled",
        description="Unconstrained delegation is enabled on this account.",
        check_id="unconstrained-delegation",
        severity="critical",
        rationale="Unconstrained delegation allows TGT theft.",
        remediation="Remove delegation or use constrained/RBCD instead.",
        affected_asset_id="user:CORP\\svc_sql",
        source="bloodhound",
    )


@pytest.fixture
def sample_credential() -> Credential:
    """Create a sample Credential entity."""
    return Credential(
        title="NTLM Hash for jsmith",
        credential_type="ntlm",
        username="jsmith",
        domain="CORP",
        value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        hash_type="NTLM",
        is_cracked=False,
        severity="high",
        origin="secretsdump",
        source="impacket",
    )


@pytest.fixture
def sample_cracked_credential() -> Credential:
    """Create a sample cracked Credential entity."""
    return Credential(
        title="Cracked password for testuser",
        credential_type="password",
        username="testuser",
        domain="CORP",
        value="Password123!",
        is_cracked=True,
        cracked_value="Password123!",
        severity="critical",
        origin="hashcat",
        source="impacket",
    )


@pytest.fixture
def sample_kerberos_ticket() -> Credential:
    """Create a sample Kerberos ticket Credential."""
    return Credential(
        title="TGS ticket for svc_sql",
        credential_type="kerberos",
        username="svc_sql",
        domain="CORP",
        value="$krb5tgs$23$*svc_sql$CORP$...",
        hash_type="RC4-HMAC",
        severity="high",
        origin="kerberoasting",
        source="rubeus",
    )


# =============================================================================
# Relationship Fixtures
# =============================================================================


@pytest.fixture
def sample_admin_relationship() -> Relationship:
    """Create a sample AdminTo relationship."""
    return Relationship(
        source_id="user:CORP\\admin",
        target_id="host:192.168.1.100",
        relation_type=RelationType.ADMIN_TO,
        confidence=1.0,
        source="bloodhound",
    )


@pytest.fixture
def sample_can_rdp_relationship() -> Relationship:
    """Create a sample CanRDP relationship."""
    return Relationship(
        source_id="user:CORP\\jsmith",
        target_id="host:192.168.1.50",
        relation_type=RelationType.CAN_RDP,
        confidence=1.0,
        source="bloodhound",
    )


@pytest.fixture
def sample_member_of_relationship() -> Relationship:
    """Create a sample MemberOf relationship."""
    return Relationship(
        source_id="user:CORP\\admin",
        target_id="group:CORP\\Domain Admins",
        relation_type=RelationType.MEMBER_OF,
        confidence=1.0,
        source="bloodhound",
    )


@pytest.fixture
def sample_generic_all_relationship() -> Relationship:
    """Create a sample GenericAll relationship."""
    return Relationship(
        source_id="user:CORP\\jsmith",
        target_id="user:CORP\\svc_sql",
        relation_type=RelationType.HAS_GENERIC_ALL,
        confidence=1.0,
        source="bloodhound",
    )


@pytest.fixture
def sample_has_vulnerability_relationship() -> Relationship:
    """Create a sample HasVulnerability relationship."""
    return Relationship(
        source_id="host:192.168.1.100",
        target_id="vuln:CVE-2017-0144:host:192.168.1.100",
        relation_type=RelationType.HAS_VULNERABILITY,
        confidence=1.0,
        source="nessus",
    )


# =============================================================================
# Attack Path Fixtures
# =============================================================================


@pytest.fixture
def sample_attack_technique() -> AttackTechnique:
    """Create a sample MITRE ATT&CK technique."""
    return AttackTechnique(
        technique_id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="Adversaries may use SMB to move laterally.",
    )


@pytest.fixture
def sample_attack_step() -> AttackStep:
    """Create a sample AttackStep."""
    return AttackStep(
        order=0,
        source_asset_id="host:192.168.1.50",
        target_asset_id="host:192.168.1.100",
        action="Lateral Movement via SMB",
        description="Use compromised credentials to access DC via SMB.",
        probability=0.85,
        detection_risk=0.4,
        impact="high",
    )


@pytest.fixture
def sample_attack_path(sample_attack_step: AttackStep) -> AttackPath:
    """Create a sample AttackPath."""
    return AttackPath(
        name="Domain Compromise via EternalBlue",
        description="Exploit EternalBlue on workstation, then lateral move to DC.",
        steps=[sample_attack_step],
        entry_point_id="host:192.168.1.50",
        target_id="host:192.168.1.100",
        probability=0.85,
        impact="critical",
        complexity="low",
    )


@pytest.fixture
def multi_step_attack_path() -> AttackPath:
    """Create a multi-step AttackPath."""
    steps = [
        AttackStep(
            order=0,
            source_asset_id="external",
            target_asset_id="host:192.168.1.10",
            action="Initial Access",
            description="Exploit web application vulnerability.",
            probability=0.7,
            technique=AttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
            ),
        ),
        AttackStep(
            order=1,
            source_asset_id="host:192.168.1.10",
            target_asset_id="host:192.168.1.50",
            action="Lateral Movement",
            description="Move to internal workstation via SSH.",
            probability=0.8,
            technique=AttackTechnique(
                technique_id="T1021.004",
                name="Remote Services: SSH",
                tactic="Lateral Movement",
            ),
        ),
        AttackStep(
            order=2,
            source_asset_id="host:192.168.1.50",
            target_id="host:192.168.1.100",
            target_asset_id="host:192.168.1.100",
            action="Privilege Escalation",
            description="Kerberoast service account and crack hash.",
            probability=0.6,
            technique=AttackTechnique(
                technique_id="T1558.003",
                name="Steal or Forge Kerberos Tickets: Kerberoasting",
                tactic="Credential Access",
            ),
        ),
    ]
    return AttackPath(
        name="Full Kill Chain to Domain Admin",
        description="Web exploit → lateral movement → Kerberoasting → DA",
        steps=steps,
        entry_point_id="external",
        target_id="host:192.168.1.100",
        impact="critical",
        complexity="medium",
    )


# =============================================================================
# Graph Fixtures
# =============================================================================


@pytest.fixture
def empty_graph() -> nx.DiGraph:
    """Create an empty directed graph."""
    return nx.DiGraph()


@pytest.fixture
def simple_graph() -> nx.DiGraph:
    """Create a simple test graph with basic nodes and edges."""
    g = nx.DiGraph()

    g.add_node("host:192.168.1.100", type="host", label="dc01", is_dc=True)
    g.add_node("host:192.168.1.50", type="host", label="ws01", is_dc=False)
    g.add_node("service:host:192.168.1.100:445/tcp", type="service", port=445)
    g.add_node("user:CORP\\admin", type="user", is_admin=True)
    g.add_node("user:CORP\\jsmith", type="user", is_admin=False)
    g.add_node("vuln:CVE-2017-0144:host:192.168.1.100", type="vulnerability", cvss_score=9.8)

    g.add_edge("user:CORP\\admin", "host:192.168.1.100", relation_type="admin_to")
    g.add_edge("user:CORP\\jsmith", "host:192.168.1.50", relation_type="can_rdp")
    g.add_edge("host:192.168.1.100", "vuln:CVE-2017-0144:host:192.168.1.100", relation_type="has_vulnerability")

    return g


@pytest.fixture
def complex_ad_graph() -> nx.DiGraph:
    """Create a more complex AD-style graph for testing path finding."""
    g = nx.DiGraph()

    g.add_node("host:dc01", type="host", is_dc=True, ip="192.168.1.100")
    g.add_node("host:ws01", type="host", is_dc=False, ip="192.168.1.50")
    g.add_node("host:ws02", type="host", is_dc=False, ip="192.168.1.51")
    g.add_node("host:web01", type="host", is_dc=False, ip="192.168.1.10")

    g.add_node("user:admin", type="user", is_admin=True, domain="CORP")
    g.add_node("user:jsmith", type="user", is_admin=False, domain="CORP")
    g.add_node("user:svc_sql", type="user", is_admin=False, domain="CORP")

    g.add_node("group:Domain Admins", type="group")
    g.add_node("group:IT Support", type="group")

    g.add_edge("user:admin", "group:Domain Admins", relation_type="member_of")
    g.add_edge("user:jsmith", "group:IT Support", relation_type="member_of")
    g.add_edge("group:Domain Admins", "host:dc01", relation_type="admin_to")
    g.add_edge("user:jsmith", "host:ws01", relation_type="can_rdp")
    g.add_edge("user:jsmith", "user:svc_sql", relation_type="has_generic_all")
    g.add_edge("user:svc_sql", "host:dc01", relation_type="admin_to")

    return g


# =============================================================================
# Config Fixtures
# =============================================================================


@pytest.fixture
def config() -> AriadneConfig:
    """Create a test configuration."""
    return AriadneConfig()


@pytest.fixture
def config_with_mock_llm() -> AriadneConfig:
    """Create a test configuration with mock LLM settings."""
    config = AriadneConfig()
    config.llm_provider = "mock"
    config.llm_model = "mock-model"
    return config


# =============================================================================
# Mock LLM Fixtures
# =============================================================================


@pytest.fixture
def mock_llm_response() -> dict:
    """Sample LLM response for attack path analysis."""
    return {
        "analysis": "This attack path exploits a critical SMB vulnerability to gain initial access.",
        "confidence": 0.85,
        "recommendations": [
            "Patch EternalBlue vulnerability (MS17-010)",
            "Enable SMB signing",
            "Implement network segmentation",
        ],
        "techniques": [
            {"id": "T1210", "name": "Exploitation of Remote Services"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
        ],
    }


@pytest.fixture
def mock_llm_client(mock_llm_response: dict):
    """Create a mock LLM client."""
    mock_client = MagicMock()
    mock_client.complete.return_value = json.dumps(mock_llm_response)
    mock_client.analyze_path.return_value = mock_llm_response
    mock_client.is_available.return_value = True
    return mock_client


@pytest.fixture
def patched_llm_client(mock_llm_client):
    """Patch the LLM client module."""
    with patch("ariadne.llm.client.LLMClient", return_value=mock_llm_client):
        yield mock_llm_client


# =============================================================================
# Parser Testing Utilities
# =============================================================================


@pytest.fixture
def create_temp_file(temp_dir: Path):
    """Factory fixture to create temporary test files."""

    def _create(name: str, content: str | bytes, binary: bool = False) -> Path:
        file_path = temp_dir / name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            file_path.write_bytes(content if isinstance(content, bytes) else content.encode())
        else:
            file_path.write_text(content if isinstance(content, str) else content.decode())
        return file_path

    return _create


@pytest.fixture
def create_json_file(create_temp_file):
    """Factory fixture to create temporary JSON files."""

    def _create(name: str, data: dict | list) -> Path:
        return create_temp_file(name, json.dumps(data, indent=2))

    return _create


@pytest.fixture
def create_xml_file(create_temp_file):
    """Factory fixture to create temporary XML files."""

    def _create(name: str, content: str) -> Path:
        return create_temp_file(name, content)

    return _create


# =============================================================================
# Entity Collections for Integration Tests
# =============================================================================


@pytest.fixture
def sample_entities(
    sample_host,
    sample_workstation,
    sample_linux_host,
    sample_service,
    sample_ssh_service,
    sample_user,
    sample_admin_user,
    sample_vulnerability,
    sample_misconfiguration,
    sample_credential,
    sample_admin_relationship,
    sample_can_rdp_relationship,
) -> list:
    """Create a collection of sample entities for integration testing."""
    return [
        sample_host,
        sample_workstation,
        sample_linux_host,
        sample_service,
        sample_ssh_service,
        sample_user,
        sample_admin_user,
        sample_vulnerability,
        sample_misconfiguration,
        sample_credential,
        sample_admin_relationship,
        sample_can_rdp_relationship,
    ]


# =============================================================================
# Playbook Fixtures
# =============================================================================


@pytest.fixture
def sample_playbook_command() -> PlaybookCommand:
    """Create a sample PlaybookCommand."""
    return PlaybookCommand(
        tool="impacket-psexec",
        command="psexec.py 'CORP/admin:Password123!@192.168.1.100'",
        description="PsExec for SYSTEM shell via admin access",
        requires_root=False,
        requires_implant=False,
    )


@pytest.fixture
def sample_playbook_step(sample_playbook_command: PlaybookCommand) -> PlaybookStep:
    """Create a sample PlaybookStep."""
    return PlaybookStep(
        order=0,
        attack_step_id="step-001",
        commands=[sample_playbook_command],
        prerequisites=["Admin credentials", "Network access to port 445"],
        opsec_notes=["PsExec creates a service (Event 7045)"],
        fallback_commands=[
            PlaybookCommand(
                tool="impacket-wmiexec",
                command="wmiexec.py 'CORP/admin:Password123!@192.168.1.100'",
                description="WMIExec — stealthier than PsExec",
            )
        ],
        expected_output="SYSTEM shell on target host",
        detection_signatures=["Windows Event 7045"],
        source="template",
    )


@pytest.fixture
def sample_playbook(sample_playbook_step: PlaybookStep) -> Playbook:
    """Create a sample Playbook."""
    return Playbook(
        attack_path_id="path-001",
        steps=[sample_playbook_step],
        global_prerequisites=["Admin credentials", "Network access to port 445"],
        global_opsec_notes=["PsExec creates a service (Event 7045)"],
        estimated_time="15-30 minutes",
        complexity="low",
    )
