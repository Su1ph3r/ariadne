"""Tests for finding models (Vulnerability, Misconfiguration, Credential)."""

import pytest
from datetime import datetime

from ariadne.models.finding import Finding, Vulnerability, Misconfiguration, Credential


class TestFindingBase:
    """Test base Finding class."""

    def test_finding_has_id(self):
        """Test Finding has auto-generated ID."""
        finding = Finding(title="Test Finding")
        assert finding.id is not None
        assert len(finding.id) > 0

    def test_finding_required_title(self):
        """Test Finding requires title."""
        finding = Finding(title="Test Finding")
        assert finding.title == "Test Finding"

    def test_finding_defaults(self):
        """Test Finding default values."""
        finding = Finding(title="Test")
        assert finding.description == ""
        assert finding.severity == "info"
        assert finding.affected_asset_id is None
        assert finding.source == "unknown"
        assert isinstance(finding.discovered_at, datetime)
        assert finding.tags == []
        assert finding.references == []
        assert finding.raw_data == {}

    def test_finding_severity_score_critical(self):
        """Test Finding severity_score for critical."""
        finding = Finding(title="Test", severity="critical")
        assert finding.severity_score == 1.0

    def test_finding_severity_score_high(self):
        """Test Finding severity_score for high."""
        finding = Finding(title="Test", severity="high")
        assert finding.severity_score == 0.8

    def test_finding_severity_score_medium(self):
        """Test Finding severity_score for medium."""
        finding = Finding(title="Test", severity="medium")
        assert finding.severity_score == 0.5

    def test_finding_severity_score_low(self):
        """Test Finding severity_score for low."""
        finding = Finding(title="Test", severity="low")
        assert finding.severity_score == 0.3

    def test_finding_severity_score_info(self):
        """Test Finding severity_score for info."""
        finding = Finding(title="Test", severity="info")
        assert finding.severity_score == 0.1

    def test_finding_severity_score_unknown(self):
        """Test Finding severity_score for unknown severity."""
        finding = Finding(title="Test", severity="unknown")
        assert finding.severity_score == 0.1

    def test_finding_severity_score_case_insensitive(self):
        """Test Finding severity_score is case insensitive."""
        finding = Finding(title="Test", severity="CRITICAL")
        assert finding.severity_score == 1.0


class TestVulnerability:
    """Test Vulnerability model."""

    def test_vuln_id_generation_with_cve(self):
        """Test Vulnerability ID is generated from CVE."""
        vuln = Vulnerability(
            title="Test Vuln",
            cve_id="CVE-2023-1234",
            affected_asset_id="host:192.168.1.1",
        )
        assert vuln.id == "vuln:CVE-2023-1234:host:192.168.1.1"

    def test_vuln_id_generation_without_cve(self):
        """Test Vulnerability ID is generated from title."""
        vuln = Vulnerability(
            title="Some Long Vulnerability Title Here",
            affected_asset_id="host:192.168.1.1",
        )
        assert "vuln:Some Long Vulnerability Title " in vuln.id

    def test_vuln_id_generation_without_asset(self):
        """Test Vulnerability ID handles missing asset ID."""
        vuln = Vulnerability(title="Test", cve_id="CVE-2023-1234")
        assert "unknown" in vuln.id

    def test_vuln_defaults(self):
        """Test Vulnerability default values."""
        vuln = Vulnerability(title="Test")
        assert vuln.cve_id is None
        assert vuln.cvss_score is None
        assert vuln.cvss_vector is None
        assert vuln.exploit_available is False
        assert vuln.exploit_db_id is None
        assert vuln.metasploit_module is None
        assert vuln.patch_available is False
        assert vuln.patch_url is None
        assert vuln.template_id is None
        assert vuln.cwe_id is None

    def test_vuln_with_all_fields(self):
        """Test Vulnerability with all fields populated."""
        vuln = Vulnerability(
            title="EternalBlue",
            description="SMB remote code execution",
            cve_id="CVE-2017-0144",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
            exploit_available=True,
            exploit_db_id="42315",
            metasploit_module="exploit/windows/smb/ms17_010_eternalblue",
            patch_available=True,
            patch_url="https://support.microsoft.com/kb/4012598",
            cwe_id="CWE-119",
            affected_asset_id="host:192.168.1.1",
            source="nessus",
        )
        assert vuln.cve_id == "CVE-2017-0144"
        assert vuln.cvss_score == 9.8
        assert vuln.exploit_available is True
        assert vuln.patch_available is True

    def test_vuln_severity_score_uses_cvss(self):
        """Test Vulnerability severity_score uses CVSS when available."""
        vuln = Vulnerability(title="Test", cvss_score=7.5, severity="low")
        assert vuln.severity_score == 0.75

    def test_vuln_severity_score_fallback(self):
        """Test Vulnerability severity_score falls back to string severity."""
        vuln = Vulnerability(title="Test", severity="high")
        assert vuln.severity_score == 0.8

    def test_vuln_severity_score_max_cvss(self):
        """Test Vulnerability severity_score caps at 1.0."""
        vuln = Vulnerability(title="Test", cvss_score=10.0)
        assert vuln.severity_score == 1.0

    def test_vuln_severity_score_over_10_capped(self):
        """Test Vulnerability severity_score is capped for invalid CVSS."""
        vuln = Vulnerability(title="Test", cvss_score=15.0)
        assert vuln.severity_score == 1.0

    def test_vuln_is_critical_by_cvss(self):
        """Test Vulnerability is_critical property by CVSS."""
        vuln = Vulnerability(title="Test", cvss_score=9.5)
        assert vuln.is_critical is True

    def test_vuln_is_critical_by_severity(self):
        """Test Vulnerability is_critical property by severity string."""
        vuln = Vulnerability(title="Test", severity="critical")
        assert vuln.is_critical is True

    def test_vuln_not_critical(self):
        """Test Vulnerability is_critical property for non-critical."""
        vuln = Vulnerability(title="Test", cvss_score=7.0, severity="high")
        assert vuln.is_critical is False


class TestMisconfiguration:
    """Test Misconfiguration model."""

    def test_misconfig_id_generation_with_check_id(self):
        """Test Misconfiguration ID is generated from check_id."""
        misconfig = Misconfiguration(
            title="SMB Signing Disabled",
            check_id="smb-signing",
            affected_asset_id="host:192.168.1.1",
        )
        assert misconfig.id == "misconfig:smb-signing:host:192.168.1.1"

    def test_misconfig_id_generation_without_check_id(self):
        """Test Misconfiguration ID is generated from title."""
        misconfig = Misconfiguration(
            title="Some Misconfiguration Check",
            affected_asset_id="host:192.168.1.1",
        )
        assert "misconfig:Some Misconfiguration Check" in misconfig.id

    def test_misconfig_defaults(self):
        """Test Misconfiguration default values."""
        misconfig = Misconfiguration(title="Test")
        assert misconfig.check_id is None
        assert misconfig.template_id is None
        assert misconfig.rationale is None
        assert misconfig.remediation is None
        assert misconfig.compliance_frameworks == []
        assert misconfig.expected_value is None
        assert misconfig.actual_value is None

    def test_misconfig_with_all_fields(self):
        """Test Misconfiguration with all fields populated."""
        misconfig = Misconfiguration(
            title="SMB Signing Not Required",
            description="SMB signing is not enforced",
            check_id="smb-signing-disabled",
            severity="high",
            rationale="Allows NTLM relay attacks",
            remediation="Enable SMB signing via GPO",
            compliance_frameworks=["CIS", "NIST"],
            expected_value="Required",
            actual_value="Not Required",
            affected_asset_id="host:192.168.1.1",
            source="crackmapexec",
        )
        assert misconfig.check_id == "smb-signing-disabled"
        assert misconfig.rationale == "Allows NTLM relay attacks"
        assert misconfig.remediation is not None
        assert "CIS" in misconfig.compliance_frameworks


class TestCredential:
    """Test Credential model."""

    def test_cred_id_generation_with_domain(self):
        """Test Credential ID is generated with domain."""
        cred = Credential(
            title="Hash",
            credential_type="ntlm",
            username="jsmith",
            domain="CORP",
        )
        assert cred.id == "cred:ntlm:CORP\\jsmith"

    def test_cred_id_generation_without_domain(self):
        """Test Credential ID is generated without domain."""
        cred = Credential(
            title="Hash",
            credential_type="ntlm",
            username="jsmith",
        )
        assert cred.id == "cred:ntlm:jsmith"

    def test_cred_id_generation_without_username(self):
        """Test Credential ID handles missing username."""
        cred = Credential(
            title="API Key",
            credential_type="api_key",
        )
        assert "cred:api_key:unknown" in cred.id

    def test_cred_auto_title(self):
        """Test Credential auto-generates title."""
        cred = Credential(
            title="",
            credential_type="ntlm",
            username="jsmith",
        )
        assert "ntlm" in cred.title
        assert "jsmith" in cred.title

    def test_cred_defaults(self):
        """Test Credential default values."""
        cred = Credential(title="Test", credential_type="password")
        assert cred.username is None
        assert cred.domain is None
        assert cred.value == ""
        assert cred.hash_type is None
        assert cred.is_cracked is False
        assert cred.cracked_value is None
        assert cred.ntlm_hash is None
        assert cred.last_changed is None
        assert cred.origin is None

    def test_cred_with_all_fields(self):
        """Test Credential with all fields populated."""
        cred = Credential(
            title="NTLM Hash for jsmith",
            credential_type="ntlm",
            username="jsmith",
            domain="CORP",
            value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            is_cracked=True,
            cracked_value="Password123!",
            severity="critical",
            origin="secretsdump",
            source="impacket",
        )
        assert cred.username == "jsmith"
        assert cred.domain == "CORP"
        assert cred.is_cracked is True
        assert cred.cracked_value == "Password123!"

    def test_cred_is_hash_ntlm(self):
        """Test Credential is_hash property for NTLM."""
        cred = Credential(title="Test", credential_type="ntlm")
        assert cred.is_hash is True

    def test_cred_is_hash_kerberos(self):
        """Test Credential is_hash property for Kerberos."""
        cred = Credential(title="Test", credential_type="kerberos")
        assert cred.is_hash is True

    def test_cred_is_hash_md5(self):
        """Test Credential is_hash property for MD5."""
        cred = Credential(title="Test", credential_type="md5")
        assert cred.is_hash is True

    def test_cred_is_hash_sha1(self):
        """Test Credential is_hash property for SHA1."""
        cred = Credential(title="Test", credential_type="sha1")
        assert cred.is_hash is True

    def test_cred_is_hash_password(self):
        """Test Credential is_hash property for password (not a hash)."""
        cred = Credential(title="Test", credential_type="password")
        assert cred.is_hash is False

    def test_cred_is_hash_api_key(self):
        """Test Credential is_hash property for API key (not a hash)."""
        cred = Credential(title="Test", credential_type="api_key")
        assert cred.is_hash is False

    def test_cred_masked_value_short(self):
        """Test Credential masked_value for short values."""
        cred = Credential(title="Test", credential_type="password", value="abc")
        assert cred.masked_value == "***"

    def test_cred_masked_value_long(self):
        """Test Credential masked_value for longer values."""
        cred = Credential(title="Test", credential_type="password", value="Password123!")
        masked = cred.masked_value
        assert masked.startswith("Pa")
        assert masked.endswith("!")
        assert "*" in masked
        assert len(masked) == len("Password123!")

    def test_cred_masked_value_hash(self):
        """Test Credential masked_value for hash."""
        cred = Credential(
            title="Test",
            credential_type="ntlm",
            value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        masked = cred.masked_value
        assert masked.startswith("aa")
        assert masked.endswith("c0")
        assert "*" in masked
