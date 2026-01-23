"""MITRE ATT&CK technique mapping."""

from ariadne.models.attack_path import AttackTechnique
from ariadne.models.relationship import RelationType


TECHNIQUE_DATABASE: dict[str, dict] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host.",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "initial-access",
        "description": "Adversaries may leverage external remote services to gain access to a network.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral-movement",
        "description": "Adversaries may use valid accounts to log into remote services.",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral-movement",
        "description": "Adversaries may use RDP to log into remote systems.",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "lateral-movement",
        "description": "Adversaries may use SMB to interact with remote systems.",
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "lateral-movement",
        "description": "Adversaries may use SSH to log into remote machines.",
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactic": "lateral-movement",
        "description": "Adversaries may use WinRM for remote execution.",
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to steal or forge Kerberos tickets.",
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactic": "credential-access",
        "description": "Adversaries may abuse Kerberos to obtain service ticket hashes.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to dump credentials from the OS.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to dump LSASS memory for credentials.",
    },
    "T1003.006": {
        "name": "DCSync",
        "tactic": "credential-access",
        "description": "Adversaries may use DCSync to replicate AD credentials.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "description": "Adversaries may manipulate accounts to maintain access.",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "privilege-escalation",
        "description": "Adversaries may exploit vulnerabilities to escalate privileges.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "privilege-escalation",
        "description": "Adversaries may bypass UAC or sudo to elevate privileges.",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "lateral-movement",
        "description": "Adversaries may use alternate auth material like hashes or tickets.",
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactic": "lateral-movement",
        "description": "Adversaries may use stolen NTLM hashes to authenticate.",
    },
}


RELATIONSHIP_TECHNIQUE_MAP: dict[RelationType, list[str]] = {
    RelationType.CAN_RDP: ["T1021.001"],
    RelationType.CAN_SSH: ["T1021.004"],
    RelationType.CAN_PSREMOTE: ["T1021.006"],
    RelationType.ADMIN_TO: ["T1021.002", "T1078"],
    RelationType.HAS_SESSION: ["T1550.002"],
    RelationType.CAN_EXPLOIT: ["T1190", "T1068"],
    RelationType.HAS_GENERIC_ALL: ["T1098", "T1003.006"],
    RelationType.HAS_GENERIC_WRITE: ["T1098"],
    RelationType.CAN_FORCE_CHANGE_PASSWORD: ["T1098"],
    RelationType.CAN_READ_LAPS: ["T1003"],
    RelationType.CAN_READ_GMSA: ["T1003"],
}


class TechniqueMapper:
    """Map attack steps to MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self.techniques = TECHNIQUE_DATABASE
        self.relationship_map = RELATIONSHIP_TECHNIQUE_MAP

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        """Get technique details by ID."""
        if technique_id not in self.techniques:
            return None

        data = self.techniques[technique_id]
        return AttackTechnique(
            technique_id=technique_id,
            name=data["name"],
            tactic=data["tactic"],
            description=data.get("description"),
        )

    def map_relationship(self, relation_type: RelationType) -> list[AttackTechnique]:
        """Map a relationship type to relevant techniques."""
        technique_ids = self.relationship_map.get(relation_type, [])
        techniques = []

        for tid in technique_ids:
            technique = self.get_technique(tid)
            if technique:
                techniques.append(technique)

        return techniques

    def map_service(self, service_name: str, port: int) -> list[AttackTechnique]:
        """Map a service to techniques for exploiting it."""
        techniques = []

        if service_name in ["http", "https"] or port in [80, 443, 8080, 8443]:
            techniques.append(self.get_technique("T1190"))

        if service_name == "ssh" or port == 22:
            techniques.append(self.get_technique("T1021.004"))
            techniques.append(self.get_technique("T1078"))

        if service_name == "rdp" or port == 3389:
            techniques.append(self.get_technique("T1021.001"))
            techniques.append(self.get_technique("T1078"))

        if service_name in ["smb", "microsoft-ds"] or port in [445, 139]:
            techniques.append(self.get_technique("T1021.002"))

        if service_name == "winrm" or port in [5985, 5986]:
            techniques.append(self.get_technique("T1021.006"))

        if service_name == "kerberos" or port == 88:
            techniques.append(self.get_technique("T1558"))
            techniques.append(self.get_technique("T1558.003"))

        if service_name == "ldap" or port in [389, 636]:
            techniques.append(self.get_technique("T1003.006"))

        return [t for t in techniques if t is not None]

    def map_vulnerability(self, vuln_title: str, vuln_type: str = "") -> list[AttackTechnique]:
        """Map a vulnerability to relevant techniques."""
        techniques = []
        title_lower = vuln_title.lower()

        if any(t in title_lower for t in ["rce", "remote code", "command injection"]):
            techniques.append(self.get_technique("T1190"))

        if any(t in title_lower for t in ["privilege", "escalation", "lpe"]):
            techniques.append(self.get_technique("T1068"))

        if any(t in title_lower for t in ["credential", "password", "hash"]):
            techniques.append(self.get_technique("T1003"))

        if any(t in title_lower for t in ["kerberos", "spn", "delegation"]):
            techniques.append(self.get_technique("T1558"))

        if any(t in title_lower for t in ["auth", "bypass", "default cred"]):
            techniques.append(self.get_technique("T1078"))

        return [t for t in techniques if t is not None]

    def list_all_techniques(self) -> list[AttackTechnique]:
        """List all known techniques."""
        return [
            AttackTechnique(
                technique_id=tid,
                name=data["name"],
                tactic=data["tactic"],
                description=data.get("description"),
            )
            for tid, data in self.techniques.items()
        ]

    def get_techniques_by_tactic(self, tactic: str) -> list[AttackTechnique]:
        """Get all techniques for a specific tactic."""
        return [
            AttackTechnique(
                technique_id=tid,
                name=data["name"],
                tactic=data["tactic"],
                description=data.get("description"),
            )
            for tid, data in self.techniques.items()
            if data["tactic"] == tactic
        ]
