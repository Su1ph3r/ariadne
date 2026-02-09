"""MITRE ATT&CK technique mapping."""

import logging
from pathlib import Path
from typing import Any

import yaml

from ariadne.models.attack_path import AttackTechnique
from ariadne.models.relationship import RelationType

logger = logging.getLogger(__name__)


# Default techniques database - used as fallback when no config file is found
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
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "privilege-escalation",
        "description": "Adversaries may modify access tokens to operate under a different security context.",
    },
    "T1134.001": {
        "name": "Token Impersonation/Theft",
        "tactic": "privilege-escalation",
        "description": "Adversaries may duplicate then impersonate another user's existing token.",
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "privilege-escalation",
        "description": "Adversaries may hijack the way an OS runs programs to execute their own code.",
    },
    "T1574.007": {
        "name": "Path Interception by PATH Environment Variable",
        "tactic": "privilege-escalation",
        "description": "Adversaries may place a program in an earlier entry in the PATH to hijack execution.",
    },
    "T1574.009": {
        "name": "Path Interception by Unquoted Path",
        "tactic": "privilege-escalation",
        "description": "Adversaries may take advantage of unquoted paths to place an executable.",
    },
    "T1574.010": {
        "name": "Services File Permissions Weakness",
        "tactic": "privilege-escalation",
        "description": "Adversaries may replace service binaries with malicious ones to escalate privileges.",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "privilege-escalation",
        "description": "Adversaries may abuse scheduled tasks to execute malicious code at elevated privileges.",
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactic": "privilege-escalation",
        "description": "Adversaries may bypass UAC to elevate privileges on a system.",
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "credential-access",
        "description": "Adversaries may search local file systems for files containing credentials.",
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to extract credential material from the SAM database.",
    },
    "T1222": {
        "name": "File and Directory Permissions Modification",
        "tactic": "defense-evasion",
        "description": "Adversaries may modify file or directory permissions to evade access control.",
    },
}


# Default relationship to technique mapping
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
    RelationType.CREDENTIAL_REUSE: ["T1078", "T1550.002"],
    RelationType.CAN_AUTH_AS: ["T1078"],
    RelationType.CAN_PRIVESC: ["T1068", "T1134", "T1548"],
}


def _load_techniques_from_file(config_path: Path) -> dict[str, Any] | None:
    """Load techniques configuration from a YAML file.

    Expected format:
    ```yaml
    version: "14.1"  # MITRE ATT&CK version (optional)
    techniques:
      T1190:
        name: "Exploit Public-Facing Application"
        tactic: "initial-access"
        description: "..."
    relationship_mappings:
      CAN_RDP:
        - T1021.001
    ```

    Args:
        config_path: Path to the YAML configuration file

    Returns:
        Parsed configuration dictionary, or None if loading failed
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                logger.warning("Invalid techniques config format: expected dict")
                return None
            return data
    except FileNotFoundError:
        logger.debug("Techniques config file not found: %s", config_path)
        return None
    except yaml.YAMLError as e:
        logger.warning("Failed to parse techniques config: %s", e)
        return None
    except Exception as e:
        logger.warning("Error loading techniques config: %s", e)
        return None


def _parse_relationship_mappings(
    mappings: dict[str, list[str]]
) -> dict[RelationType, list[str]]:
    """Parse relationship mappings from config to RelationType enum keys.

    Args:
        mappings: Dictionary with string keys (relationship names)

    Returns:
        Dictionary with RelationType enum keys
    """
    result: dict[RelationType, list[str]] = {}
    for rel_name, technique_ids in mappings.items():
        try:
            rel_type = RelationType(rel_name.lower())
            result[rel_type] = technique_ids
        except ValueError:
            # Try uppercase version
            try:
                rel_type = RelationType[rel_name.upper()]
                result[rel_type] = technique_ids
            except KeyError:
                logger.warning("Unknown relationship type in config: %s", rel_name)
                continue
    return result


class TechniqueMapper:
    """Map attack steps to MITRE ATT&CK techniques.

    Supports loading technique definitions from an external YAML file
    for easier updates without code changes. Falls back to built-in
    defaults if no config file is provided or found.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        """Initialize the technique mapper.

        Args:
            config_path: Optional path to a YAML configuration file.
                        If None, uses built-in defaults.
        """
        self.techniques = TECHNIQUE_DATABASE.copy()
        self.relationship_map = RELATIONSHIP_TECHNIQUE_MAP.copy()
        self.version: str | None = None

        if config_path:
            self._load_from_file(config_path)

    def _load_from_file(self, config_path: Path) -> None:
        """Load techniques from a configuration file.

        Args:
            config_path: Path to the YAML configuration file
        """
        data = _load_techniques_from_file(config_path)
        if not data:
            return

        self.version = data.get("version")

        # Load techniques
        if "techniques" in data and isinstance(data["techniques"], dict):
            loaded_count = 0
            for tid, tdata in data["techniques"].items():
                if isinstance(tdata, dict) and "name" in tdata and "tactic" in tdata:
                    self.techniques[tid] = tdata
                    loaded_count += 1
                else:
                    logger.warning(
                        "Invalid technique entry '%s': missing name or tactic", tid
                    )
            logger.info(
                "Loaded %d techniques from %s (version: %s)",
                loaded_count,
                config_path,
                self.version or "unknown",
            )

        # Load relationship mappings
        if "relationship_mappings" in data and isinstance(
            data["relationship_mappings"], dict
        ):
            parsed = _parse_relationship_mappings(data["relationship_mappings"])
            self.relationship_map.update(parsed)
            logger.debug(
                "Loaded %d relationship mappings from config", len(parsed)
            )

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
