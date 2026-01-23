"""Fixture generators for creating sample parser output data.

These generators create realistic sample data for testing parsers without
requiring actual tool output files.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any


# =============================================================================
# Nmap Output Generators
# =============================================================================


def generate_nmap_xml(
    hosts: list[dict[str, Any]] | None = None,
    scanner: str = "nmap",
    version: str = "7.94",
) -> str:
    """Generate sample Nmap XML output.

    Args:
        hosts: List of host dicts with keys: ip, hostname, ports, os
        scanner: Scanner name
        version: Scanner version

    Returns:
        XML string
    """
    if hosts is None:
        hosts = [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9"}],
            }
        ]

    root = ET.Element("nmaprun", scanner=scanner, version=version)

    for host_data in hosts:
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", state="up")
        ET.SubElement(host, "address", addr=host_data["ip"], addrtype="ipv4")

        if "hostname" in host_data:
            hostnames = ET.SubElement(host, "hostnames")
            ET.SubElement(hostnames, "hostname", name=host_data["hostname"])

        if "os" in host_data:
            os_elem = ET.SubElement(host, "os")
            ET.SubElement(os_elem, "osmatch", name=host_data["os"], accuracy="100")

        if "ports" in host_data:
            ports = ET.SubElement(host, "ports")
            for port_data in host_data["ports"]:
                port = ET.SubElement(
                    ports, "port",
                    protocol=port_data.get("proto", "tcp"),
                    portid=str(port_data["port"])
                )
                ET.SubElement(port, "state", state="open")
                service_attrs = {"name": port_data.get("service", "unknown")}
                if "product" in port_data:
                    service_attrs["product"] = port_data["product"]
                if "version" in port_data:
                    service_attrs["version"] = port_data["version"]
                ET.SubElement(port, "service", **service_attrs)

    return ET.tostring(root, encoding="unicode")


def generate_nmap_xml_with_scripts(host_ip: str, scripts: list[dict]) -> str:
    """Generate Nmap XML with NSE script output."""
    root = ET.Element("nmaprun", scanner="nmap", version="7.94")
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "status", state="up")
    ET.SubElement(host, "address", addr=host_ip, addrtype="ipv4")

    ports = ET.SubElement(host, "ports")
    port = ET.SubElement(ports, "port", protocol="tcp", portid="445")
    ET.SubElement(port, "state", state="open")
    ET.SubElement(port, "service", name="microsoft-ds")

    for script_data in scripts:
        script = ET.SubElement(port, "script", id=script_data["id"])
        script.set("output", script_data.get("output", ""))
        for elem_data in script_data.get("elements", []):
            ET.SubElement(script, "elem", key=elem_data["key"]).text = elem_data["value"]

    return ET.tostring(root, encoding="unicode")


# =============================================================================
# Nuclei Output Generators
# =============================================================================


def generate_nuclei_json(findings: list[dict[str, Any]] | None = None) -> str:
    """Generate sample Nuclei JSON output (JSONL format).

    Args:
        findings: List of finding dicts

    Returns:
        JSONL string (one JSON object per line)
    """
    if findings is None:
        findings = [
            {
                "template-id": "exposed-panels/phpmyadmin",
                "host": "http://192.168.1.10:8080",
                "matched-at": "http://192.168.1.10:8080/phpmyadmin/",
                "severity": "info",
                "name": "phpMyAdmin Panel Detected",
            }
        ]

    lines = []
    for finding in findings:
        obj = {
            "template-id": finding.get("template-id", "unknown"),
            "template": f"templates/{finding.get('template-id', 'unknown')}.yaml",
            "host": finding.get("host", "http://localhost"),
            "matched-at": finding.get("matched-at", finding.get("host", "")),
            "type": finding.get("type", "http"),
            "severity": finding.get("severity", "info"),
            "info": {
                "name": finding.get("name", "Unknown Finding"),
                "description": finding.get("description", ""),
                "severity": finding.get("severity", "info"),
            },
            "timestamp": finding.get("timestamp", datetime.utcnow().isoformat()),
        }
        if "cve" in finding:
            obj["info"]["classification"] = {"cve-id": finding["cve"]}
        lines.append(json.dumps(obj))

    return "\n".join(lines)


# =============================================================================
# BloodHound Output Generators
# =============================================================================


def generate_bloodhound_users_json(users: list[dict] | None = None) -> str:
    """Generate BloodHound users JSON."""
    if users is None:
        users = [
            {
                "name": "ADMIN@CORP.LOCAL",
                "enabled": True,
                "admincount": True,
                "groups": ["DOMAIN ADMINS@CORP.LOCAL"],
            }
        ]

    data = {
        "meta": {"count": len(users), "type": "users", "version": 5},
        "data": [],
    }

    for user in users:
        user_obj = {
            "ObjectIdentifier": f"S-1-5-21-{hash(user['name']) % 1000000000}",
            "Properties": {
                "name": user["name"],
                "domain": user["name"].split("@")[1] if "@" in user["name"] else "UNKNOWN",
                "enabled": user.get("enabled", True),
                "admincount": user.get("admincount", False),
                "description": user.get("description", ""),
            },
            "PrimaryGroupSID": "S-1-5-21-0-0-0-513",
            "AllowedToDelegate": [],
            "SPNTargets": [],
        }
        data["data"].append(user_obj)

    return json.dumps(data, indent=2)


def generate_bloodhound_computers_json(computers: list[dict] | None = None) -> str:
    """Generate BloodHound computers JSON."""
    if computers is None:
        computers = [
            {
                "name": "DC01.CORP.LOCAL",
                "operatingsystem": "Windows Server 2019",
                "unconstraineddelegation": True,
            }
        ]

    data = {
        "meta": {"count": len(computers), "type": "computers", "version": 5},
        "data": [],
    }

    for comp in computers:
        comp_obj = {
            "ObjectIdentifier": f"S-1-5-21-{hash(comp['name']) % 1000000000}",
            "Properties": {
                "name": comp["name"],
                "domain": comp["name"].split(".")[1] if "." in comp["name"] else "UNKNOWN",
                "operatingsystem": comp.get("operatingsystem", "Unknown"),
                "unconstraineddelegation": comp.get("unconstraineddelegation", False),
                "enabled": comp.get("enabled", True),
            },
            "AllowedToDelegate": [],
            "AllowedToAct": [],
        }
        data["data"].append(comp_obj)

    return json.dumps(data, indent=2)


# =============================================================================
# CrackMapExec Output Generators
# =============================================================================


def generate_cme_json(results: list[dict] | None = None) -> str:
    """Generate CrackMapExec JSON output."""
    if results is None:
        results = [
            {
                "host": "192.168.1.100",
                "hostname": "DC01",
                "domain": "CORP.LOCAL",
                "signing": False,
                "smbv1": True,
            }
        ]

    output = []
    for result in results:
        output.append({
            "host": result.get("host", "127.0.0.1"),
            "hostname": result.get("hostname", "UNKNOWN"),
            "domain": result.get("domain", ""),
            "os": result.get("os", "Windows"),
            "signing": result.get("signing", True),
            "smbv1": result.get("smbv1", False),
            "shares": result.get("shares", []),
        })

    return json.dumps(output, indent=2)


# =============================================================================
# Impacket Output Generators
# =============================================================================


def generate_secretsdump_output(
    sam_hashes: list[dict] | None = None,
    lsa_secrets: list[dict] | None = None,
    domain_hashes: list[dict] | None = None,
) -> str:
    """Generate Impacket secretsdump output."""
    lines = ["[*] Service RemoteRegistry is in stopped state"]
    lines.append("[*] Starting service RemoteRegistry")
    lines.append("[*] Target system bootKey: 0x" + "a" * 32)
    lines.append("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)")

    if sam_hashes is None:
        sam_hashes = [
            {"user": "Administrator", "rid": "500", "lm": "aad3b435b51404eeaad3b435b51404ee", "nt": "31d6cfe0d16ae931b73c59d7e0c089c0"},
            {"user": "Guest", "rid": "501", "lm": "aad3b435b51404eeaad3b435b51404ee", "nt": "31d6cfe0d16ae931b73c59d7e0c089c0"},
        ]

    for h in sam_hashes:
        lines.append(f"{h['user']}:{h['rid']}:{h['lm']}:{h['nt']}:::")

    if lsa_secrets:
        lines.append("[*] Dumping LSA Secrets")
        for secret in lsa_secrets:
            lines.append(f"[*] {secret['name']}")
            lines.append(f"    {secret['value']}")

    if domain_hashes:
        lines.append("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)")
        for h in domain_hashes:
            domain = h.get("domain", "CORP")
            lines.append(f"{domain}\\{h['user']}:{h['rid']}:{h['lm']}:{h['nt']}:::")

    lines.append("[*] Cleaning up...")
    lines.append("[*] Stopping service RemoteRegistry")

    return "\n".join(lines)


def generate_kerberoasting_output(tickets: list[dict] | None = None) -> str:
    """Generate Impacket GetUserSPNs output."""
    lines = ["Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation"]
    lines.append("")
    lines.append("ServicePrincipalName                     Name         MemberOf                    PasswordLastSet             LastLogon                   Delegation")
    lines.append("-----------------------------------------  -----------  --------------------------  --------------------------  --------------------------  ----------")

    if tickets is None:
        tickets = [
            {
                "spn": "MSSQLSvc/sql01.corp.local:1433",
                "user": "svc_sql",
                "memberof": "CN=Domain Users,CN=Users,DC=corp,DC=local",
                "hash": "$krb5tgs$23$*svc_sql$CORP.LOCAL$...",
            }
        ]

    for ticket in tickets:
        lines.append(
            f"{ticket['spn']:<40} {ticket['user']:<12} {ticket.get('memberof', ''):<27} "
            f"2023-01-01 00:00:00  2023-06-01 00:00:00  "
        )

    lines.append("")
    for ticket in tickets:
        lines.append(ticket.get("hash", "$krb5tgs$23$*user$DOMAIN$hash"))

    return "\n".join(lines)


# =============================================================================
# Mimikatz Output Generators
# =============================================================================


def generate_mimikatz_logonpasswords(credentials: list[dict] | None = None) -> str:
    """Generate Mimikatz sekurlsa::logonpasswords output."""
    lines = [
        "mimikatz # sekurlsa::logonpasswords",
        "",
        "Authentication Id : 0 ; 999 (00000000:000003e7)",
        "Session           : UndefinedLogonType from 0",
        "User Name         : SYSTEM",
        "Domain            : NT AUTHORITY",
        "Logon Server      : (null)",
        "Logon Time        : 1/1/2024 12:00:00 AM",
        "SID               : S-1-5-18",
        "",
    ]

    if credentials is None:
        credentials = [
            {
                "user": "Administrator",
                "domain": "CORP",
                "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "password": "Password123!",
            }
        ]

    for cred in credentials:
        lines.extend([
            f"Authentication Id : 0 ; {hash(cred['user']) % 1000000}",
            "Session           : Interactive from 1",
            f"User Name         : {cred['user']}",
            f"Domain            : {cred.get('domain', 'WORKGROUP')}",
            f"Logon Server      : {cred.get('logon_server', 'DC01')}",
            "Logon Time        : 1/1/2024 12:00:00 AM",
            f"SID               : S-1-5-21-0-0-0-{hash(cred['user']) % 10000}",
            "	msv :",
            "	 [00000003] Primary",
            f"	 * Username : {cred['user']}",
            f"	 * Domain   : {cred.get('domain', 'WORKGROUP')}",
            f"	 * NTLM     : {cred.get('ntlm', '')}",
            f"	 * SHA1     : {cred.get('sha1', '')}",
        ])
        if cred.get("password"):
            lines.append(f"	 * Password : {cred['password']}")
        lines.extend(["	tspkg :", "	wdigest :", "	kerberos :", ""])

    return "\n".join(lines)


# =============================================================================
# Nessus Output Generators
# =============================================================================


def generate_nessus_xml(
    hosts: list[dict] | None = None,
    policy_name: str = "Basic Network Scan",
) -> str:
    """Generate Nessus XML output."""
    if hosts is None:
        hosts = [
            {
                "ip": "192.168.1.100",
                "hostname": "dc01.corp.local",
                "vulns": [
                    {
                        "plugin_id": "10396",
                        "name": "Microsoft Windows SMB Shares Unprivileged Access",
                        "severity": "3",
                        "description": "SMB shares are accessible",
                    }
                ],
            }
        ]

    root = ET.Element("NessusClientData_v2")
    policy = ET.SubElement(root, "Policy")
    ET.SubElement(policy, "policyName").text = policy_name

    report = ET.SubElement(root, "Report", name="Scan Results")

    for host_data in hosts:
        host = ET.SubElement(report, "ReportHost", name=host_data["ip"])
        props = ET.SubElement(host, "HostProperties")
        ET.SubElement(props, "tag", name="host-ip").text = host_data["ip"]
        if "hostname" in host_data:
            ET.SubElement(props, "tag", name="hostname").text = host_data["hostname"]

        for vuln in host_data.get("vulns", []):
            item = ET.SubElement(
                host, "ReportItem",
                port="0",
                svc_name="general",
                protocol="tcp",
                severity=str(vuln.get("severity", "0")),
                pluginID=str(vuln.get("plugin_id", "0")),
                pluginName=vuln.get("name", "Unknown"),
            )
            if "description" in vuln:
                ET.SubElement(item, "description").text = vuln["description"]
            if "solution" in vuln:
                ET.SubElement(item, "solution").text = vuln["solution"]
            if "cvss_score" in vuln:
                ET.SubElement(item, "cvss_base_score").text = str(vuln["cvss_score"])
            if "cve" in vuln:
                ET.SubElement(item, "cve").text = vuln["cve"]

    return ET.tostring(root, encoding="unicode")


# =============================================================================
# Metasploit Output Generators
# =============================================================================


def generate_metasploit_xml(
    hosts: list[dict] | None = None,
    workspace: str = "default",
) -> str:
    """Generate Metasploit workspace XML export."""
    if hosts is None:
        hosts = [
            {
                "address": "192.168.1.100",
                "name": "dc01",
                "os_name": "Windows",
                "services": [{"port": 445, "proto": "tcp", "name": "smb"}],
                "vulns": [{"name": "MS17-010", "refs": ["CVE-2017-0144"]}],
            }
        ]

    root = ET.Element("MetasploitV5")
    ET.SubElement(root, "generated", time=datetime.utcnow().isoformat())
    ws = ET.SubElement(root, "workspace", name=workspace)

    hosts_elem = ET.SubElement(ws, "hosts")
    for host_data in hosts:
        host = ET.SubElement(hosts_elem, "host")
        ET.SubElement(host, "address").text = host_data["address"]
        if "name" in host_data:
            ET.SubElement(host, "name").text = host_data["name"]
        if "os_name" in host_data:
            ET.SubElement(host, "os-name").text = host_data["os_name"]

        services = ET.SubElement(host, "services")
        for svc in host_data.get("services", []):
            service = ET.SubElement(services, "service")
            ET.SubElement(service, "port").text = str(svc["port"])
            ET.SubElement(service, "proto").text = svc.get("proto", "tcp")
            ET.SubElement(service, "name").text = svc.get("name", "unknown")

        vulns = ET.SubElement(host, "vulns")
        for v in host_data.get("vulns", []):
            vuln = ET.SubElement(vulns, "vuln")
            ET.SubElement(vuln, "name").text = v["name"]
            refs = ET.SubElement(vuln, "refs")
            for ref in v.get("refs", []):
                ET.SubElement(refs, "ref").text = ref

    return ET.tostring(root, encoding="unicode")


# =============================================================================
# Responder Output Generators
# =============================================================================


def generate_responder_log(hashes: list[dict] | None = None) -> str:
    """Generate Responder captured hash log."""
    if hashes is None:
        hashes = [
            {
                "type": "NTLMv2",
                "client": "192.168.1.50",
                "user": "jsmith",
                "domain": "CORP",
                "hash": "jsmith::CORP:1122334455667788:AABBCCDD...:0101000000000000...",
            }
        ]

    lines = ["[*] [LLMNR] Poisoned answer sent to 192.168.1.50 for name SERVER01"]

    for h in hashes:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"[{h['type']}] {h['type']} Client   : {h['client']}")
        lines.append(f"[{h['type']}] {h['type']} Username : {h.get('domain', '')}\\{h['user']}")
        lines.append(f"[{h['type']}] {h['type']} Hash     : {h['hash']}")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# C2 Framework Output Generators
# =============================================================================


def generate_cobaltstrike_beacon_log(
    events: list[dict] | None = None,
    beacon_id: str = "12345678",
) -> str:
    """Generate Cobalt Strike beacon log."""
    if events is None:
        events = [
            {"type": "checkin", "user": "CORP\\jsmith", "computer": "WS01", "ip": "192.168.1.50"},
            {"type": "task", "command": "shell whoami", "output": "corp\\jsmith"},
        ]

    lines = [f"[*] Beacon {beacon_id}"]

    for event in events:
        ts = datetime.utcnow().strftime("%m/%d %H:%M:%S")
        if event["type"] == "checkin":
            lines.append(f"[{ts}] metadata: {event.get('user', 'unknown')} @ {event.get('computer', 'unknown')}")
            lines.append(f"[{ts}] internal IP: {event.get('ip', '0.0.0.0')}")
        elif event["type"] == "task":
            lines.append(f"[{ts}] [{beacon_id}] Tasked beacon to {event.get('command', '')}")
            if "output" in event:
                lines.append(f"[{ts}] [{beacon_id}] received output:")
                lines.append(event["output"])

    return "\n".join(lines)


def generate_sliver_implant_json(implants: list[dict] | None = None) -> str:
    """Generate Sliver implant session JSON."""
    if implants is None:
        implants = [
            {
                "id": "abc12345",
                "name": "BRIGHT_NEEDLE",
                "hostname": "WS01",
                "username": "jsmith",
                "os": "windows",
                "remote_address": "192.168.1.50:443",
            }
        ]

    return json.dumps({"implants": implants}, indent=2)


# =============================================================================
# Utility Functions
# =============================================================================


def write_fixture(path: str, content: str) -> None:
    """Write content to a fixture file."""
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
