# Ariadne

Takes findings from security tools, builds a graph of how they connect, and produces ranked attack paths with MITRE ATT&CK mappings. Optionally generates operator playbooks with tool commands, OPSEC notes, and detection signatures for each path.

## Inputs

Scanners: Nessus, OpenVAS, Qualys, Nuclei, Nmap, Masscan, RustScan, TestSSL, Shodan, Censys

Active Directory (enum): BloodHound, CrackMapExec/NetExec, Certipy, PingCastle, LDAPDomainDump, ADRecon, PlumHound, Grouper2, Enum4linux, SMBMap, windapsearch, ldeep, rpcclient

Active Directory (attack): Impacket, Rubeus, Mimikatz, Kerbrute, Responder, ntlmrelayx, mitm6, Snaffler

C2: Cobalt Strike, Sliver, Havoc, Mythic

Post-exploitation: Seatbelt, SharpUp, Watson, PowerView/SharpView

Recon: Amass, Subfinder, httpx, EyeWitness

Cloud: AzureHound, Metasploit

Correlation: Vinculum (deduplicated, EPSS-enriched findings)

## Install

```bash
git clone https://github.com/Su1ph3r/ariadne.git && cd ariadne
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Or with Docker:

```bash
docker-compose up -d
```

## Usage

```bash
# Ingest scan data and validate files
ariadne analyze ./scan_data/ --dry-run

# Run full analysis with HTML report
ariadne analyze ./scan_data/ --output report --format html

# Enable all features: playbooks, credential sprawl, privesc chaining
ariadne analyze ./scan_data/ --output report --format html --playbook --sprawl --privesc

# Export to JSON
ariadne analyze ./scan_data/ --output results --format json

# Start the web UI
ariadne web --port 8443
```

API:

```bash
# Upload findings
curl -X POST http://localhost:8443/api/ingest/upload \
  -F "files=@nmap_scan.xml" -F "files=@bloodhound_users.json"

# Build graph and generate attack paths
curl -X POST http://localhost:8443/api/analysis/synthesize \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID"}'
```

## What it produces

- **Attack paths**: Ranked chains from initial access to high-value targets, scored by CVSS, exploit availability, network position, and detection likelihood.
- **Knowledge graph**: Unified graph of hosts, services, users, vulnerabilities, and their relationships. Exportable as GraphML or Neo4j Cypher.
- **Operator playbooks**: Step-by-step commands (Impacket, CrackMapExec, Certipy, etc.) with prerequisites, OPSEC notes, fallbacks, and detection signatures.
- **MITRE ATT&CK mappings**: Automatic technique IDs on every attack step and privilege escalation vector.
- **Credential sprawl maps**: Detects credential reuse across hosts and models the blast radius as lateral movement edges in the graph.

## Configuration

```yaml
# config.yaml
llm:
  provider: anthropic       # or openai, ollama, lm_studio
  model: claude-sonnet-4-20250514
  api_key: ${ANTHROPIC_API_KEY}
scoring:
  weights:
    cvss: 0.3
    exploit_available: 0.25
    network_position: 0.2
    privilege_required: 0.15
    detection_likelihood: 0.1
  max_path_length: 10
output:
  default_format: html
  max_paths: 20
sprawl:
  enabled: false
  min_reuse_count: 2
privesc:
  enabled: false
  min_confidence: 0.5
web:
  host: 127.0.0.1
  port: 8443
```

Environment variables use the `ARIADNE_` prefix with double-underscore nesting (e.g., `ARIADNE_LLM__PROVIDER=anthropic`).

## Testing

```bash
pytest
pytest --cov=ariadne --cov-report=html
ruff check src/ && ruff format --check src/ && mypy src/ariadne/
```

## License

MIT
