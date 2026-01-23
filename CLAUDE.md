# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run CLI
ariadne --help
ariadne analyze ./data/ --output report.html
ariadne parsers list
ariadne web --port 8443

# Lint
ruff check src/
ruff format src/

# Type check
mypy src/ariadne/

# Run all tests
pytest

# Run single test file
pytest tests/test_parsers/test_nmap.py

# Run single test
pytest tests/test_parsers/test_nmap.py::TestNmapParser::test_parse_simple_host -v

# Validate sample data without full analysis
ariadne analyze tests/fixtures/sample_data/ --dry-run
```

## Architecture

Ariadne synthesizes attack paths from security tool output using this pipeline:

```
Input Files → Parsers → Entities → Graph Builder → NetworkX Graph → Path Finding → LLM Enrichment → Scored Attack Paths
```

### Core Data Flow

1. **Parsers** (`src/ariadne/parsers/`) - Plugin system that normalizes tool output into unified entities
2. **Models** (`src/ariadne/models/`) - Pydantic models: `Host`, `Service`, `User`, `CloudResource`, `Vulnerability`, `Misconfiguration`, `Credential`, `Relationship`
3. **Graph** (`src/ariadne/graph/`) - NetworkX-based knowledge graph with attack-relevant edge types
4. **Engine** (`src/ariadne/engine/synthesizer.py`) - Orchestrates: parse → build graph → find paths → LLM enrich → score
5. **LLM** (`src/ariadne/llm/`) - LiteLLM wrapper supporting OpenAI, Anthropic, Ollama, LM Studio

### Adding a Parser

Parsers auto-register via `@register_parser` decorator:

```python
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser

@register_parser
class MyParser(BaseParser):
    name = "myparser"
    description = "Parse MyTool output"
    file_patterns = ["*.mytool.json"]
    entity_types = ["Host", "Vulnerability"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        # Yield Host, Service, Vulnerability, Relationship, etc.
        yield Host(ip="192.168.1.1", hostname="server")

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        # Optional: content sniffing for ambiguous file types
        return file_path.suffix == ".json"
```

Parsers are discovered via:
- `@register_parser` decorator
- Entry points in `pyproject.toml` (`[project.entry-points."ariadne.parsers"]`)

### Entity Types

Assets: `Host`, `Service`, `User`, `CloudResource`
Findings: `Vulnerability`, `Misconfiguration`, `Credential`
Edges: `Relationship` with `RelationType` enum (e.g., `CAN_RDP`, `ADMIN_TO`, `HAS_GENERIC_ALL`)

### Attack Path Scoring

`PathScorer` in `src/ariadne/engine/scoring.py` calculates probability based on weighted factors:
- CVSS scores of vulnerabilities
- Exploit availability
- Network position (external entry points score higher)
- Privilege requirements
- Path length penalty

### Web API

FastAPI app in `src/ariadne/web/app.py`:
- `POST /api/ingest/upload` - Upload files, returns session_id
- `POST /api/graph/build` - Build graph from session
- `POST /api/analysis/synthesize` - Generate attack paths
- `GET /api/graph/{session}/visualization` - Cytoscape.js format

### Configuration

`config.yaml` or `AriadneConfig` Pydantic model. Key settings:
- `llm.provider` / `llm.model` - LLM backend (uses LiteLLM format: `anthropic/claude-3-sonnet`)
- `scoring.weights` - Attack path probability weights
- `parsers.enabled` - List of active parsers

## Implemented Parsers (45 total)

### Network/Infrastructure
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `nmap` | Nmap | `*.xml`, `nmap_*.xml` | Port scans, service detection, NSE scripts |
| `masscan` | Masscan | `*masscan*.json`, `*masscan*.xml` | Fast port scanning |
| `rustscan` | RustScan | `*rustscan*.json`, `*rustscan*.txt` | Fast Rust-based port scanning |
| `nessus` | Nessus/Tenable | `*.nessus`, `nessus_*.xml` | Enterprise vulnerability scanning |
| `testssl` | TestSSL.sh | `*testssl*.json` | TLS/SSL configuration analysis |
| `openvas` | OpenVAS/GVM | `*openvas*.xml`, `*gvm*.xml` | Open-source vulnerability scanning |
| `qualys` | Qualys | `*qualys*.xml`, `*qualys*.csv` | Enterprise vulnerability scanner |
| `shodan` | Shodan | `*shodan*.json` | Internet-wide scan data |
| `censys` | Censys | `*censys*.json` | Internet scan search results |

### Active Directory - Enumeration
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `bloodhound` | BloodHound/SharpHound | `*bloodhound*.json`, `*users.json` | AD relationships, attack paths |
| `crackmapexec` | CrackMapExec/NetExec | `*cme*.json`, `*nxc*.json` | SMB/WinRM/LDAP enumeration |
| `certipy` | Certipy | `*certipy*.json`, `*adcs*.json` | AD Certificate Services vulnerabilities (ESC1-11) |
| `pingcastle` | PingCastle | `*pingcastle*.xml`, `ad_hc_*.xml` | AD security assessment |
| `ldapdomaindump` | LDAPDomainDump | `domain_users*.json`, `domain_computers*.json` | AD LDAP enumeration |
| `enum4linux` | Enum4linux | `*enum4linux*.txt` | SMB/NetBIOS enumeration |
| `smbmap` | SMBMap | `*smbmap*.txt`, `*smbmap*.json` | SMB share enumeration |
| `adrecon` | ADRecon | `*ADRecon*.csv`, `*-Users.csv`, `*-Computers.csv` | AD enumeration reports (CSV/Excel) |
| `plumhound` | PlumHound | `*plumhound*.csv`, `*plumhound*.json` | BloodHound automated query results |
| `grouper2` | Grouper2 | `*grouper2*.json`, `*gpo_audit*.json` | GPO vulnerability analysis |
| `windapsearch` | windapsearch | `*windapsearch*.txt`, `*windapsearch*.json` | LDAP enumeration (users, groups, computers) |
| `ldeep` | ldeep | `*ldeep*.json`, `*ldeep*.txt` | LDAP deep enumeration (delegation, trusts, gMSA, LAPS) |
| `rpcclient` | rpcclient | `*rpcclient*.txt`, `*rpc_enum*.txt` | RPC/SMB enumeration (users, groups, password policy) |

### Active Directory - Attacks & Credentials
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `impacket` | Impacket tools | `*secretsdump*.txt`, `*getuserspns*.txt` | Credential dumping, Kerberoasting, AS-REP roasting |
| `rubeus` | Rubeus | `*rubeus*.txt`, `*kerberoast*.txt` | Kerberos attacks (AS-REP, TGS, tickets, delegation) |
| `mimikatz` | Mimikatz | `*mimikatz*.txt`, `*sekurlsa*.txt` | Credential extraction (LSASS, SAM, DCSync, DPAPI) |
| `kerbrute` | Kerbrute | `*kerbrute*.txt` | Kerberos user enum and password spraying |
| `responder` | Responder | `*Responder*.txt`, `*NTLM*.txt` | LLMNR/NBT-NS poisoning captured hashes |
| `ntlmrelayx` | ntlmrelayx | `*ntlmrelayx*.log`, `*relay*.log` | NTLM relay attack logs and dumped creds |
| `mitm6` | mitm6 | `*mitm6*.txt`, `*mitm6*.log` | IPv6 DNS takeover, DHCPv6 spoofing, WPAD attacks |
| `snaffler` | Snaffler | `*snaffler*.txt`, `*snaffler*.json` | File share secret hunting |

### Cloud
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `azurehound` | AzureHound | `*azurehound*.json`, `*azure_*.json` | Azure AD enumeration (users, groups, apps, roles) |

### Exploitation Frameworks
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `metasploit` | Metasploit | `*metasploit*.xml`, `*msf*.json` | Workspace exports (hosts, services, vulns, creds) |

### Web Application
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `nuclei` | Nuclei | `*nuclei*.json` | Template-based vulnerability scanning |

### C2 Frameworks
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `cobaltstrike` | Cobalt Strike | `*beacon*.log`, `*cobaltstrike*.json` | Beacon logs, team server exports, credential harvesting |
| `sliver` | Sliver | `*sliver*.json`, `*implant*.json` | Implant sessions, pivots, credential capture |
| `havoc` | Havoc | `*havoc*.json`, `*demon*.log` | Demon sessions, operator commands, mimikatz output |
| `mythic` | Mythic | `*mythic*.json`, `*callback*.json` | Callbacks, tasks, credential harvesting |

### Windows Post-Exploitation
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `seatbelt` | Seatbelt | `*seatbelt*.txt`, `*seatbelt*.json` | Host enumeration, security checks, credentials |
| `sharpup` | SharpUp | `*sharpup*.txt`, `*privesc*.txt` | Privilege escalation checks (services, registry, paths) |
| `watson` | Watson | `*watson*.txt` | Missing Windows patches for privilege escalation |
| `powerview` | PowerView/SharpView | `*powerview*.txt`, `*Get-Domain*.txt` | AD enumeration (users, computers, ACLs, sessions) |

### Recon/OSINT
| Parser | Tool | File Patterns | Description |
|--------|------|---------------|-------------|
| `amass` | Amass | `*amass*.json`, `*amass*.txt` | Subdomain enumeration, DNS discovery |
| `subfinder` | Subfinder | `*subfinder*.json`, `*subdomains*.txt` | Subdomain discovery |
| `httpx` | httpx | `*httpx*.json` | HTTP probing, technology detection, headers |
| `eyewitness` | EyeWitness | `*eyewitness*.xml`, `*eyewitness*.json` | Web screenshots, service categorization |

## Future Parsers (TODO) - Red Team Focus

### Cloud Exploitation
- [ ] **pacu** - AWS exploitation framework findings
- [ ] **roadtools** - ROADtools Azure AD enumeration
- [ ] **scoutsuite** - Scout Suite multi-cloud security auditing
