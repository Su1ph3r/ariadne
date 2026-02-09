# Ariadne

**AI-Powered Attack Path Synthesizer for Penetration Testing and Red Team Operations**

Ariadne ingests output from security tools, builds a knowledge graph of discovered assets and relationships, and uses AI to synthesize realistic attack paths with MITRE ATT&CK technique mappings.

Named after the mythological princess who provided Theseus with the thread to navigate the Labyrinth, Ariadne helps security professionals navigate complex environments by illuminating paths from initial access to high-value targets.

---

## Features

- **Multi-Tool Ingestion**: Parse output from 45+ security tools including Nmap, BloodHound, Nuclei, CrackMapExec, Mimikatz, and more
- **Knowledge Graph**: Build a unified graph of hosts, services, users, vulnerabilities, and their relationships
- **Attack Path Synthesis**: AI-powered identification of viable attack paths through the environment
- **MITRE ATT&CK Mapping**: Automatic technique mapping for each attack step
- **Risk Scoring**: Probability-based scoring considering CVSS, exploit availability, network position, and detection likelihood
- **Operator Playbooks**: Generate executable playbooks with tool commands, OPSEC notes, fallback techniques, and detection signatures for each attack path
- **Multiple Export Formats**: HTML reports, JSON, GraphML, and Neo4j Cypher statements
- **Web Dashboard**: Interactive UI for uploading data and visualizing results
- **REST API**: Full API for integration with other tools and automation

---

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ariadne.git
cd ariadne

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Verify installation
ariadne --version
```

### Using Docker

```bash
# Build the image
docker build -t ariadne .

# Run with docker-compose (recommended)
docker-compose up -d

# Or run directly
docker run -p 8443:8443 -v ./data:/app/data:ro ariadne
```

---

## Quick Start

### Command Line

```bash
# List available parsers
ariadne parsers list

# Analyze scan data (dry run to validate files)
ariadne analyze ./scan_data/ --dry-run

# Full analysis with HTML report
ariadne analyze ./scan_data/ --output report --format html

# Export to JSON
ariadne analyze ./scan_data/ --output results --format json

# Generate operator playbooks alongside attack paths
ariadne analyze ./scan_data/ --output report --format html --playbook
```

### Web Interface

```bash
# Start the web server
ariadne web --port 8443

# Open browser to http://localhost:8443
```

### API Usage

```bash
# Upload files
curl -X POST http://localhost:8443/api/ingest/upload \
  -F "files=@nmap_scan.xml" \
  -F "files=@bloodhound_users.json"

# Build graph and analyze
curl -X POST http://localhost:8443/api/analysis/synthesize \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID"}'
```

---

## Supported Tools

### Network and Infrastructure
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| Nmap | `nmap` | XML |
| Masscan | `masscan` | JSON, XML |
| Nessus | `nessus` | .nessus XML |
| OpenVAS/GVM | `openvas` | XML |
| Qualys | `qualys` | XML, CSV |
| Nuclei | `nuclei` | JSON, JSONL |
| TestSSL | `testssl` | JSON |
| Shodan | `shodan` | JSON |
| Censys | `censys` | JSON |
| RustScan | `rustscan` | JSON, TXT |

### Active Directory Enumeration
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| BloodHound/SharpHound | `bloodhound` | JSON |
| CrackMapExec/NetExec | `crackmapexec` | JSON |
| Certipy | `certipy` | JSON |
| PingCastle | `pingcastle` | XML |
| LDAPDomainDump | `ldapdomaindump` | JSON |
| ADRecon | `adrecon` | CSV |
| PlumHound | `plumhound` | CSV, JSON |
| Grouper2 | `grouper2` | JSON |
| Enum4linux | `enum4linux` | TXT |
| SMBMap | `smbmap` | TXT, JSON |
| windapsearch | `windapsearch` | TXT, JSON |
| ldeep | `ldeep` | JSON, TXT |
| rpcclient | `rpcclient` | TXT |

### Active Directory Attacks
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| Impacket (secretsdump, etc.) | `impacket` | TXT |
| Rubeus | `rubeus` | TXT |
| Mimikatz | `mimikatz` | TXT |
| Kerbrute | `kerbrute` | TXT |
| Responder | `responder` | TXT |
| ntlmrelayx | `ntlmrelayx` | LOG |
| mitm6 | `mitm6` | TXT, LOG |
| Snaffler | `snaffler` | TXT, JSON |

### C2 Frameworks
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| Cobalt Strike | `cobaltstrike` | LOG, JSON |
| Sliver | `sliver` | JSON |
| Havoc | `havoc` | JSON, LOG |
| Mythic | `mythic` | JSON |

### Post-Exploitation
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| Seatbelt | `seatbelt` | TXT, JSON |
| SharpUp | `sharpup` | TXT |
| Watson | `watson` | TXT |
| PowerView/SharpView | `powerview` | TXT |

### Reconnaissance
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| Amass | `amass` | JSON, TXT |
| Subfinder | `subfinder` | JSON, TXT |
| httpx | `httpx` | JSON |
| EyeWitness | `eyewitness` | XML, JSON |

### Cloud
| Tool | Parser Name | Output Formats |
|------|-------------|----------------|
| AzureHound | `azurehound` | JSON |
| Metasploit | `metasploit` | XML, JSON |

---

## Configuration

Ariadne looks for configuration in the following locations (in order):

1. `./config.yaml` (current directory)
2. `~/.ariadne/config.yaml`
3. `~/.config/ariadne/config.yaml`
4. Environment variables with `ARIADNE_` prefix

### Example Configuration

```yaml
# config.yaml
llm:
  provider: anthropic  # or openai, ollama, lm_studio
  model: claude-sonnet-4-20250514
  api_key: ${ANTHROPIC_API_KEY}  # Environment variable substitution
  temperature: 0.7
  max_tokens: 4096

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

web:
  host: 127.0.0.1
  port: 8443
  persistent_sessions: true
  session_ttl_hours: 24
```

### Environment Variables

```bash
# LLM Configuration
export ARIADNE_LLM__PROVIDER=anthropic
export ARIADNE_LLM__API_KEY=sk-...
export ARIADNE_LLM__MODEL=claude-sonnet-4-20250514

# Web Configuration
export ARIADNE_WEB__PORT=9000
export ARIADNE_WEB__PERSISTENT_SESSIONS=true

# Custom home directory
export ARIADNE_HOME=/opt/ariadne
```

---

## Operator Playbooks

Ariadne can generate executable operator playbooks for each discovered attack path. Playbooks transform abstract attack paths into step-by-step instructions with specific tool commands, OPSEC considerations, fallback techniques, and detection signatures.

### Generating Playbooks

```bash
# Add --playbook (-p) to any analyze command
ariadne analyze ./scan_data/ --output report --format html --playbook

# Playbooks are embedded in both HTML and JSON reports
ariadne analyze ./scan_data/ --output results --format json --playbook
```

### What Playbooks Include

Each playbook step contains:

- **Tool Commands**: Executable commands for tools like Impacket, CrackMapExec, Certipy, Evil-WinRM, and more
- **Prerequisites**: What access or tools are needed before execution
- **OPSEC Notes**: Operational security considerations (noise level, log artifacts, detection risk)
- **Fallback Commands**: Alternative approaches if the primary command fails
- **Expected Output**: What successful execution looks like
- **Detection Signatures**: Indicators that defenders might use to detect the activity

### Coverage

Playbooks cover attack techniques across all domains:

| Domain | Techniques |
|--------|-----------|
| **Active Directory** | DCSync, DACL abuse (GenericAll, GenericWrite, WriteDacl, WriteOwner), Kerberoasting, ADCS abuse, LAPS/gMSA reading, forced password change, group membership manipulation |
| **Network** | SSH, RDP, WinRM/PSRemote, SMB lateral movement (PsExec, WmiExec), vulnerability exploitation |
| **Cloud** | AWS STS AssumeRole, Azure role escalation, IAM permission abuse |
| **Sessions** | Pass-the-Hash, credential reuse |

### Two-Tier Generation

1. **Deterministic Templates**: Known `RelationType` values (e.g., `HAS_GENERIC_ALL`, `CAN_SSH`, `CAN_ASSUME`) are mapped to pre-built command templates with proper placeholders for target IPs, domains, usernames, and credentials.

2. **LLM Enhancement** (optional): When an LLM provider is configured, Ariadne can enhance template-generated playbooks with contextual OPSEC notes and fill in commands for novel attack patterns not covered by templates.

### Playbook Configuration

```yaml
# config.yaml
playbook:
  enabled: false             # Enable playbook generation (or use --playbook flag)
  llm_enhance: true          # Use LLM to add OPSEC context and fill gaps
  include_detection_sigs: true  # Include detection signatures in output
  max_fallbacks: 2           # Maximum fallback commands per step
```

### Placeholder Handling

Playbook commands use placeholders like `{target_ip}`, `{domain}`, `{username}`, and `{hash}` that are automatically filled from the knowledge graph. When entity data is unavailable, placeholders remain in the output as-is (e.g., `{target_ip}`) for the operator to fill manually.

---

## Architecture

```
Input Files --> Parsers --> Entities --> Graph Builder --> NetworkX Graph
                                                              |
                                                              v
                                                         Path Finding
                                                              |
                                                              v
                                                      LLM Enrichment
                                                              |
                                                              v
                                                          Scoring
                                                              |
                                              +---------------+---------------+
                                              |                               |
                                              v                               v
                                     Playbook Generator              HTML/JSON Report
                                    (template + LLM)                 (with playbooks)
```

### Core Components

- **Parsers** (`ariadne.parsers`): Plugin-based system that normalizes tool output into unified entity models
- **Models** (`ariadne.models`): Pydantic models for assets (Host, Service, User), findings (Vulnerability, Credential), relationships, and playbooks
- **Graph** (`ariadne.graph`): NetworkX-based knowledge graph with attack-relevant edge types
- **Engine** (`ariadne.engine`): Orchestrates parsing, graph building, path finding, scoring, and playbook generation
- **LLM** (`ariadne.llm`): LiteLLM wrapper supporting multiple providers for AI-powered analysis and playbook enhancement
- **Output** (`ariadne.output`): Report generators for HTML, JSON, and graph formats with integrated playbook sections

---

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest/upload` | Upload scan files |
| GET | `/api/ingest/session/{id}` | Get session info |
| DELETE | `/api/ingest/session/{id}` | Delete session |
| GET | `/api/ingest/parsers` | List available parsers |
| POST | `/api/graph/build` | Build knowledge graph |
| GET | `/api/graph/{session}/stats` | Get graph statistics |
| GET | `/api/graph/{session}/nodes` | Get graph nodes |
| GET | `/api/graph/{session}/edges` | Get graph edges |
| GET | `/api/graph/{session}/visualization` | Get Cytoscape.js format |
| POST | `/api/analysis/synthesize` | Generate attack paths |
| GET | `/api/analysis/{session}/paths` | Get discovered paths |
| GET | `/api/analysis/{session}/export` | Export results |

Full API documentation available at `/docs` when running the web server.

---

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ariadne --cov-report=html

# Run specific test file
pytest tests/test_parsers/test_nmap.py -v

# Run single test
pytest tests/test_parsers/test_nmap.py::TestNmapParser::test_parse_simple_host -v
```

### Code Quality

```bash
# Lint
ruff check src/

# Format
ruff format src/

# Type check
mypy src/ariadne/
```

### Adding a New Parser

1. Create parser file in `src/ariadne/parsers/`:

```python
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser
from ariadne.models.asset import Host, Service

@register_parser
class MyToolParser(BaseParser):
    name = "mytool"
    description = "Parse MyTool output"
    file_patterns = ["*.mytool.json", "*mytool*.json"]
    entity_types = ["Host", "Service", "Vulnerability"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        # Parse file and yield entities
        data = json.loads(file_path.read_text())
        for item in data:
            yield Host(ip=item["ip"], hostname=item.get("hostname"))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        # Content sniffing for ambiguous file types
        if file_path.suffix != ".json":
            return False
        content = file_path.read_bytes()[:1000]
        return b"mytool" in content.lower()
```

2. Import in `src/ariadne/parsers/registry.py`

3. Add tests in `tests/test_parsers/test_mytool.py`

---

## License

MIT License - See LICENSE file for details.

---

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before conducting security assessments.

---

## Acknowledgments

- [NetworkX](https://networkx.org/) for graph operations
- [LiteLLM](https://github.com/BerriAI/litellm) for LLM provider abstraction
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- [Typer](https://typer.tiangolo.com/) for the CLI
- [Pydantic](https://pydantic.dev/) for data validation

---

## Contributing

Contributions are welcome. Please ensure:

1. All tests pass (`pytest`)
2. Code is formatted (`ruff format src/`)
3. No linting errors (`ruff check src/`)
4. Type hints are correct (`mypy src/ariadne/`)
5. New parsers include comprehensive tests
