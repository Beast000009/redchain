# Contributing to RedChain

Thank you for your interest in contributing to RedChain! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/redchain.git
cd redchain

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install ruff mypy pytest

# Install external tools
python3 cli.py update
```

## Project Structure

```
redchain/
├── cli.py                  # Main entry point (Typer CLI)
├── config.py               # Configuration management
├── utils.py                # Shared utilities & platform detection
├── models.py               # Pydantic data models
├── agents/                 # Pipeline agent modules
│   ├── osint_agent.py      # Phase 1: OSINT
│   ├── subdomain_agent.py  # Phase 2: Subdomain enumeration
│   ├── webapp_agent.py     # Phase 3: Web app fingerprinting
│   ├── scanner_agent.py    # Phase 4: Vulnerability scanning
│   ├── cve_agent.py        # Phase 5: CVE matching
│   ├── report_agent.py     # Phase 6: AI report generation
│   └── threat_intel.py     # Advanced OSINT integrations
├── orchestrator/
│   └── graph.py            # LangGraph pipeline orchestrator
├── llm/                    # Multi-LLM adapter layer
│   ├── __init__.py         # Abstract base + factory
│   ├── gemini_adapter.py
│   ├── openai_adapter.py
│   └── ollama_adapter.py
├── i18n/                   # Internationalization
├── plugins/                # Plugin architecture
│   ├── __init__.py         # Plugin base class
│   ├── loader.py           # Auto-discovery
│   └── community/          # Community plugins
├── report/
│   ├── generator.py        # PDF/MD/JSON/CSV generation
│   └── templates/          # HTML report templates
├── tests/                  # Unit tests
├── Dockerfile              # Container support
└── docker-compose.yml
```

## Writing a Plugin

```python
from plugins import RedChainPlugin

class MyPlugin(RedChainPlugin):
    name = "my_scanner"
    description = "Custom scanning module"
    version = "1.0.0"
    phase = "scan"  # osint, scan, exploit, report, post
    
    def run(self, state):
        # Your logic here
        return {"custom_results": [...]}
    
    def get_requirements(self):
        return ["custom-tool"]
```

Save to `~/.redchain/plugins/my_scanner.py` — it will be auto-discovered.

## Running Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Code Style

- Use `ruff` for linting: `ruff check .`
- Follow PEP 8 conventions
- Add type hints to all functions
- Use Pydantic models for structured data

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with tests
4. Run `ruff check .` and `python -m unittest discover -s tests -v`
5. Submit a PR with a clear description

## Adding a New LLM Provider

1. Create `llm/your_adapter.py` extending `LLMAdapter`
2. Implement `generate_report()` and `is_available()`
3. Register in `llm/__init__.py` factory
4. Add API key field to `config.py`
