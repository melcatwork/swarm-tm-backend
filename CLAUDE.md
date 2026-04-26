# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

# Swarm TM Backend (Unified with VulnKillChain)

Python FastAPI + CrewAI multi-agent threat modeling engine with integrated CVE intelligence.

**Repository**: https://github.com/redcountryroad/swarm-tm-backend (split from monorepo 2026-04-23)  
**Frontend**: https://github.com/redcountryroad/swarm-tm-frontend

## Project Structure

Unified backend repository:
- `app/` — FastAPI application, routers, parsers, swarm orchestration
  - `routers/vulnkillchain.py` — **NEW**: CVE intelligence endpoints
- `data/` — SQLite DB, STIX cache, persona YAML
- `samples/` — Test IaC files for threat modeling
- `tests/` — Backend tests

## Commands

```bash
# Backend development
source venv/bin/activate
uvicorn app.main:app --reload --port 8000       # start API server
python -m pytest tests/ -v                       # run tests
python -m pytest tests/test_parsers.py -v        # run specific test file

# Docker deployment
docker-compose up -d                             # start backend service
docker-compose logs -f                           # view logs
docker-compose down                              # stop service

# Quick verification
curl http://localhost:8000/api/health              # Backend health check
curl http://localhost:8000/api/llm/status          # LLM provider status
curl http://localhost:8000/api/llm/models          # Available models
```

## LLM Provider

Supports 3 LLM backends configured via `.env` → `LLM_PROVIDER`:
- `ollama` — local, no API key needed. Ensure `ollama serve` is running.
- `bedrock` — AWS Bedrock via bearer token. Uses `AWS_BEARER_TOKEN_BEDROCK`.
- `anthropic` — direct Anthropic API. Uses `ANTHROPIC_API_KEY`.

All agent LLM instances MUST use the `get_llm()` helper in `app/swarm/crews.py`. Never hardcode a model name or provider in any agent definition.

## Code Style

- Python: type hints on all function signatures. Pydantic models for all data structures. Docstrings on public functions and classes.
- No `print()` in Python — use `logging` module with appropriate levels (INFO, WARNING, ERROR).
- API responses always return JSON with a `status` field.

## Security Rules — NEVER violate these

1. **No secrets in code.** API keys, tokens, passwords, and private keys go in `.env` only. Never hardcode, log, or commit them.
2. **No secret logging.** Never log request bodies containing credentials, secret ARNs, or API keys. Sanitise before logging.
3. **Validate all file uploads.** Reject files >1MB. Only accept `.tf`, `.yaml`, `.yml`, `.json` extensions. Validate content structure before parsing.
4. **No `eval()` or `exec()` on user input.** IaC files are parsed by python-hcl2 or PyYAML safe_load — never executed.
5. **No shell commands from user input.** CrewAI agents must not have Code Interpreter enabled.
6. **Pin dependency versions.** When adding packages, pin to a specific range in requirements.txt.
7. **Sanitise LLM output before rendering.** Attack path JSON from agents may contain injection attempts. Validate against Pydantic models.
8. **CORS is restricted.** Set `CORS_ORIGINS` in .env to allow frontend domain. Default: `http://localhost:5173,http://localhost:3000`.

## Architecture Decisions

- **CrewAI** orchestrates the 3-layer swarm (exploration → evaluation → adversarial). Do not replace with LangGraph or raw API calls.
- **Modular threat intel** uses adapter pattern in `app/threat_intel/adapters/`. To add a source: create adapter implementing `BaseAdapter`, add entry to `config/sources.yaml`.
- **Persona registry** at `app/swarm/agents/persona_registry.py`. Default personas are `protected: true` and cannot be deleted, only disabled.
- **Kill chain output** — all attack paths follow 3-5 step kill chain format with ATT&CK technique IDs. See `app/swarm/models.py` for schema.
- **Asset graph is cloud-agnostic** — parsers normalise to common schema (`app/parsers/models.py`). Swarm layer never sees raw Terraform/CloudFormation.

## Development Workflow

### When Adding New Features

1. **Update routers**: `app/routers/swarm.py` and/or `app/swarm/crews.py`
2. **Test with sample file**: Use `samples/clouddocs-saas-app.tf` or similar
3. **Verify attack path structure**: Ensure all required fields present (technique_id, target_asset, mitigations)
4. **Check backend logs**: Confirm feature working as intended
5. **Update OpenAPI schema**: Ensure `/openapi.json` reflects new parameters

### When Fixing Bugs

1. **Document root cause**: Explain why the bug occurred
2. **Document solution**: Explain the fix and why it works
3. **Identify affected files**: List all files modified with line numbers
4. **Test verification**: Run scenario that previously failed

## Known Limitations

1. **Long execution times**: Full pipeline takes 25-30 minutes, quick run ~14 minutes. This is inherent to LLM-based multi-agent systems.
2. **LLM output variability**: Even with structured prompts, LLMs occasionally return inconsistent JSON keys. Fallback mechanism mitigates data loss.
3. **AWS-focused mitigations**: Recommendations tailored for AWS. GCP/Azure equivalents not yet implemented.

## Frontend Integration

This backend is designed to work with the Swarm TM frontend:
- Repository: https://github.com/redcountryroad/swarm-tm-frontend
- Set CORS_ORIGINS in .env to allow frontend domain
- Frontend expects backend at http://localhost:8000 by default

## CVE Intelligence Endpoints (NEW)

Unified backend now includes CVE intelligence capabilities under `/api/cve/*` prefix:

### Endpoints

```bash
# Health check
curl http://localhost:8000/api/cve/health

# Search CVEs by product
curl "http://localhost:8000/api/cve/search?product=log4j&limit=10"

# Get CVE details
curl http://localhost:8000/api/cve/CVE-2021-44228

# Get MITRE ATT&CK kill chain mapping
curl http://localhost:8000/api/cve/attack/CVE-2021-44228

# Get CISA Known Exploited Vulnerabilities
curl "http://localhost:8000/api/cve/cisa-kev/list?limit=20"

# Get EPSS score
curl http://localhost:8000/api/cve/epss/CVE-2021-44228
```

### Implementation Details

**Router**: `app/routers/vulnkillchain.py`

**Key Features**:
- 80+ hardcoded CVE-to-MITRE ATT&CK technique mappings
- 120+ keyword patterns for inferring techniques from CVE descriptions
- 196+ base techniques + 100+ sub-techniques mapped to 14 MITRE tactics
- Mermaid flowchart generation for kill chain visualization
- Vulnerability intelligence extraction (patches, mitigations, detection, recovery)

**Data Sources**:
- NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
- CISA KEV (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- EPSS API (https://api.first.org/data/v1/epss)

**Rate Limits**:
- NVD API: ~5 requests per 30 seconds without API key
- Set `NVD_API_KEY` in .env for higher rate limits

### Adding New CVE Mappings

To add hardcoded ATT&CK mappings for specific CVEs, edit `CVE_ATTACK_MAPPING` dict in `app/routers/vulnkillchain.py`:

```python
CVE_ATTACK_MAPPING = {
    "CVE-YYYY-NNNNN": ["T1234", "T5678.001"],  # Base or sub-techniques
}
```

Verify technique exists in `technique_to_tactic()` function, or add new mapping.
