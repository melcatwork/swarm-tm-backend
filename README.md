# Swarm TM Backend

AI-powered threat modeling engine using CrewAI multi-agent swarm intelligence for automated attack path discovery and evaluation against AWS infrastructure.

**Repository**: https://github.com/redcountryroad/swarm-tm-backend  
**Frontend**: https://github.com/redcountryroad/swarm-tm-frontend  
**Status**: Production Ready ✅

---

## Overview

The Swarm TM backend is a Python FastAPI application that uses CrewAI to orchestrate multiple AI agent personas for threat modeling. It analyzes Infrastructure-as-Code (Terraform/CloudFormation) files and generates realistic attack paths with MITRE ATT&CK technique mapping and AWS-specific mitigations.

### Key Features

- **Multi-Agent Swarm Intelligence**: 13 threat actor personas (APT29, Scattered Spider, Lazarus Group, etc.)
- **4 Pipeline Modes**: Full Swarm, Quick Run, Single Agent, Stigmergic Swarm
- **3-Layer Validation**: Exploration → Evaluation → Adversarial Review
- **Flexible LLM Support**: Ollama (local), AWS Bedrock, Anthropic API
- **MITRE ATT&CK Mapping**: Automatic technique identification for each kill chain step
- **CSA CII Risk Assessment**: 5×5 risk matrix with residual risk calculation
- **Threat Intelligence**: 13 integrated sources (NVD, SecurityWeek, BleepingComputer, etc.)

---

## Quick Start

### Prerequisites

- Python 3.11+
- An LLM provider:
  - **Ollama** (recommended for local development), OR
  - **AWS Bedrock** API key, OR
  - **Anthropic** API key

### Installation

```bash
# Clone repository
git clone https://github.com/redcountryroad/swarm-tm-backend.git
cd swarm-tm-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your LLM provider credentials

# Run server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at `http://localhost:8000`

### Docker Deployment

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Configuration

### Environment Variables

Create a `.env` file with your LLM provider configuration:

#### Option 1: Ollama (Local, Free)

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen3.5:27b
```

**Setup Ollama:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3.5:27b
ollama serve
```

#### Option 2: AWS Bedrock

```bash
LLM_PROVIDER=bedrock
AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
AWS_REGION_NAME=us-east-1
BEDROCK_MODEL=bedrock/anthropic.claude-sonnet-4-20250514-v1:0
```

#### Option 3: Anthropic API

```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

### CORS Configuration

Allow frontend origins (default includes localhost development ports):

```bash
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,https://yourdomain.com
```

### Optional: Threat Intelligence

```bash
# NVD API key for CVE lookups (optional)
NVD_API_KEY=your-nvd-api-key

# GitHub token for GHSA sync (optional)
GITHUB_TOKEN=your-github-token

# Enable/disable CVE lookups (default: true)
ENABLE_CVE_LOOKUP=true
```

---

## API Endpoints

### Health Check

```bash
GET /api/health
# Returns: {"status": "ok", "message": "Swarm TM Backend is running"}
```

### LLM Configuration

```bash
# Get current LLM provider and model
GET /api/llm/status

# List all available models
GET /api/llm/models
```

### Threat Modeling Pipelines

```bash
# Full Swarm (5+ agents, 25-30 min)
POST /api/swarm/run
Content-Type: multipart/form-data
file: <iac-file>
model: qwen3.5:27b  # optional

# Quick Run (2 agents, 14 min)
POST /api/swarm/run/quick
file: <iac-file>
model: qwen3.5:27b  # optional

# Single Agent (1 specific threat actor, 10-15 min)
POST /api/swarm/run/single?agent_name=apt29_cozy_bear
file: <iac-file>
model: qwen3.5:27b  # optional

# Stigmergic Swarm (sequential with shared graph, 20-25 min)
POST /api/swarm/run/stigmergic
file: <iac-file>
execution_order: capability_asc
model: qwen3.5:27b  # optional
```

### Threat Intelligence

```bash
# Get threat intel items
GET /api/intel/items?category=cve&limit=50&source=NVD

# Pull latest threat intel
POST /api/intel/pull

# Get configured sources
GET /api/intel/sources
```

### Interactive API Documentation

Full API documentation with interactive testing available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

---

## Architecture

### Three-Layer Agent Architecture

#### Layer 1: Exploration Swarm
Multiple threat actor personas explore infrastructure:
- APT29 (Cozy Bear), Scattered Spider, Lazarus Group
- Cloud-native Attacker, Opportunistic Attacker, Insider Threat
- Ransomware Operator, Nation-State APT, Hacktivism
- Supply Chain Attacker, Cryptojacking, Data Exfiltration Specialist

Each generates attack paths with:
- Kill chain steps (Initial Access → Execution → Lateral Movement → Objective → Covering Tracks)
- MITRE ATT&CK technique IDs
- Target assets from infrastructure
- Prerequisites, actions, outcomes

#### Layer 2: Evaluation Swarm
Five specialized evaluators score paths (0-10 scale):
- **Feasibility Scorer** (30%): Can this attack realistically be executed?
- **Impact Scorer** (25%): What's the business impact?
- **Detection Scorer** (15%): How stealthy is this attack?
- **Novelty Scorer** (15%): Is this a creative attack vector?
- **Coherence Checker** (15%): Does the chain make logical sense?

**Composite Score** = (F×0.30 + I×0.25 + D×0.15 + N×0.15 + C×0.15)

#### Layer 3: Adversarial Validation
Three agents perform adversarial review:
- **Red Team**: Identifies gaps, proposes additional paths
- **Blue Team**: Validates controls, suggests improvements
- **Arbitrator**: Produces final validated threat model

### Technology Stack

- **FastAPI**: REST API framework
- **CrewAI**: Multi-agent orchestration
- **LiteLLM**: Unified LLM interface
- **python-hcl2**: Terraform parser
- **PyYAML**: CloudFormation parser
- **Pydantic**: Data validation
- **SQLite**: Threat intel cache
- **STIX/TAXII**: MITRE ATT&CK integration

---

## Frontend Integration

This backend is designed to work with the Swarm TM frontend dashboard:

- **Repository**: https://github.com/redcountryroad/swarm-tm-frontend
- **Default Backend URL**: `http://localhost:8000`
- **CORS Configuration**: Set `CORS_ORIGINS` in `.env` to allow frontend domain

### Local Development

```bash
# Terminal 1: Start backend
cd swarm-tm-backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2: Start frontend
cd swarm-tm-frontend
npm run dev
# Frontend will be at http://localhost:5173
```

---

## Development

### Project Structure

```
swarm-tm-backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── parsers/             # IaC parsers (Terraform, CloudFormation)
│   ├── routers/             # API endpoints
│   ├── swarm/               # CrewAI crews and agent personas
│   └── threat_intel/        # Threat intelligence adapters
├── data/                    # SQLite DB, STIX cache, persona YAML
├── samples/                 # Test IaC files
├── tests/                   # Backend tests
├── requirements.txt         # Python dependencies
├── Dockerfile               # Container configuration
└── docker-compose.yml       # Service orchestration
```

### Running Tests

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

### Code Quality

```bash
# Linting
flake8 app/

# Formatting
black app/

# Type checking
mypy app/
```

---

## Deployment

### Railway Deployment

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login and initialize
railway login
railway init

# Set environment variables in Railway dashboard:
# - LLM_PROVIDER
# - ANTHROPIC_API_KEY or AWS_BEARER_TOKEN_BEDROCK
# - Other required variables from .env.example

# Deploy
railway up
```

The `Procfile` is configured for automatic Railway deployment.

### Zeabur Deployment

Zeabur provides one-click deployment with automatic HTTPS and environment variable management.

**📄 Automatic Configuration**: This repository includes `zeabur.yml` which automatically configures deployment settings, environment variables, health checks, and resource limits. Zeabur will use this configuration when you deploy.

#### Option 1: Deploy via GitHub Integration (Recommended)

1. **Push to GitHub** (already done):
   ```
   https://github.com/melcatwork/swarm-tm-backend
   ```

2. **Create New Project on Zeabur**:
   - Go to https://dash.zeabur.com
   - Click "Create Project"
   - Select "Deploy from GitHub"
   - Authorize Zeabur to access your GitHub account
   - Select repository: `melcatwork/swarm-tm-backend`
   - Click "Deploy"

3. **Configure Environment Variables**:
   In Zeabur dashboard → Your Service → Environment Variables, add:
   
   **Required:**
   ```bash
   LLM_PROVIDER=ollama           # or bedrock, anthropic
   OLLAMA_BASE_URL=http://host.docker.internal:11434  # if using Ollama
   OLLAMA_MODEL=qwen3.5:27b
   CORS_ORIGINS=https://your-frontend.zeabur.app,http://localhost:5173
   ```
   
   **For AWS Bedrock:**
   ```bash
   LLM_PROVIDER=bedrock
   AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
   AWS_REGION_NAME=us-east-1
   BEDROCK_MODEL=bedrock/anthropic.claude-sonnet-4-20250514-v1:0
   CORS_ORIGINS=https://your-frontend.zeabur.app
   ```
   
   **For Anthropic API:**
   ```bash
   LLM_PROVIDER=anthropic
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ANTHROPIC_MODEL=claude-sonnet-4-20250514
   CORS_ORIGINS=https://your-frontend.zeabur.app
   ```
   
   **Optional:**
   ```bash
   NVD_API_KEY=your-nvd-api-key
   GITHUB_TOKEN=your-github-token
   ENABLE_CVE_LOOKUP=true
   ```

4. **Verify Deployment**:
   - Zeabur will auto-detect Python and install dependencies
   - Check logs in Zeabur dashboard for any errors
   - Once deployed, Zeabur provides a URL like: `https://swarm-tm-backend-xxx.zeabur.app`
   - Test: `curl https://your-backend-url.zeabur.app/api/health`

5. **Enable Custom Domain** (Optional):
   - Go to Service → Domains
   - Add custom domain: `api.yourdomain.com`
   - Configure DNS CNAME record pointing to Zeabur

#### Option 2: Deploy via Zeabur CLI

```bash
# Install Zeabur CLI
npm i -g @zeabur/cli

# Login to Zeabur
zeabur auth login

# Navigate to backend directory
cd swarm-tm-backend

# Deploy
zeabur deploy

# Set environment variables
zeabur env set LLM_PROVIDER=anthropic
zeabur env set ANTHROPIC_API_KEY=sk-ant-your-key
zeabur env set CORS_ORIGINS=https://your-frontend.zeabur.app
```

#### Important Notes for Zeabur

**1. Ollama on Zeabur:**
- Ollama requires GPU which may not be available on Zeabur's free tier
- **Recommended**: Use Anthropic API or AWS Bedrock for production
- If you need Ollama, consider Railway or self-hosted Docker

**2. CORS Configuration:**
- Update `CORS_ORIGINS` with your deployed frontend URL
- Example: `CORS_ORIGINS=https://swarm-tm-frontend-xxx.zeabur.app`
- Multiple origins: `CORS_ORIGINS=https://frontend.zeabur.app,https://yourdomain.com`

**3. Database Persistence:**
- Zeabur provides persistent storage for SQLite database
- Data survives redeployments
- Volume path: `/app/data` (automatically mounted)

**4. Logs and Monitoring:**
- View logs: Zeabur Dashboard → Service → Logs
- Monitor resource usage: Dashboard → Metrics
- Set up alerts for errors or high CPU usage

**5. Automatic Redeployment:**
- Push to GitHub triggers automatic redeployment
- Zero-downtime deployments with health checks
- Rollback available in dashboard if issues occur

#### Troubleshooting Zeabur Deployment

**Build Fails:**
- Check logs in Zeabur dashboard
- Verify `requirements.txt` has all dependencies
- Ensure Python version compatible (3.11+)

**Backend Unreachable:**
- Verify service is running (check status in dashboard)
- Test health endpoint: `curl https://your-url.zeabur.app/api/health`
- Check environment variables are set correctly

**LLM Provider Errors:**
- Verify API keys are correct in environment variables
- Check LLM_PROVIDER matches your configuration
- Test locally first: `uvicorn app.main:app --reload`

---

## Troubleshooting

### Backend Won't Start

**Issue**: `ERROR: [Errno 48] Address already in use`

**Solution**:
```bash
lsof -ti :8000 | xargs kill -9
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Issue**: `LLM is not properly configured`

**Solution**: Check `.env` file has correct LLM provider credentials
```bash
# Verify Ollama is running
curl http://localhost:11434/api/tags

# Check LLM status
curl http://localhost:8000/api/llm/status
```

### Frontend Can't Connect

**Issue**: CORS errors in browser console

**Solution**: Add frontend origin to CORS_ORIGINS in `.env`:
```bash
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run tests: `pytest tests/ -v`
5. Submit a pull request

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

**Copyright (c) 2026 redcountryroad**

---

## Acknowledgments

- [CrewAI](https://github.com/joaomdmoura/crewAI) - Multi-agent orchestration
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework

---

## Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/redcountryroad/swarm-tm-backend/issues)
- **API Documentation**: Interactive Swagger UI at `http://localhost:8000/docs`
- **Frontend Repository**: https://github.com/redcountryroad/swarm-tm-frontend
