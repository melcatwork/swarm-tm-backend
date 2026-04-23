#!/usr/bin/env bash
# Test suite for Revised Prompt 1 and Revised Prompt 2
# Runs unit tests automatically, provides instructions for integration tests

set -e

echo "=================================================="
echo "Revised Prompt 1 & 2 Test Suite"
echo "=================================================="
echo ""

# Check we're in the right directory
if [[ ! -f "backend/app/swarm/persona_selector.py" ]]; then
    echo "ERROR: Must run from swarm-tm project root"
    exit 1
fi

# Activate virtual environment if it exists
if [[ -d "backend/.venv" ]]; then
    echo "Activating virtual environment..."
    source backend/.venv/bin/activate
fi

echo "Running unit tests (no server required)..."
echo ""

# Run persona structure tests
echo "=================================================="
echo "TEST MODULE 1: cloud_native_attacker persona"
echo "=================================================="
python -m pytest tests/test_rp1_persona.py -v --tb=short

# Run module unit tests
echo ""
echo "=================================================="
echo "TEST MODULE 2: RP2 modules (selector/filter/consensus)"
echo "=================================================="
python -m pytest tests/test_rp2_modules.py -v --tb=short

echo ""
echo "=================================================="
echo "Unit tests complete."
echo "=================================================="
echo ""
echo "To run integration tests (requires backend server):"
echo ""
echo "  1. Start backend server in another terminal:"
echo "     cd /Users/bland/Desktop/swarm-tm"
echo "     source backend/.venv/bin/activate"
echo "     uvicorn app.main:app --port 8000 --app-dir backend"
echo ""
echo "  2. Run integration tests:"
echo "     python -m pytest tests/test_rp2_integration.py -v --tb=short"
echo ""
echo "Integration tests validate all 4 run types surface"
echo "confirmed findings dynamically for the same IaC input."
echo ""
