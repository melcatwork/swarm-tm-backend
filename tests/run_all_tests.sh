#!/bin/bash
set -e

echo "=============================================="
echo "swarm-tmv2 Enhancement Test Suite"
echo "=============================================="
echo ""

cd "$(dirname "$0")/.."

# Activate backend venv
source backend/.venv/bin/activate

# Check intel DB exists
if [ ! -f "backend/app/swarm/vuln_intel/intel.db" ]; then
    echo "intel.db not found. Running initial sync..."
    python3 backend/scripts/sync_intel.py
    echo ""
fi

echo "Running unit tests (no server required)..."
echo ""

echo "[L1] Persona reasoning instructions..."
python3 -m pytest tests/test_revised_l1.py -v --tb=short
echo ""

echo "[L2] IaC serialiser and security analyser..."
python3 -m pytest tests/test_revised_l2.py -v --tb=short
echo ""

echo "[L3] Selective technique KB..."
python3 -m pytest tests/test_revised_l3.py -v --tb=short
echo ""

echo "[L4] LLM path evaluator..."
python3 -m pytest tests/test_revised_l4.py -v --tb=short
echo ""

echo "[V1] Dynamic intel database..."
python3 -m pytest tests/test_v1_dynamic.py -v --tb=short
echo ""

echo "[V2/V3] Vuln matcher, chain assembler, context builder..."
python3 -m pytest tests/test_v2_v3.py -v --tb=short
echo ""

echo "=============================================="
echo "Unit tests complete."
echo ""
echo "To run end-to-end tests, start the backend server:"
echo "  cd backend && uvicorn app.main:app --port 8000"
echo "Then run:"
echo "  python3 -m pytest tests/test_end_to_end.py -v --tb=short -s"
echo "=============================================="
