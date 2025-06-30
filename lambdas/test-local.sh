#!/bin/bash
# Local testing script for IAM Policy Monitor Lambda functions
set -e

echo "🧪 IAM Policy Monitor - Local Testing"
echo "======================================"

# Change to lambdas directory
cd "$(dirname "$0")"

echo "📍 Current directory: $(pwd)"

# Check Python version
echo "🐍 Python version:"
python --version

echo ""
echo "1️⃣  Installing dependencies..."
cd ..
pip install -q -e lambdas/[dev]
cd lambdas

echo ""
echo "2️⃣  Running basic tests..."
python run_tests.py

echo ""
echo "3️⃣  Running comprehensive tests..."
pytest --cov=detector --cov=remediator --cov-report=term-missing -v

echo ""
echo "4️⃣  Code quality checks..."
echo "🔍 Running code quality checks..."

# Ruff linting
echo "  - Running Ruff linting..."
ruff check . --config=pyproject.toml

# MyPy type checking
echo "  - Running MyPy type checking..."
mypy . --config-file=pyproject.toml

# Ruff formatting check
echo "  - Checking Ruff formatting..."
ruff format --check . --config=pyproject.toml

echo ""
echo "5️⃣  Testing local execution..."
echo "   - Testing detector with mock data (default)..."
# Use mock clients by default (no USE_REAL_AWS=true)
RULES_BUCKET=test-bucket python detector.py --log-level INFO

echo "   - Testing detector with sample rules..."
# Test with sample rules file if it exists
if [ -f "test_data/sample_rules.yaml" ]; then
    RULES_BUCKET=test-bucket python detector.py \
        --rules test_data/sample_rules.yaml \
        --suppress test_data/sample_suppressions.yaml \
        --log-level INFO
else
    echo "   (No sample rules file found, skipping)"
fi

echo "   - Testing remediator with mock data..."
RULES_BUCKET=test-bucket python remediator.py --log-level INFO

echo ""
echo "✅ All tests completed successfully!"
echo ""
echo "💡 Tips:"
echo "   - To use real AWS: USE_REAL_AWS=true ./test-local.sh"
echo "   - To test with custom event: python detector.py --event your_event.json"
echo "   - To run specific tests: pytest test_detector.py::TestDetector::test_specific"
