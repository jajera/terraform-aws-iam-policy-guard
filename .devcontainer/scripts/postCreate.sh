#!/bin/bash
set -e

echo "🚀 Setting up IAM Policy Monitor development environment..."

# Navigate to workspace
cd /workspaces/terraform-aws-iam-policy-guard

# Install Python dependencies for lambdas
echo "📦 Installing Python dependencies..."
cd lambdas
pip install -e .[dev]
cd ..

# Set executable permissions for Python files
echo "🔧 Setting permissions..."
find . -name "*.py" -type f -exec chmod +x {} \;

# Run quality checks using unified config
echo "🔍 Running code quality checks..."

# Ruff linting and formatting (using root config)
echo "  - Running Ruff linting..."
if ! ruff check lambdas/; then
    echo "⚠️  Ruff found linting issues"
fi

echo "  - Running Ruff formatting..."
if ! ruff format lambdas/; then
    echo "⚠️  Ruff formatting issues found"
fi

# MyPy type checking (using root config)
echo "  - Running MyPy type checking..."
if ! mypy lambdas/; then
    echo "⚠️  MyPy found type issues (some may be expected boto3 stub warnings)"
fi

# Run tests
echo "🧪 Running tests..."

# Basic tests first
echo "  - Running basic tests..."
cd lambdas
if python run_tests.py; then
    echo "✅ Basic tests passed"
else
    echo "❌ Basic tests failed"
fi

# Comprehensive tests with pytest
echo "  - Running comprehensive test suite..."
if pytest -v; then
    echo "✅ All tests passed"
else
    echo "❌ Some tests failed"
fi

cd ..

# Verify project structure
echo "📂 Verifying project structure..."
echo "  - Lambda configuration: lambdas/pyproject.toml"
ls -la lambdas/pyproject.toml 2>/dev/null && echo "    ✅ Found" || echo "    ❌ Missing"

echo "  - Lambda functions:"
ls -la lambdas/*.py 2>/dev/null && echo "    ✅ Found Python files" || echo "    ❌ No Python files"

echo "  - Test files:"
ls -la lambdas/test_*.py 2>/dev/null && echo "    ✅ Found test files" || echo "    ❌ No test files"

echo "  - Configuration files:"
ls -la .vscode/settings.json 2>/dev/null && echo "    ✅ VS Code settings" || echo "    ❌ Missing VS Code settings"
ls -la .devcontainer/devcontainer.json 2>/dev/null && echo "    ✅ DevContainer config" || echo "    ❌ Missing DevContainer config"

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Review and configure AWS credentials for local testing"
echo "  2. Set environment variables for S3 bucket names and SNS topics"
echo "  3. Run 'cd lambdas && python detector.py' to test the detector function"
echo "  4. Run 'cd lambdas && python remediator.py' to test the remediator function"
echo "  5. Use 'cd lambdas && ruff check .' and 'ruff format .' for code quality"
echo "  6. Use 'mypy lambdas/' for type checking"
echo "  7. Use 'pytest lambdas/' for running tests"
echo ""
echo "🔧 Development tools configured:"
echo "  - Linting configuration in lambdas/pyproject.toml"
echo "  - Auto-formatting on save enabled"
echo "  - 79-character line length enforced"
echo "  - Type checking with MyPy"
echo "  - Comprehensive test suite"
