#!/bin/bash

# Build Lambda package with dependencies for Terraform deployment
# Creates a unified package containing all Lambda functions for event-driven architecture

set -e

# Get the directory where this script is located (lambdas directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the script directory (lambdas directory)
cd "$SCRIPT_DIR"

# Create dist directory if it doesn't exist
mkdir -p dist

# Check if rebuild is needed (idempotent behavior)
PACKAGE_FILE="dist/lambda-package.zip"
NEEDS_REBUILD=false

# Allow manual rebuild with --force argument or FORCE_REBUILD env var
if [ "$1" == "--force" ] || [ "${FORCE_REBUILD:-false}" = "true" ]; then
    NEEDS_REBUILD=true
fi

if [ "$NEEDS_REBUILD" = false ]; then
    echo "✅ Package is up-to-date, skipping build"
    echo "📋 Existing package:"
    ls -lh "$PACKAGE_FILE"
    exit 0
fi

echo "🚀 Building unified Lambda package with dependencies..."
echo "======================================================"

# Create a requirements file without boto3/botocore (provided by AWS Lambda runtime)
echo "📦 Creating optimized requirements..."
if [ -f "requirements.txt" ]; then
    grep -v -E "^(boto3|botocore)" requirements.txt > requirements-lambda.txt 2>/dev/null || cp requirements.txt requirements-lambda.txt
else
    echo "⚠️  requirements.txt not found, creating minimal requirements..."
    echo "PyYAML>=6.0" > requirements-lambda.txt
    echo "requests>=2.28.0" >> requirements-lambda.txt
fi

echo "🔧 Installing dependencies with transitive requirements (excluding AWS SDK)..."
rm -rf temp_deps
mkdir temp_deps

# Install all dependencies (minus boto3/botocore) into temp_deps
pip install -r requirements-lambda.txt \
    --target temp_deps/ \
    --upgrade \
    --disable-pip-version-check \
    --quiet

# Some environments miss the C-extension package name mapping.
# Explicitly install PyYAML to guarantee the 'yaml' module is present.
pip install PyYAML -t temp_deps/ --upgrade --disable-pip-version-check --quiet

echo "📂 Copying all Lambda function modules..."

# List of all Lambda function modules in the event-driven architecture
LAMBDA_MODULES=(
    "detector.py"
    "remediator.py"
    "sns_publisher.py"
    "slack_handler.py"
    "audit_logger.py"
    "metrics_publisher.py"
    "athena_table_creator.py"
    "violation_event.py"
    "slack_notifier.py"
)

# Copy all Lambda modules
for module in "${LAMBDA_MODULES[@]}"; do
    if [ -f "$module" ]; then
        echo "  ✅ Adding $module"
        cp "$module" temp_deps/
    else
        echo "  ⚠️  Warning: $module not found, skipping..."
    fi
done

# Copy requirements.txt for reference (if it exists)
if [ -f "requirements.txt" ]; then
    cp requirements.txt temp_deps/
else
    cp requirements-lambda.txt temp_deps/requirements.txt
fi

echo "📦 Creating unified deployment package..."
cd temp_deps
zip -r ../dist/lambda-package.zip . -x "*.pyc" "*/__pycache__/*" "pip*" "setuptools*" "wheel*" --quiet
cd ..

# Clean up
rm -rf temp_deps
rm -f requirements-lambda.txt

echo ""
echo "🎉 Build complete!"
echo ""
echo "📋 Unified Lambda package created:"
ls -lh dist/lambda-package.zip

echo ""
echo "📊 Package contents:"
unzip -l dist/lambda-package.zip | grep -E "\.(py|txt)$" | head -20

echo ""
echo "💡 This package contains all Lambda functions:"
for module in "${LAMBDA_MODULES[@]}"; do
    if [ -f "$module" ]; then
        echo "  • ${module%.py}: ${module%.py}.lambda_handler"
    fi
done

echo ""
echo "🔧 For Terraform deployment:"
echo "  - The package will be uploaded to S3 automatically"
echo "  - Each Lambda function uses the same package with different handlers"
echo "  - If this package doesn't exist, Terraform will create a basic package without dependencies"

echo ""
echo "✅ Ready for: terraform apply"
