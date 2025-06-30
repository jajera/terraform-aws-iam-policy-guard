"""Pytest configuration for Lambda tests."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# Add the lambdas directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def mock_boto3():
    """Mock boto3 imports to avoid AWS dependency issues during testing."""
    with patch.dict("sys.modules", {"boto3": None, "botocore": None}):
        yield


@pytest.fixture
def clean_environment():
    """Provide a clean environment for testing."""
    original_env = os.environ.copy()
    # Clear AWS-related environment variables
    aws_vars = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "RULES_BUCKET",
        "SNS_TOPIC_ARN",
        "SQS_QUEUE_URL",
        "ENABLE_SLACK_ALERTS",
        "ENABLE_REMEDIATION",
        "ALLOWED_ACTIONS",
        "DRY_RUN",
    ]

    for var in aws_vars:
        os.environ.pop(var, None)

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
