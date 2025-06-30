#!/usr/bin/env python3
"""Simple test runner for basic functionality testing.

This script provides a basic test suite that doesn't require pytest,
making it useful for quick validation in environments where pytest
might not be available.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Mock boto3 and related AWS modules
sys.modules["boto3"] = Mock()
sys.modules["yaml"] = Mock()

# Import our modules after mocking
try:
    from detector import (
        DetectorConfig,
        ViolationResult,
    )
    from detector import (
        lambda_handler as detector_lambda_handler,
    )
    from remediator import (
        RemediationConfig,
        RemediationResult,
    )
    from remediator import (
        lambda_handler as remediator_lambda_handler,
    )

    print("✓ Successfully imported detector and remediator modules")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


class TestDetectorBasic(unittest.TestCase):
    """Basic tests for detector without external dependencies."""

    def test_detector_config_creation(self):
        """Test DetectorConfig creation."""
        config = DetectorConfig(rules_bucket="test-bucket", sns_topic_arn="test-topic")
        self.assertEqual(config.rules_bucket, "test-bucket")
        self.assertEqual(config.sns_topic_arn, "test-topic")

    def test_violation_result_creation(self):
        """Test ViolationResult creation."""
        result = ViolationResult(found=True, rule_name="TestRule", severity="HIGH")
        self.assertTrue(result.found)
        self.assertEqual(result.rule_name, "TestRule")

        result_dict = result.to_dict()
        self.assertIn("rule_name", result_dict)
        self.assertEqual(result_dict["rule_name"], "TestRule")


class TestRemediatorBasic(unittest.TestCase):
    """Basic tests for remediator without external dependencies."""

    def test_remediation_config_creation(self):
        """Test RemediationConfig creation."""
        config = RemediationConfig(
            rules_bucket="test-bucket", allowed_actions=["detach_policy"]
        )
        self.assertEqual(config.rules_bucket, "test-bucket")
        self.assertEqual(config.allowed_actions, ["detach_policy"])

    def test_remediation_result_creation(self):
        """Test RemediationResult creation."""
        result = RemediationResult(
            success=True, details={"action": "detach_policy"}, error=None
        )
        self.assertTrue(result.success)
        self.assertEqual(result.details["action"], "detach_policy")
        self.assertIsNone(result.error)


class TestLambdaHandlers(unittest.TestCase):
    """Test Lambda handlers with mocked dependencies."""

    @patch("detector.DetectorConfig.from_env")
    @patch("detector.AWSClients")
    @patch("detector.PolicyViolationDetector")
    def test_detector_lambda_handler(self, mock_detector, _mock_clients, mock_config):
        """Test detector Lambda handler."""
        # Setup mocks
        mock_config.return_value = DetectorConfig(rules_bucket="test")
        mock_detector_instance = Mock()
        mock_detector_instance.process_eventbridge_event.return_value = {
            "statusCode": 200,
            "body": "Success",
        }
        mock_detector.return_value = mock_detector_instance

        # Test handler
        event = {"detail": {"eventName": "PutUserPolicy"}}
        result = detector_lambda_handler(event, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["body"], "Success")

    @patch("remediator.RemediationConfig.from_env")
    @patch("remediator.AWSClients")
    @patch("remediator.PolicyRemediator")
    def test_remediator_lambda_handler(
        self, mock_remediator, _mock_clients, mock_config
    ):
        """Test remediator Lambda handler."""
        # Setup mocks
        mock_config.return_value = RemediationConfig(
            rules_bucket="test", allowed_actions=["detach_policy"]
        )
        mock_remediator_instance = Mock()
        mock_remediator_instance.process_sqs_event.return_value = {
            "statusCode": 200,
            "body": "Success",
        }
        mock_remediator.return_value = mock_remediator_instance

        # Test handler
        event = {"Records": [{"eventSource": "aws:sqs", "body": "{}"}]}
        result = remediator_lambda_handler(event, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["body"], "Success")


def run_tests():
    """Run all tests."""
    print("Running Lambda function tests...")
    print("=" * 50)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDetectorBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestRemediatorBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestLambdaHandlers))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")

    if result.wasSuccessful():
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
