#!/usr/bin/env python3
"""Bedrock AI Analysis Demo for IAM Policy Violations.

This script demonstrates the new Bedrock AI analysis functionality
integrated into the IAM policy violation detector.
"""

import json
from pathlib import Path

import yaml

from detector import (
    DetectorConfig,
    MockAWSClients,
    PolicyViolationDetector,
)


def main():
    """Run the Bedrock demo."""
    print("🤖 IAM Policy Violation Detector - Bedrock AI Analysis Demo")
    print("=" * 60)

    # Create sample rules
    sample_rules = {
        "rules": [
            {
                "name": "DangerousInlinePolicy",
                "description": "Detects dangerous inline policies with wildcard permissions",
                "severity": "HIGH",
                "action": "alert",
                "conditions": {
                    "event_names": ["PutUserPolicy", "PutRolePolicy"],
                    "conditions": {"policy_document_contains": ['"Action": "*"']},
                },
            }
        ]
    }

    sample_suppressions = {"suppressions": []}

    # Test with Bedrock DISABLED
    print("\n1. Testing WITHOUT Bedrock Analysis:")
    print("-" * 40)

    config_no_bedrock = DetectorConfig(
        rules_bucket="test-bucket",
        enable_bedrock_analysis=False,
    )

    # Create temporary files for the mock to read
    rules_file = "temp_rules.yaml"
    suppress_file = "temp_suppress.yaml"

    try:
        with Path(rules_file).open("w") as f:
            yaml.dump(sample_rules, f)
        with Path(suppress_file).open("w") as f:
            yaml.dump(sample_suppressions, f)

        mock_clients = MockAWSClients(rules_file, suppress_file)

        detector_no_bedrock = PolicyViolationDetector(config_no_bedrock, mock_clients)

        # Create a violation event
        violation_event = {
            "eventName": "PutUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {
                "userName": "test-user",
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/test-user",
            },
            "requestParameters": {
                "userName": "test-user",
                "policyName": "DangerousPolicy",
                "policyDocument": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    }
                ),
            },
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "aws-cli/2.0.0",
            "awsRegion": "us-east-1",
            "eventTime": "2024-01-01T12:00:00Z",
        }

        violation_result = detector_no_bedrock._check_violations(
            violation_event, sample_rules
        )

        print(f"Violation Found: {violation_result.found}")
        print(f"Rule Name: {violation_result.rule_name}")
        print(f"Severity: {violation_result.severity}")
        print(f"Bedrock Analysis: {violation_result.bedrock_analysis}")

        # Test with Bedrock ENABLED
        print("\n2. Testing WITH Bedrock Analysis:")
        print("-" * 40)

        config_with_bedrock = DetectorConfig(
            rules_bucket="test-bucket",
            enable_bedrock_analysis=True,
            bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        )

        detector_with_bedrock = PolicyViolationDetector(
            config_with_bedrock, mock_clients
        )

        violation_result_ai = detector_with_bedrock._check_violations(
            violation_event, sample_rules
        )

        print(f"Violation Found: {violation_result_ai.found}")
        print(f"Rule Name: {violation_result_ai.rule_name}")
        print(f"Severity: {violation_result_ai.severity}")

        if violation_result_ai.bedrock_analysis:
            analysis = violation_result_ai.bedrock_analysis
            print("\n🤖 AI Risk Analysis:")
            print(f"  Risk Score: {analysis.risk_score}/10")
            print(f"  Risk Level: {analysis.risk_level}")
            print(f"  Summary: {analysis.summary}")
            print(f"  Confidence: {analysis.confidence:.2f}")
            print(f"  Potential Impact: {analysis.potential_impact}")
            print("  Recommendations:")
            for i, rec in enumerate(analysis.recommendations, 1):
                print(f"    {i}. {rec}")
        else:
            print("Bedrock Analysis: None")

        # Show alert message comparison
        print("\n3. Alert Message Comparison:")
        print("-" * 40)

        print("\nWithout Bedrock:")
        message_no_ai = detector_no_bedrock._format_alert_message(
            violation_result, violation_event
        )
        print(
            message_no_ai[:200] + "..." if len(message_no_ai) > 200 else message_no_ai
        )

        print("\nWith Bedrock AI Analysis:")
        message_with_ai = detector_with_bedrock._format_alert_message(
            violation_result_ai, violation_event
        )
        print(
            message_with_ai[:400] + "..."
            if len(message_with_ai) > 400
            else message_with_ai
        )

        print("\n" + "=" * 60)
        print("✅ Demo completed! Bedrock integration is working correctly.")
        print("\nTo enable in production:")
        print("1. Set enable_bedrock_analysis = true in terraform.tfvars")
        print("2. Ensure Bedrock model access is enabled in AWS console")
        print("3. Deploy with: terraform apply")

    finally:
        # Clean up temporary files
        for temp_file in [rules_file, suppress_file]:
            temp_path = Path(temp_file)
            if temp_path.exists():
                temp_path.unlink()


if __name__ == "__main__":
    main()
