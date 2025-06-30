# Minimal Example - IAM Policy Monitor

The **absolute simplest** deployment of the IAM Policy Monitor. Perfect for first-time users who want to understand the core functionality without complexity.

## What This Example Provides

✅ **Monitors IAM Events**: Detects policy violations
✅ **Email Alerts**: Sends notifications to your email
✅ **Audit Logging**: Records violations to S3
✅ **Metrics**: Basic CloudWatch metrics
✅ **Dashboard**: Simple monitoring dashboard for test visibility

❌ **No Changes**: Won't modify any IAM policies (safe to test!)
❌ **No Slack**: Email only (simple setup)
❌ **No Remediation**: Detection only (no automated fixes)

## Architecture Overview

**Lambda Functions (3 total):**

- **Detector** (256MB): Analyzes IAM events
- **SNS Publisher** (256MB): Sends email alerts
- **Audit Logger** (256MB): Logs to S3

## Quick Start

### 1. Prerequisites

Ensure you have:

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0 installed
- CloudTrail enabled in your AWS account

> **Note on AWS Region**: This example deploys to `us-east-1` because while IAM is a global service, the monitoring infrastructure (Lambda, EventBridge, CloudWatch) is regional. `us-east-1` is recommended for IAM monitoring as it's where CloudTrail global events typically originate and has the most comprehensive service availability.

### 2. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
# Basic Configuration
# Email for alerts (REQUIRED)
alert_email = "your-email@company.com"
```

### 3. Deploy Infrastructure

```bash
terraform init
terraform apply
```

### 4. Confirm SNS Subscription

Check your email for the AWS SNS subscription confirmation and click "Confirm Subscription" — and be sure to check your spam or junk folder if you don't see it.

### 5. Validate the Deployment

This minimal example is **detection-only**, so no automated remediation tests are run.

To verify everything is working:

1. Create a simple IAM policy to generate a violation (e.g. overly-permissive policy).
2. Check your email for an alert and confirm the violation appears in the CloudWatch dashboard.

For a full end-to-end automated test suite (including remediation), use the **[standard example](../standard/)**.

### 6. Cleanup

```bash
terraform destroy
```

## What You'll Get

### Email Alert Example

```plaintext
Subject: IAM Policy Violation - MEDIUM: PolicyCreation

IAM Policy Violation Detected

Rule: PolicyCreation
Severity: MEDIUM
Description: Monitor creation of new IAM policies

Event Details:
- Event Name: CreatePolicy
- User: your-user-name
- Policy ARN: arn:aws:iam::123456789012:policy/test-minimal-policy
- Timestamp: 2024-01-01T12:00:00Z
```

### S3 Audit Log

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "rule_name": "PolicyCreation",
  "severity": "MEDIUM",
  "event_name": "CreatePolicy",
  "user_identity": {
    "type": "IAMUser",
    "userName": "your-user"
  }
}
```

## Why This Is Perfect for Getting Started

- **🔒 Safe**: No automated changes to your IAM policies
- **💰 Cheap**: Under $1/month
- **⚡ Fast**: Quick setup
- **📧 Simple**: Just email notifications
- **🧹 Clean**: Easy to remove with `terraform destroy`

## Next Steps

Once you're comfortable with the minimal version:

- **Try the [standard example](../standard/)** - adds Slack, remediation, and comprehensive monitoring
- **Try the [complete example](../complete/)** - full dashboard and analytics
- **Customize rules** in `templates/rules.yaml`
