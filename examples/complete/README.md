# Complete Example - IAM Policy Monitor

A deployment of the IAM Policy Monitor with comprehensive monitoring, alerting, and remediation capabilities.

## What This Example Provides

- ✅ **Complete Event-Driven Architecture**: EventBridge + 6 Lambda functions
- ✅ **Dual Notification Channels**: Email alerts + Rich Slack notifications
- ✅ **Automated Remediation**: Safe policy detachment and cleanup
- ✅ **Comprehensive Monitoring**: CloudWatch dashboard + metrics + alarms
- ✅ **Priority Alerting**: Separate high-severity notification channel
- ✅ **Audit Compliance**: S3 logging with structured audit trail
- ✅ **Athena Analytics**: Query structured violation data with Amazon Athena
- ✅ **AI-Powered Risk Analysis**: Contextual severity scoring via Amazon Bedrock
- ✅ **Production Safety**: Configurable safety controls and rate limiting

## Architecture Overview

**Lambda Functions (6 total):**

- **Detector** (256MB): Analyzes IAM events against security rules
- **Remediator** (512MB): Automatically fixes violations with safety controls
- **SNS Publisher** (256MB): Sends detailed email notifications
- **Slack Handler** (256MB): Rich Slack messages with color coding
- **Audit Logger** (256MB): Compliance logging to S3
- **Metrics Publisher** (256MB): CloudWatch metrics and monitoring

**AWS Services:**

- **EventBridge Custom Bus**: Event routing with sophisticated patterns
- **SQS Queue**: Reliable remediation action queuing
- **SNS Topics**: Email alerts + priority high-severity notifications
- **S3 Bucket**: Rules, configs, and audit logs with partitioning
- **CloudWatch**: Dashboard, metrics, alarms, and log aggregation
- **Athena + Glue Data Catalog**: Queryable analytics table for security violations

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
alert_email = "security-team@company.com"

slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Optional
owner = "security-team"
```

### 3. Deploy Infrastructure

```bash
terraform init
terraform apply
```

### 4. Confirm SNS Subscription

Check your email for the AWS SNS subscription confirmation and click "Confirm Subscription" — and be sure to check your spam or junk folder if you don't see it.

### 5. Test the System

The module includes an automated testing feature using AWS CodeBuild. This example has testing enabled by default (`create_tests = true`).

After deployment, trigger the test:

```bash
# Start the automated test suite
aws codebuild start-build --project-name "$(terraform output -raw name_prefix)-iam-policy-monitor-tests" --query "build.id" --output text
```

**Monitor test status** via the CloudWatch dashboard (in us-east-1):

```plaintext
curl https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=$(terraform output -raw name_prefix)-dashboard
```

Or check progress via CLI:

```bash
aws codebuild batch-get-builds --ids $(aws codebuild list-builds-for-project \
  --project-name "$(terraform output -raw name_prefix)-iam-policy-monitor-tests" \
  --query 'ids[0]' --output text)
```

**The automated test will:**

1. Create test IAM policies that trigger various violation rules
2. Wait for the detector Lambda to process the violations
3. Verify notifications are sent correctly
4. Check that audit logs are written to S3
5. Clean up test resources automatically

**Expected Results:**

- 📧 Email alert within 30 seconds
- 💬 Slack notification with color-coded severity
- 📊 CloudWatch metrics updated
- 📁 Audit log written to S3
- ✅ CodeBuild test completion notification

**View test logs:**

```bash
# Get the latest build logs
aws logs get-log-events \
  --log-group-name "/aws/codebuild/$(terraform output -raw name_prefix)-tests" \
  --log-stream-name "$(aws logs describe-log-streams \
    --log-group-name "/aws/codebuild/$(terraform output -raw name_prefix)-tests" \
    --order-by LastEventTime --descending \
    --query 'logStreams[0].logStreamName' --output text)"
```

## Features in Detail

### Monitoring & Detection

**Security Rules Included:**

- Admin policy attachments (HIGH severity)
- Overly broad inline policies (HIGH severity)
- Root user IAM activity (CRITICAL severity)
- Cross-account assume role policies (HIGH severity)
- Policy creation/deletion tracking (MEDIUM severity)

### Automated Remediation

**Safe Actions Enabled:**

- `detach_policy`: Remove dangerous managed policies from users/roles
- `delete_inline_policy`: Remove overly broad inline policies

**Safety Controls:**

- **Configurable Exclusions**: Prevent remediation on critical IAM principals (users/roles) and policies.
- **Wildcard Support**: Use `*` for flexible pattern matching (e.g., `*Admin*`, `ServiceRole*`).
- **Audit Trail**: Every action logged to S3 with full context.
- **Configuration-Driven**: Easily adjust safety settings via `remediator-config.json`.

The `remediator-config.json` file provides granular control over the remediation behavior.

```json
{
  "dry_run": false,
  "allowed_actions": [
    "detach_policy",
    "delete_inline_policy"
  ],
  "safety_checks": {
    "exclude_patterns": [
      "*Admin*",
      "OrganizationAccountAccessRole",
      "AWSServiceRoleFor*"
    ],
    "protected_policies": [
        "arn:aws:iam::*:policy/*Admin*",
        "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
  },
  "rate_limits": {
    "actions_per_minute": 5,
    "actions_per_hour": 50
  }
}
```

- `exclude_patterns`: A list of principal names (users or roles) to exclude from remediation. If a principal's name matches any of these patterns, remediation will be skipped. This is useful for protecting administrative or service roles.
- `protected_policies`: A list of policy ARNs to exclude from remediation actions. If a detected policy violation involves a policy matching one of these ARNs, it will not be detached or deleted. This is a safeguard for essential policies.

### Verify Athena Integration

The **IAM Policy Analytics Engine** is deployed automatically and provides continuous security intelligence:

#### 🤖 Automated Analytics Features

- **Violation Trend Analysis**: Tracks patterns and anomalies in IAM violations
- **High-Risk Principal Detection**: Identifies accounts/roles with suspicious activity patterns
- **Attack Pattern Recognition**: Detects coordinated policy manipulation attempts
- **Automated CloudWatch Metrics**: Publishes security insights to CloudWatch every hour
- **Proactive Alerting**: SNS alerts when analytics detect potential security threats

#### 📊 CloudWatch Analytics Metrics

The system automatically publishes these metrics to CloudWatch namespace `IAMPolicyMonitor/Analytics`:

- `HighRiskPrincipals` - Count of principals with multiple violations (threshold: >5 triggers alarm)
- `PotentialAttacks` - Count of potential coordinated attacks (threshold: >2 triggers alarm)
- `ViolationTrends_CRITICAL` - Critical violations per hour (threshold: >10 triggers alarm)
- `ViolationTrends_HIGH` - High-severity violations per hour
- `ViolationTrends_MEDIUM` - Medium-severity violations per hour

#### 🔍 Analytics Views (Advanced Users)

For advanced analysis, the engine creates these Athena views automatically:

```bash
# List the Glue database that stores IAM violation logs
aws glue get-database --name "$(terraform output -raw athena_database_name)"

# Verify the violations table exists
aws glue get-tables \
  --database-name "$(terraform output -raw athena_database_name)" \
  --query "TableList[].Name" --output table
```

The analytics engine creates these views for advanced investigation:

- `violation_trends` - 30-day violation patterns and trends
- `high_risk_principals` - Principals with suspicious activity (>3 violations or >2 rule types)
- `policy_attack_patterns` - Potential coordinated policy manipulation attacks

**Query the analytics views:**

```sql
-- View high-risk principals (automated analysis)
SELECT * FROM "$(terraform output -raw athena_database_name)".high_risk_principals;

-- View potential attack patterns (automated analysis)
SELECT * FROM "$(terraform output -raw athena_database_name)".policy_attack_patterns;

-- View violation trends (automated analysis)
SELECT * FROM "$(terraform output -raw athena_database_name)".violation_trends
WHERE violation_date >= current_date - interval '7' day;
```

#### ⚡ Real-Time Intelligence

The analytics engine runs every hour and automatically:

1. **Analyzes** new violation data for patterns and anomalies
2. **Publishes** security metrics to CloudWatch
3. **Triggers** SNS alerts when thresholds are exceeded
4. **Updates** analytics views with fresh insights

No manual intervention required - the system provides continuous security intelligence out of the box.

> **Tip:** In the Athena console the **Run** button stays disabled until you
> configure a Query result location. Click the blue "Edit settings" banner at
> the top of the editor and set the output location to:
>
> ```plaintext
> s3://$(terraform output -raw athena_results_bucket)/
> ```
>
> You only need to do this once per Athena setup.

### Notification Channels

#### Email Notifications

```plaintext
Subject: IAM Policy Violation - HIGH: AdminPolicyAttachment

🚨 IAM POLICY VIOLATION DETECTED 🚨

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VIOLATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule: AdminPolicyAttachment
Severity: HIGH ⚠️
Description: Detect when administrative policies are attached to users or roles
Action Triggered: detach_policy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHO PERFORMED THE ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User Identity: IAMUser
User Name: test-user-inline
User ARN: arn:aws:iam::<ACCOUNT_ID>:user/test-user-inline
Access Key ID: AKIAIOSFODNN7EXAMPLE
Session Context: N/A
Principal ID: AIDACKCEVSQ6C2EXAMPLE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT ACTION WAS PERFORMED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Event Name: AttachUserPolicy
Event Source: iam.amazonaws.com
Event Time: 2024-01-01T21:20:00Z
AWS Region: us-east-1
Source IP: 203.0.113.42
User Agent: aws-cli/2.0.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POLICY ATTACHMENT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target User: test-user-inline
Policy ARN: arn:aws:iam::aws:policy/AdministratorAccess
Policy Type: AWS Managed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFFECTED RESOURCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• AWS::IAM::User: arn:aws:iam::<ACCOUNT_ID>:user/test-user-inline

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRACKING INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Correlation ID: violation-12345-abcde
Event ID: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p

⚠️  IMMEDIATE ATTENTION REQUIRED - Review and take appropriate action
```

**Remediation Completion Email:**

```plaintext
Subject: IAM Policy Remediation SUCCESS: AdminPolicyAttachment

✅ IAM POLICY REMEDIATION COMPLETED ✅

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REMEDIATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule: AdminPolicyAttachment
Original Severity: HIGH ⚠️
Remediation Action: detach_policy
Status: SUCCESS
Timestamp: 2024-01-01T21:20:30Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ORIGINAL VIOLATION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Description: Detect when administrative policies are attached to users or roles
Event: AttachUserPolicy
Performed By: test-user-inline
User ARN: arn:aws:iam::<ACCOUNT_ID>:user/test-user-inline
User Type: IAMUser
Source IP: 203.0.113.42
AWS Region: us-east-1

Original Action Details:
• AttachUserPolicy: Attached dangerous policy to user
• Target User: test-user-inline
• Policy ARN: arn:aws:iam::aws:policy/AdministratorAccess

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REMEDIATION ACTION TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action: Policy Detachment
Policy ARN: arn:aws:iam::aws:policy/AdministratorAccess
Detached From: 1 entities
• User: test-user-inline

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRACKING INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Correlation ID: violation-12345-abcde
Original Event ID: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
Remediation Timestamp: 2024-01-01T21:20:30Z

✅ SECURITY VIOLATION SUCCESSFULLY REMEDIATED
```

#### Slack Notifications

**Violation Alerts:**

- Color-coded by severity (🚨 Red=HIGH, 🟠 Orange=MEDIUM, 🟡 Yellow=LOW)
- Detailed IAM context: User ARN, policy details, event specifics
- Source IP, region, and user agent information
- Policy attachment/creation details with target resources
- Correlation IDs for tracking across systems

**Remediation Updates:**

- ✅ Success/❌ Failure indicators with detailed context
- Shows original violation details and user who triggered it
- Lists specific remediation actions taken (policies detached, deleted)
- Entity-by-entity breakdown of what was affected
- Error details for failed remediations with troubleshooting info

### CloudWatch Dashboard

Access your dashboard at:

```plaintext
https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=complete-iam-monitor-dashboard
```

**Widgets Include:**

- Violations by severity over time
- Lambda function performance metrics
- Remediation actions taken
- Error rates and alerting status

### Monitoring & Alerts

**CloudWatch Alarms:**

- High violation volume (>10 in 5 minutes)
- Critical violations (any CRITICAL severity)
- Lambda function errors (>5 in 5 minutes)
- EventBridge failures

### Remediation Configuration

**This example uses its own `remediator-config.json` file** (not the global template). Review and customize the local configuration:

```json
{
  "dry_run": false,
  "allowed_actions": ["detach_policy", "delete_inline_policy"],
  "safety_checks": {
    "exclude_patterns": ["*Admin*", "*Root*", "OrganizationAccountAccessRole", "AWSServiceRoleFor*"]
  },
  "protected_policies": [
    "arn:aws:iam::aws:policy/*",
    "arn:aws:iam::*:policy/*Admin*",
    "arn:aws:iam::*:policy/*Root*"
  ],
  "rate_limits": {
    "actions_per_minute": 5,
    "actions_per_hour": 50
  }
}
```

**Location**: `examples/complete/remediator-config.json`
**Usage**: Automatically uploaded to S3 and used by the remediator Lambda

## Next Steps

Ready to go even further? Here are some ideas:

- **Query data in Athena** – Use the automatically-created `iam_violation_logs` table to run ad-hoc queries or power visualizations in Amazon QuickSight.
- **Integrate with your SIEM** – Feed the structured S3/Athena data into Splunk, Elastic, or Security Hub for centralized analysis.
- **Customize detection rules** in `templates/rules.yaml` to match your organisation's policies.
- **Tune the AI risk analysis** by adjusting `bedrock_model_id`, prompt templates, or disabling debug mode for lower cost.
- **Harden remediation safety controls** before moving to production (e.g. set `dry_run` to `false` and tighten `exclude_patterns`).
