# AWS IAM Policy Monitor

Terraform module for real-time IAM policy monitoring, automated remediation, and **security intelligence analytics** using EventBridge and Lambda.

## ✨ Key Features

- **🔍 Real-time Monitoring**: Event-driven IAM policy violation detection
- **🛠️ Automated Remediation**: Safe policy detachment/deletion with comprehensive safety controls
- **📊 Security Analytics**: Automated threat intelligence and attack pattern detection (Athena-powered)
- **🚨 Multi-channel Alerts**: SNS, Slack, and priority notifications
- **📝 Compliance Logging**: Comprehensive audit trail with S3 partitioning
- **🎯 Zero Manual Work**: Fully automated setup and continuous operation

## Quick Start

```bash
# Build Lambda packages (includes dependencies)
./lambdas/build-lambda-packages.sh

# Deploy infrastructure
terraform init
terraform apply
```

## Configuration

```hcl
# terraform.tfvars
name_prefix           = "iam-monitor"
enable_remediation    = true
sns_alert_email      = "alerts@company.com"
slack_webhook_url     = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"  # Stored securely in Parameter Store
```

Edit `templates/rules.yaml` and `templates/suppress.yaml` to control monitoring behavior:

```yaml
# templates/rules.yaml
rules:
  - name: "dangerous-policy-creation"
    description: "Detect creation of overly permissive policies"
    severity: "HIGH"
    action: "alert"
    conditions:
      event_names: ["CreatePolicy", "PutUserPolicy"]
```

## Architecture

### Event-Driven Design

- **EventBridge**: Central event routing for IAM violations
- **Custom Event Bus**: Dedicated bus for IAM policy violations
- **6 Lambda Functions**: Specialized handlers for different responsibilities
- **Least-Privilege IAM**: Separate roles with minimal permissions

### Components

- **Detector Lambda**: Processes IAM events, detects violations, publishes to EventBridge
- **SNS Publisher**: Sends email alerts for violations
- **Slack Handler**: Posts formatted messages to Slack channels
- **Audit Logger**: Records all violations to S3 for compliance
- **Metrics Publisher**: Publishes CloudWatch metrics for monitoring
- **Athena Table Creator**: Automated analytics engine for security intelligence (optional)
- **Analytics Scheduler**: Hourly execution of threat detection queries (optional)
- **Remediator Lambda**: Handles policy detachment/deletion (optional)

### Infrastructure

- **S3**: Stores rules, configurations, audit logs, and Lambda artifacts
- **SQS**: Queues remediation actions with DLQ
- **CloudWatch**: Dashboards, alarms, and log retention
- **Athena**: Automated security analytics with threat intelligence views
- **EventBridge**: Custom event bus with scheduled analytics execution

## Terraform Structure

The module uses service-based organization for better maintainability:

```plaintext
├── main.tf          # Core data sources and locals
├── storage.tf       # S3 buckets, objects, Athena resources
├── messaging.tf     # SNS, SQS, EventBridge configuration
├── compute.tf       # Lambda functions and packaging
├── iam.tf          # Least-privilege IAM roles and policies
├── monitoring.tf    # CloudWatch logs, dashboards, alarms
├── variables.tf     # Input variables
├── outputs.tf       # Output values
└── versions.tf      # Provider requirements
```

### Lambda Functions

- **detector**: Event processing and violation detection
- **sns-publisher**: Email notifications via SNS
- **slack-handler**: Slack webhook notifications
- **audit-logger**: Compliance logging to S3
- **metrics-publisher**: CloudWatch metrics publishing
- **athena-table-creator**: Automated analytics engine and threat intelligence (optional)
- **analytics-scheduler**: Hourly security analytics execution (optional)
- **remediator**: Automated policy remediation (optional)

## Examples

### Basic Usage

```hcl
module "iam_policy_monitor" {
  source = "path/to/module"

  name_prefix     = "my-iam-monitor"
  sns_alert_email = "security@company.com"

  # Minimal configuration
  enable_remediation           = false
  enable_cloudwatch_dashboard  = true
  enable_athena_table         = false
}
```

### Complete Configuration

```hcl
module "iam_policy_monitor" {
  source = "path/to/module"

  name_prefix     = "prod-iam-monitor"
  sns_alert_email = "security@company.com"
  slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"  # Stored securely in Parameter Store

  # Enable all features
  enable_remediation           = true
  enable_slack_alerts         = true
  enable_cloudwatch_dashboard  = true
  enable_athena_table         = true
  enable_priority_alerts      = true
  enable_bedrock_analysis     = true

    # Customize settings
  lambda_memory      = 512
  lambda_timeout     = 300
  log_retention_days = 90
  dry_run_mode      = false

  # Customize Slack notification colors
  severity_colors = {
    CRITICAL = "#FF0000" # Red
    HIGH     = "#FF4500" # OrangeRed
    MEDIUM   = "#FFA500" # Orange
    LOW      = "#FFFF00" # Yellow
  }

  # Force destroy options (use with caution)
  force_destroy_s3   = false
  force_destroy_logs = false

  common_tags = {
    Environment = "production"
    Team        = "security"
    Purpose     = "iam-monitoring"
  }
}
```

## Monitoring & Alerts

### CloudWatch Dashboard

- Violation counts by severity (LOW, MEDIUM, HIGH, CRITICAL)
- Lambda function metrics (duration, errors, invocations)
- Remediation actions taken
- **Analytics Intelligence**: High-risk principals, potential attacks, violation trends (when Athena enabled)

### CloudWatch Alarms

- High volume of violations (>10 in 5 minutes)
- Any critical violations (immediate alert)
- Lambda function errors (>5 in 5 minutes)
- EventBridge rule failures
- **High-risk principals detected** (>5 suspicious accounts - when Athena enabled)
- **Potential coordinated attacks** (>2 attack patterns - when Athena enabled)
- **Critical violation trends** (>10/hour - when Athena enabled)

### Priority Alerts

High and critical severity violations trigger immediate notifications via:

- Priority SNS topic with custom message formatting
- Slack alerts with severity indicators
- CloudWatch alarms for operations teams

## 📊 Security Analytics Engine

When `enable_athena_table = true`, the module deploys a comprehensive **automated security intelligence platform** that transforms raw violation data into actionable threat intelligence.

### 🎯 Zero Manual Work Required

- **Automatic Setup**: Creates Athena database, tables, and analytics views automatically
- **Continuous Analysis**: Runs security analytics every hour without intervention
- **Proactive Alerting**: Publishes CloudWatch metrics for immediate alerting
- **Ready-to-Use Views**: Pre-built analytics queries for common security scenarios

### 🔍 Threat Intelligence Capabilities

#### **High-Risk Principal Detection**

Identifies accounts showing suspicious patterns:

- Principals with >3 violations across multiple rule types
- Accounts with unusual policy modification behavior
- Cross-account activity anomalies

#### **Attack Pattern Recognition**

Detects coordinated policy manipulation attempts:
>
- >5 policy modifications from single source in short timeframe
- Multiple source IPs targeting same principal
- Coordinated privilege escalation attempts

#### **Violation Trend Analysis**

30-day trending analysis with anomaly detection:

- Severity-based violation patterns
- Time-based attack correlation
- Principal behavior baseline establishment

### 📈 CloudWatch Integration

The analytics engine publishes metrics to `IAMPolicyMonitor/Analytics` namespace:

- `HighRiskPrincipals` - Count of suspicious accounts
- `PotentialAttacks` - Coordinated attack detection counter
- `ViolationTrends_CRITICAL/HIGH/MEDIUM` - Severity-based trend analysis

### 🚨 Automated Alerting

CloudWatch alarms trigger when:

- **>5 high-risk principals** detected (potential compromise)
- **>2 potential attacks** identified (coordinated threat)
- **>10 critical violations/hour** (attack in progress)

### 🔍 Analytics Views

Pre-built Athena views for security investigation:

```sql
-- High-risk principals (>3 violations or >2 rule types)
SELECT * FROM high_risk_principals;

-- Coordinated attack patterns
SELECT * FROM policy_attack_patterns;

-- 30-day violation trends with anomalies
SELECT * FROM violation_trends;
```

## Security Features

### Least-Privilege IAM

Each Lambda function has its own IAM role with minimal permissions:

- **Detector**: S3 read (config), EventBridge publish, CloudWatch metrics
- **SNS Publisher**: SNS publish to specific topic only
- **Slack Handler**: S3 read (notification config), SSM Parameter Store read
- **Audit Logger**: S3 write to audit-logs/* prefix only
- **Metrics Publisher**: CloudWatch metrics to specific namespace
- **Athena Table Creator**: Athena queries, Glue catalog, S3 read/write, CloudWatch metrics (optional)
- **Analytics Scheduler**: Same as table creator for hourly analytics execution (optional)
- **Remediator**: Restricted IAM actions, SQS access (optional)

### Compliance Logging

- All violations logged to S3 with timestamps
- **Automated analytics** with threat intelligence views (when Athena enabled)
- Audit trail for remediation actions
- CloudWatch logs with configurable retention
- **Proactive security metrics** for continuous monitoring

### AI-Powered Risk Analysis (Bedrock)

When enabled, the detector can enrich each violation with an Amazon Bedrock Claude 3 analysis that provides:

- 1-10 risk score and risk level
- Executive summary and potential impact
- Actionable recommendations
- Model confidence score

To enable this feature, set `enable_bedrock_analysis = true`. Note that this feature currently uses the `anthropic.claude-3-sonnet-20240229-v1:0` model, which requires access to the `us-east-1` Bedrock region.

### Best-Practice Ruleset

The module includes a default `rules.yaml` and `suppress.yaml` based on security best practices:

- **High-Fidelity Rules**: Detects common misconfigurations like overly permissive inline policies, security tool tampering, and privilege escalation.
- **Intelligent Suppression**: Automatically ignores noise from the module's own remediation actions, common AWS services, and low-risk IaC operations, significantly reducing alert fatigue.

## Cleanup & Destruction

### Force Destroy Options

By default, S3 buckets, CloudWatch log groups, and Athena databases are protected from accidental deletion. You can override this for development/testing:

```hcl
module "iam_policy_monitor" {
  source = "path/to/module"

  # Force destroy options (use with extreme caution in production)
  force_destroy_s3     = true  # Allows S3 bucket deletion even with objects
  force_destroy_logs   = true  # Allows log group deletion even with logs
  force_destroy_athena = true  # Allows Athena database deletion even with tables/views

  # ... other configuration
}
```

⚠️ **Warning**:

- Setting `force_destroy_s3 = true` will permanently delete all audit logs and configuration files when running `terraform destroy`
- Setting `force_destroy_athena = true` automatically cleans up Athena tables and views before database deletion using destroy-time provisioners
- Only use these options in development environments

### Safe Cleanup Process

For production environments, manually clean up before destroying:

```bash
# 1. Export audit logs if needed
aws s3 sync s3://your-bucket-name/audit-logs/ ./backup-logs/

# 2. Export Athena analytics data if needed
# Run your final analytics queries in Athena console before cleanup

# 3. Empty S3 buckets
aws s3 rm s3://your-bucket-name --recursive

# 4. Drop Athena tables manually (or use force_destroy_athena = true for automatic cleanup)
# In Athena console: DROP VIEW viewname; DROP TABLE tablename;

# 5. Delete CloudWatch logs (optional)
aws logs delete-log-group --log-group-name /aws/lambda/your-prefix-detector

# 6. Run terraform destroy
terraform destroy
```

## Setup

### Prerequisites

1. AWS CLI configured with appropriate permissions
2. Terraform >= 1.0
3. S3 bucket for storing Lambda packages (optional - can be created by module)

### Slack Integration Setup

To enable Slack notifications, simply provide your webhook URL in the Terraform configuration. The module will automatically create a secure parameter store entry for it:

```hcl
enable_slack_alerts = true
slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

The webhook URL is stored securely in AWS Systems Manager Parameter Store and is marked as sensitive in Terraform to prevent accidental exposure in logs or state files.

## Customization

### Rules and Suppressions

You can customize the detection logic by editing `templates/rules.yaml` and `templates/suppress.yaml`. See the `templates/README.md` for a detailed guide on structuring these files.

### Configurable Slack Colors

You can customize the color bar for each severity level in Slack notifications by providing a map of severity-to-hex-color codes.

```hcl
module "iam_policy_monitor" {
  source = "path/to/module"

  # ... other configuration
  severity_colors = {
    CRITICAL = "#FF0000"
    HIGH     = "#FF4500"
    MEDIUM   = "#FFA500"
    LOW      = "#FFFF00"
    INFO     = "#D3D3D3"
  }
}
```

If not provided, a default color scheme will be used.

## 🧪 Testing

The repository contains **two independent test suites**:

1. **Python unit tests** (`pytest`) for all Lambda functions (under `lambdas/`).
2. **Terraform configuration tests** (`tests/iam-policy-guard.tftest.hcl`).  These use the new
   `mock_provider` feature in Terraform 1.7+, which lets us validate the
   generated plan *without making any AWS API calls*.

### Running all tests locally

```bash
# 1. Python tests + static analysis (ruff & mypy)
cd lambdas
pip install -r requirements-dev.txt
pytest -q

# 2. Terraform mock tests (no AWS credentials required)
cd ..
terraform test -verbose
```

The Terraform test file validates:

- Variable validation and default handling.
- Conditional creation of resources when feature flags such as
  `enable_athena_table` or `enable_slack_alerts` are toggled.
- Basic structural checks (e.g., every Lambda has a log group, Athena buckets are named correctly, etc.).

Because the tests use **mock providers**, they are fast, free, and safe to
run in CI pipelines that don't have AWS credentials.

> Looking for a full end-to-end test that *actually* provisions resources?
> See `testing.tf`, which defines an optional CodeBuild project that can be
> deployed separately for integration testing in a real AWS account.

---

## 📚 Additional Docs

- [Evaluation Notes](EVALUATION_NOTES.md) – quick operational tips for Hackathon judges / first-time users.
- [Roadmap](ROADMAP.md) – list of future enhancements and ideas.
