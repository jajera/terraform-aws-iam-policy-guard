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

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0.0 |
| <a name="requirement_null"></a> [null](#requirement\_null) | >= 3.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | n/a |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |
| <a name="provider_null"></a> [null](#provider\_null) | >= 3.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_athena_database.violations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database) | resource |
| [aws_cloudwatch_composite_alarm.eventbridge_failures_composite](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_composite_alarm) | resource |
| [aws_cloudwatch_composite_alarm.lambda_errors_composite](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_composite_alarm) | resource |
| [aws_cloudwatch_composite_alarm.sns_delivery_composite](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_composite_alarm) | resource |
| [aws_cloudwatch_composite_alarm.sqs_backlog_composite](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_composite_alarm) | resource |
| [aws_cloudwatch_dashboard.iam_policy_monitor](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_dashboard) | resource |
| [aws_cloudwatch_event_bus.iam_violations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_bus) | resource |
| [aws_cloudwatch_event_rule.analytics_schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.high_severity_violations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.iam_events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.iam_violations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.remediation_status](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.analytics_scheduler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.priority_sns](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.remediation_audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.remediation_metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.remediation_slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.remediation_sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.analytics_scheduler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.athena_table_creator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.codebuild_testing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.remediator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_metric_alarm.critical_violation_spike](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.eventbridge_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.high_risk_principals_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.lambda_errors_alarms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.potential_attacks_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.sns_delivery_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.sqs_backlog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.test_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_codebuild_project.iam_policy_monitor_tests](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project) | resource |
| [aws_iam_role.athena_table_creator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.codebuild_testing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.remediator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.athena_table_creator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.codebuild_testing_iam](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.codebuild_testing_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.codebuild_testing_metrics](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.remediator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_event_source_mapping.remediator_sqs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_event_source_mapping) | resource |
| [aws_lambda_function.analytics_scheduler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.athena_table_creator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.remediator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_invocation.create_athena_table](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_invocation) | resource |
| [aws_lambda_permission.analytics_scheduler_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.audit_logger_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.detector_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.metrics_publisher_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.remediation_audit_logger_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.remediation_metrics_publisher_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.remediation_slack_handler_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.remediation_sns_publisher_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.slack_handler_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.sns_publisher_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.rules_and_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_public_access_block.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.rules_and_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.rules_and_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.rules_and_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_s3_object.lambda_package](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.notification_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.remediator_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.rules](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_s3_object.suppress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_sns_topic.alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic.priority_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.priority_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.email_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_sqs_queue.eventbridge_dlq](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_sqs_queue.remediation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_sqs_queue.remediation_dlq](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_ssm_parameter.slack_webhook](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [null_resource.athena_cleanup](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [archive_file.lambda_terraform](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_bedrock_foundation_model.claude_sonnet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/bedrock_foundation_model) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.athena_table_creator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.audit_logger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.detector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.lambda_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.metrics_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.remediator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.slack_handler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sns_publisher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_bedrock_model_id"></a> [bedrock\_model\_id](#input\_bedrock\_model\_id) | The model ID to use for Bedrock analysis. E.g., 'anthropic.claude-v2'. | `string` | `"anthropic.claude-3-sonnet-20240229-v1:0"` | no |
| <a name="input_bucket_name"></a> [bucket\_name](#input\_bucket\_name) | S3 bucket name for config and logs (if not provided, will be auto-generated) | `string` | `""` | no |
| <a name="input_common_tags"></a> [common\_tags](#input\_common\_tags) | Common tags to apply to all resources | `map(string)` | `{}` | no |
| <a name="input_create_tests"></a> [create\_tests](#input\_create\_tests) | Create CodeBuild project for manual IAM Policy Monitor testing | `bool` | `false` | no |
| <a name="input_custom_notification_config_file"></a> [custom\_notification\_config\_file](#input\_custom\_notification\_config\_file) | Path to custom notification-config.yaml file (overrides default) | `string` | `""` | no |
| <a name="input_custom_remediator_config_file"></a> [custom\_remediator\_config\_file](#input\_custom\_remediator\_config\_file) | Path to custom remediator-config.json file (overrides default) | `string` | `""` | no |
| <a name="input_custom_rules_file"></a> [custom\_rules\_file](#input\_custom\_rules\_file) | Path to custom rules.yaml file (overrides default templates/rules.yaml) | `string` | `""` | no |
| <a name="input_custom_suppress_file"></a> [custom\_suppress\_file](#input\_custom\_suppress\_file) | Path to custom suppress.yaml file (overrides default templates/suppress.yaml) | `string` | `""` | no |
| <a name="input_debug_mode"></a> [debug\_mode](#input\_debug\_mode) | Enable debug logging for all Lambda functions | `bool` | `false` | no |
| <a name="input_dry_run_mode"></a> [dry\_run\_mode](#input\_dry\_run\_mode) | Enable dry-run mode for remediator (no actual changes) | `bool` | `true` | no |
| <a name="input_enable_athena_table"></a> [enable\_athena\_table](#input\_enable\_athena\_table) | Create Athena table for historical reporting | `bool` | `true` | no |
| <a name="input_enable_bedrock_analysis"></a> [enable\_bedrock\_analysis](#input\_enable\_bedrock\_analysis) | Enable AI-powered risk analysis for IAM policy violations using Amazon Bedrock. | `bool` | `false` | no |
| <a name="input_enable_cloudwatch_alarms"></a> [enable\_cloudwatch\_alarms](#input\_enable\_cloudwatch\_alarms) | Create CloudWatch alarms for monitoring | `bool` | `true` | no |
| <a name="input_enable_cloudwatch_dashboard"></a> [enable\_cloudwatch\_dashboard](#input\_enable\_cloudwatch\_dashboard) | Create CloudWatch dashboard | `bool` | `true` | no |
| <a name="input_enable_priority_alerts"></a> [enable\_priority\_alerts](#input\_enable\_priority\_alerts) | Enable priority SNS topic for high/critical severity violations | `bool` | `true` | no |
| <a name="input_enable_remediation"></a> [enable\_remediation](#input\_enable\_remediation) | Enable automatic remediation of violations | `bool` | `false` | no |
| <a name="input_enable_s3_versioning"></a> [enable\_s3\_versioning](#input\_enable\_s3\_versioning) | Enable versioning on S3 bucket | `bool` | `true` | no |
| <a name="input_enable_slack_alerts"></a> [enable\_slack\_alerts](#input\_enable\_slack\_alerts) | Enable Slack webhook alerts | `bool` | `false` | no |
| <a name="input_enable_sns_alerts"></a> [enable\_sns\_alerts](#input\_enable\_sns\_alerts) | Enable SNS notifications for violations | `bool` | `true` | no |
| <a name="input_eventbridge_rule_description"></a> [eventbridge\_rule\_description](#input\_eventbridge\_rule\_description) | Description for EventBridge rule | `string` | `"Captures IAM-related events for policy monitoring"` | no |
| <a name="input_force_destroy_athena"></a> [force\_destroy\_athena](#input\_force\_destroy\_athena) | Force destroy Athena database even if it contains tables/views (use with caution in production) | `bool` | `false` | no |
| <a name="input_force_destroy_logs"></a> [force\_destroy\_logs](#input\_force\_destroy\_logs) | Force destroy CloudWatch log groups even if they contain logs (use with caution in production) | `bool` | `false` | no |
| <a name="input_force_destroy_s3"></a> [force\_destroy\_s3](#input\_force\_destroy\_s3) | Force destroy S3 buckets even if they contain objects (use with caution in production) | `bool` | `false` | no |
| <a name="input_lambda_memory"></a> [lambda\_memory](#input\_lambda\_memory) | Default Lambda memory size in MB for detector and notification functions | `number` | `256` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | Lambda runtime version | `string` | `"python3.13"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | Lambda timeout in seconds | `number` | `300` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | CloudWatch logs retention period in days | `number` | `30` | no |
| <a name="input_name_prefix"></a> [name\_prefix](#input\_name\_prefix) | Prefix for all resource names | `string` | `"iam-policy-monitor"` | no |
| <a name="input_remediation_actions"></a> [remediation\_actions](#input\_remediation\_actions) | List of allowed remediation actions | `list(string)` | <pre>[<br/>  "delete_policy",<br/>  "detach_user_policy",<br/>  "detach_role_policy"<br/>]</pre> | no |
| <a name="input_remediator_memory_size"></a> [remediator\_memory\_size](#input\_remediator\_memory\_size) | Default Lambda memory size in MB for remediator function | `number` | `512` | no |
| <a name="input_severity_colors"></a> [severity\_colors](#input\_severity\_colors) | Map of severity levels to hex color codes for Slack notifications. Pass as a map, not jsonencode(). | `map(string)` | <pre>{<br/>  "CRITICAL": "#FF0000",<br/>  "HIGH": "#FF4500",<br/>  "INFO": "#D3D3D3",<br/>  "LOW": "#FFFF00",<br/>  "MEDIUM": "#FFA500"<br/>}</pre> | no |
| <a name="input_slack_webhook_parameter_name"></a> [slack\_webhook\_parameter\_name](#input\_slack\_webhook\_parameter\_name) | AWS Systems Manager Parameter Store path for Slack webhook URL (auto-generated if not provided) | `string` | `""` | no |
| <a name="input_slack_webhook_url"></a> [slack\_webhook\_url](#input\_slack\_webhook\_url) | Slack webhook URL for notifications (will be stored securely in Parameter Store) | `string` | `""` | no |
| <a name="input_sns_alert_email"></a> [sns\_alert\_email](#input\_sns\_alert\_email) | Optional email address for SNS alerts | `string` | `""` | no |
| <a name="input_sqs_message_retention"></a> [sqs\_message\_retention](#input\_sqs\_message\_retention) | SQS message retention period in seconds | `number` | `1209600` | no |
| <a name="input_sqs_visibility_timeout"></a> [sqs\_visibility\_timeout](#input\_sqs\_visibility\_timeout) | SQS message visibility timeout in seconds | `number` | `900` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Common tags to apply to all resources (alias for common\_tags) | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_athena_database_name"></a> [athena\_database\_name](#output\_athena\_database\_name) | Athena database name for violations |
| <a name="output_athena_results_bucket"></a> [athena\_results\_bucket](#output\_athena\_results\_bucket) | S3 bucket for Athena query results |
| <a name="output_athena_table_creator_function_name"></a> [athena\_table\_creator\_function\_name](#output\_athena\_table\_creator\_function\_name) | Name of the Lambda function that creates the Athena table automatically |
| <a name="output_athena_table_name"></a> [athena\_table\_name](#output\_athena\_table\_name) | Athena table name for violations (always 'violations' when enabled) |
| <a name="output_audit_logger_lambda_arn"></a> [audit\_logger\_lambda\_arn](#output\_audit\_logger\_lambda\_arn) | Audit Logger Lambda ARN |
| <a name="output_audit_logger_role_arn"></a> [audit\_logger\_role\_arn](#output\_audit\_logger\_role\_arn) | IAM role ARN for Audit Logger Lambda |
| <a name="output_bedrock_model_arn_for_analysis"></a> [bedrock\_model\_arn\_for\_analysis](#output\_bedrock\_model\_arn\_for\_analysis) | The ARN of the Bedrock model used for analysis. If plan/apply fails referencing this output, enable the model in the Bedrock console. |
| <a name="output_cloudwatch_dashboard_url"></a> [cloudwatch\_dashboard\_url](#output\_cloudwatch\_dashboard\_url) | URL to the CloudWatch dashboard |
| <a name="output_cloudwatch_log_group_detector"></a> [cloudwatch\_log\_group\_detector](#output\_cloudwatch\_log\_group\_detector) | CloudWatch Log Group for detector Lambda |
| <a name="output_cloudwatch_log_group_remediator"></a> [cloudwatch\_log\_group\_remediator](#output\_cloudwatch\_log\_group\_remediator) | CloudWatch Log Group for remediator Lambda |
| <a name="output_codebuild_project_arn"></a> [codebuild\_project\_arn](#output\_codebuild\_project\_arn) | ARN of the CodeBuild project for manual testing |
| <a name="output_codebuild_project_name"></a> [codebuild\_project\_name](#output\_codebuild\_project\_name) | Name of the CodeBuild project for manual testing |
| <a name="output_config_files_used"></a> [config\_files\_used](#output\_config\_files\_used) | Map of configuration files actually used by the module |
| <a name="output_detector_lambda_arn"></a> [detector\_lambda\_arn](#output\_detector\_lambda\_arn) | IAM Detector Lambda ARN |
| <a name="output_detector_lambda_name"></a> [detector\_lambda\_name](#output\_detector\_lambda\_name) | IAM Detector Lambda function name |
| <a name="output_detector_role_arn"></a> [detector\_role\_arn](#output\_detector\_role\_arn) | IAM role ARN for Detector Lambda |
| <a name="output_eventbridge_bus_arn"></a> [eventbridge\_bus\_arn](#output\_eventbridge\_bus\_arn) | EventBridge Bus ARN for IAM violations |
| <a name="output_eventbridge_bus_name"></a> [eventbridge\_bus\_name](#output\_eventbridge\_bus\_name) | EventBridge Bus name for IAM violations |
| <a name="output_eventbridge_dlq_arn"></a> [eventbridge\_dlq\_arn](#output\_eventbridge\_dlq\_arn) | EventBridge Dead Letter Queue ARN |
| <a name="output_eventbridge_rule_arn"></a> [eventbridge\_rule\_arn](#output\_eventbridge\_rule\_arn) | EventBridge Rule ARN |
| <a name="output_eventbridge_rule_name"></a> [eventbridge\_rule\_name](#output\_eventbridge\_rule\_name) | EventBridge Rule name |
| <a name="output_metrics_namespace"></a> [metrics\_namespace](#output\_metrics\_namespace) | CloudWatch metrics namespace |
| <a name="output_metrics_publisher_lambda_arn"></a> [metrics\_publisher\_lambda\_arn](#output\_metrics\_publisher\_lambda\_arn) | Metrics Publisher Lambda ARN |
| <a name="output_metrics_publisher_role_arn"></a> [metrics\_publisher\_role\_arn](#output\_metrics\_publisher\_role\_arn) | IAM role ARN for Metrics Publisher Lambda |
| <a name="output_name_prefix"></a> [name\_prefix](#output\_name\_prefix) | Name prefix used for all resources |
| <a name="output_notification_config_s3_key"></a> [notification\_config\_s3\_key](#output\_notification\_config\_s3\_key) | S3 key for notification configuration |
| <a name="output_priority_sns_topic_arn"></a> [priority\_sns\_topic\_arn](#output\_priority\_sns\_topic\_arn) | Priority SNS Topic ARN for high severity violations |
| <a name="output_remediation_metric_name"></a> [remediation\_metric\_name](#output\_remediation\_metric\_name) | CloudWatch metric name for remediation |
| <a name="output_remediator_config_s3_key"></a> [remediator\_config\_s3\_key](#output\_remediator\_config\_s3\_key) | S3 key for remediator configuration |
| <a name="output_remediator_lambda_arn"></a> [remediator\_lambda\_arn](#output\_remediator\_lambda\_arn) | IAM Remediator Lambda ARN |
| <a name="output_remediator_lambda_name"></a> [remediator\_lambda\_name](#output\_remediator\_lambda\_name) | IAM Remediator Lambda function name |
| <a name="output_remediator_role_arn"></a> [remediator\_role\_arn](#output\_remediator\_role\_arn) | IAM role ARN for Remediator Lambda |
| <a name="output_rules_bucket_arn"></a> [rules\_bucket\_arn](#output\_rules\_bucket\_arn) | ARN of S3 bucket for rules and logs |
| <a name="output_rules_bucket_name"></a> [rules\_bucket\_name](#output\_rules\_bucket\_name) | S3 bucket for rules and logs |
| <a name="output_rules_s3_key"></a> [rules\_s3\_key](#output\_rules\_s3\_key) | S3 key for rules configuration |
| <a name="output_slack_handler_lambda_arn"></a> [slack\_handler\_lambda\_arn](#output\_slack\_handler\_lambda\_arn) | Slack Handler Lambda ARN |
| <a name="output_slack_handler_role_arn"></a> [slack\_handler\_role\_arn](#output\_slack\_handler\_role\_arn) | IAM role ARN for Slack Handler Lambda |
| <a name="output_slack_webhook_parameter_name"></a> [slack\_webhook\_parameter\_name](#output\_slack\_webhook\_parameter\_name) | AWS Systems Manager Parameter Store path for Slack webhook URL |
| <a name="output_sns_publisher_lambda_arn"></a> [sns\_publisher\_lambda\_arn](#output\_sns\_publisher\_lambda\_arn) | SNS Publisher Lambda ARN |
| <a name="output_sns_publisher_role_arn"></a> [sns\_publisher\_role\_arn](#output\_sns\_publisher\_role\_arn) | IAM role ARN for SNS Publisher Lambda |
| <a name="output_sns_topic_arn"></a> [sns\_topic\_arn](#output\_sns\_topic\_arn) | SNS Topic ARN |
| <a name="output_sns_topic_name"></a> [sns\_topic\_name](#output\_sns\_topic\_name) | SNS Topic name |
| <a name="output_sqs_queue_arn"></a> [sqs\_queue\_arn](#output\_sqs\_queue\_arn) | SQS Queue ARN for remediation |
| <a name="output_sqs_queue_url"></a> [sqs\_queue\_url](#output\_sqs\_queue\_url) | SQS Queue URL for remediation |
| <a name="output_suppress_s3_key"></a> [suppress\_s3\_key](#output\_suppress\_s3\_key) | S3 key for suppression configuration |
| <a name="output_testing_log_group_name"></a> [testing\_log\_group\_name](#output\_testing\_log\_group\_name) | CloudWatch log group name for manual testing |
| <a name="output_violation_metric_name"></a> [violation\_metric\_name](#output\_violation\_metric\_name) | CloudWatch metric name for violations |
<!-- END_TF_DOCS -->