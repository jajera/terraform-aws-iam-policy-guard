# Event-Driven IAM Policy Monitor Architecture

## 🏗️ **Overview**

This project implements an **event-driven architecture** for monitoring IAM policy violations in AWS. When violations are detected, events are published to EventBridge which triggers multiple specialized Lambda functions to handle different aspects of the response.

The infrastructure uses a **service-based Terraform organization** with clear separation of concerns across storage, messaging, compute, IAM, and monitoring resources.

## 📊 **Architecture Diagram**

```plaintext
🔍 CloudTrail Events
        ↓
┌─────────────────────────┐
│    🔍 Detector          │ ← AWS Lambda Function
│    Lambda Function      │   (Python 3.13 runtime)
│                         │
└─────────┬───────────────┘
          │ (routes by action type)
          ↓
    ┌─────────────┐          ┌─────────────────────────┐
    │  action=    │          │   📡 EventBridge        │ ← AWS EventBridge
    │  "alert"    ├─────────→│   Custom Bus            │   (Custom event bus)
    └─────────────┘          └─────────┬───────────────┘
          │                            │ (fan-out to handlers)
    ┌─────────────┐                    ↓
    │  action=    │         ┌──────────┼──────────┬──────────┬──────────┐
    │ "remediate" │         ↓          ↓          ↓          ↓          ↓
    └──────┬──────┘   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
           │          │📧 SNS   │ │💬 Slack │ │📝 Audit │ │📊Metrics│
           ↓          │Publisher│ │Handler  │ │ Logger  │ │Publisher│
   ┌─────────────────┐│ Lambda  │ │ Lambda  │ │ Lambda  │ │ Lambda  │
   │📬 SQS Queue     │└─────────┘ └─────────┘ └─────────┘ └─────────┘
   │ - Main Queue    │     │           │           │           │
   │ - Dead Letter Q │     ↓           ↓           ↓           ↓
   │ - 14-day retention   ┌─────┐   ┌─────┐   ┌─────┐   ┌─────────┐
   └─────────┬───────┘    │📧SNS│   │💬Slack│ │📁 S3│   │📈CloudWatch│
             │            │Topic│   │Webhook│ │Bucket│ │ Metrics │
             ↓            └─────┘   └─────┘   └─────┘   └─────────┘
     ┌─────────────────┐
     │  🛠️ Remediator   │ ← AWS Lambda Function
     │  Lambda Function │   (Automated IAM actions)
     │                  │   + Safety controls
     └─────────┬────────┘
               │
               ↓
     ┌─────────────────────────┐
     │ 🎯 AWS Resources        │
     │ - IAM DetachUserPolicy  │ ← AWS IAM API Calls
     │ - IAM DeletePolicy      │
     │ - IAM DeleteUserPolicy  │
     │ + S3 Audit Logs         │ ← AWS S3 Object
     │ + CloudWatch Metrics    │ ← AWS CloudWatch
     │ + SNS Notifications     │ ← AWS SNS Topic
     │ + EventBridge Events    │ ← AWS EventBridge
     │ + Athena Queries        │ ← AWS Athena / Glue
     └─────────────────────────┘
```

## 🏛️ **Service-Based Infrastructure**

The Terraform infrastructure is organized into service-based modules for better maintainability:

### **File Structure**

```plaintext
├── main.tf          # Core data sources and locals (24 lines)
├── storage.tf       # S3 buckets, objects, Athena database (217 lines)
├── messaging.tf     # SNS, SQS, EventBridge (358 lines)
├── compute.tf       # Lambda functions and packaging (370 lines)
├── iam.tf          # Least-privilege IAM roles (500+ lines)
├── monitoring.tf    # CloudWatch logs, dashboards, alarms (456 lines)
├── variables.tf     # Input variables (156+ lines)
├── outputs.tf       # Output values (229 lines)
├── testing.tf       # On-demand CodeBuild test stack (≈250 lines)
└── versions.tf      # Provider requirements (19 lines)
```

### **AWS Service Boundaries**

- **Storage** (`storage.tf`):
  - `aws_s3_bucket.rules_and_logs` - Configuration files and audit logs
  - `aws_s3_bucket.athena_results` - Athena query results (conditional: `enable_athena_table`)
  - `aws_s3_object.rules`, `aws_s3_object.suppress` - Policy rules and suppression patterns
  - `aws_s3_object.notification_config`, `aws_s3_object.remediator_config` - Configuration files
  - `aws_athena_database.violations` - Query interface for audit logs (conditional: `enable_athena_table`)
  - `aws_lambda_invocation.create_athena_table` - Initial table creation trigger (conditional)
  - `aws_cloudwatch_event_rule.analytics_schedule` - Hourly analytics scheduler (conditional)
  - `aws_cloudwatch_event_target.analytics_scheduler` - EventBridge target for analytics (conditional)
  - `aws_lambda_permission.analytics_scheduler_eventbridge` - EventBridge permissions (conditional)
- **Messaging** (`messaging.tf`):
  - `aws_sns_topic.alerts`, `aws_sns_topic.priority_alerts` - Email/SMS notifications (conditional)
  - `aws_sqs_queue.remediation`, `aws_sqs_queue.remediation_dlq` - Remediation queuing (conditional: `enable_remediation`)
  - `aws_cloudwatch_event_bus.iam_violations` - Custom event bus with rules/targets
  - `aws_cloudwatch_event_rule.iam_violations` - All violation events
  - `aws_cloudwatch_event_rule.high_severity_violations` - HIGH/CRITICAL only (conditional: `enable_priority_alerts`)
  - `aws_cloudwatch_event_rule.remediation_status` - Remediation status events
  - `aws_sqs_queue.eventbridge_dlq` - EventBridge dead letter queue
- **Compute** (`compute.tf`):
  - 8 x `aws_lambda_function.*` - Event-driven serverless functions (some conditional)
  - `aws_s3_object.lambda_package` - Unified deployment package
  - `data.archive_file.lambda_package` - Fallback package creation
- **IAM** (`iam.tf`):
  - 8 x `aws_iam_role.*` - Separate least-privilege roles per Lambda (some conditional)
  - 8 x `aws_iam_role_policy.*` - Service-specific permissions
- **Monitoring** (`monitoring.tf`):
  - 8 x `aws_cloudwatch_log_group.*` - Lambda function logs (some conditional)
  - `aws_cloudwatch_dashboard.iam_policy_monitor` - Operational dashboard
  - 6+ x `aws_cloudwatch_metric_alarm.*` - Alerting thresholds including analytics alarms
  - 3 x `aws_cloudwatch_composite_alarm.*` - System health monitoring

## 🔧 **AWS Components**

### 1. **🔍 Detector Lambda Function** (`detector.py`)

- **AWS Resource**: `aws_lambda_function.detector`
- **Runtime**: Python 3.13 (configurable), 256MB memory, 300s timeout
- **Purpose**: Core violation detection engine
- **Trigger**: AWS EventBridge rule (`iam_events`) from CloudTrail
- **IAM Role**: `aws_iam_role.detector` - S3 read (config), EventBridge publish, SQS send, CloudWatch metrics, IAM GetPolicy*
- **Environment Variables**:
  - `RULES_BUCKET`, `RULES_KEY`, `SUPPRESS_KEY`
  - `EVENTBRIDGE_BUS_NAME`, `SQS_QUEUE_URL`
  - `USE_EVENTBRIDGE`, `ENABLE_REMEDIATION`, `DEBUG`
- **Actions**:
  - Analyzes IAM events against policy rules from S3
  - Routes to EventBridge (alerts) or SQS (remediation)
  - Publishes alert events for both alert and remediate actions
  - Fallback to direct notifications if EventBridge fails

### 2. **📡 EventBridge Custom Bus** (`messaging.tf`)

- **AWS Resource**: `aws_cloudwatch_event_bus.iam_violations`
- **Name**: `${name_prefix}-iam-violations`
- **Purpose**: Central event routing and filtering for notifications
- **Event Rules**:
  - `aws_cloudwatch_event_rule.iam_violations` - All violation events (`"IAM Policy Violation"`)
  - `aws_cloudwatch_event_rule.high_severity_violations` - HIGH/CRITICAL only (conditional)
  - `aws_cloudwatch_event_rule.remediation_status` - Remediation status events (`"IAM Policy Remediation Status"`)
- **Features**:
  - Event patterns for different severity levels
  - Priority routing for HIGH/CRITICAL violations
  - Dead letter queue: `aws_sqs_queue.eventbridge_dlq`
  - Lambda permissions for all targets
  - Remediation status event routing

### 3. **📧 SNS Publisher Lambda Function** (`sns_publisher.py`)

- **AWS Resource**: `aws_lambda_function.sns_publisher[0]` (conditional: `enable_sns_alerts`)
- **Runtime**: Python 3.13, 256MB memory, 300s timeout
- **Purpose**: Email/SMS notifications via SNS
- **Trigger**: AWS EventBridge rule (`iam_violations` AND `remediation_status`)
- **IAM Role**: `aws_iam_role.sns_publisher` - SNS publish to specific topic only
- **Target**: `aws_sns_topic.alerts[0]`
- **Features**:
  - Handles both violation and remediation status events
  - Formatted email alerts with severity and rule name
  - Detailed violation information in email body
  - Subject line customization

### 4. **💬 Slack Handler Lambda Function** (`slack_handler.py`)

- **AWS Resource**: `aws_lambda_function.slack_handler[0]` (conditional: `enable_slack_alerts`)
- **Runtime**: Python 3.13, 256MB memory, 300s timeout
- **Purpose**: Rich Slack notifications
- **Trigger**: AWS EventBridge rule (`iam_violations` AND `remediation_status`)
- **IAM Role**: `aws_iam_role.slack_handler` - S3 read (notification config), SSM parameter access
- **Configuration**: S3 object `notification-config.yaml`, Parameter Store webhook URL
- **Features**:
  - Color-coded messages by severity (🚨🟠🟡🔵)
  - Handles both violation and remediation events
  - Configurable field mappings via S3
  - Exponential backoff for reliability
  - Rate limiting support

### 5. **📝 Audit Logger Lambda Function** (`audit_logger.py`)

- **AWS Resource**: `aws_lambda_function.audit_logger` (always enabled)
- **Runtime**: Python 3.13, 256MB memory, 300s timeout
- **Purpose**: Compliance audit trail
- **Trigger**: AWS EventBridge rule (`iam_violations` AND `remediation_status`)
- **IAM Role**: `aws_iam_role.audit_logger` - S3 write to `audit-logs/*` prefix only
- **Storage**: `aws_s3_bucket.rules_and_logs` with partitioned paths
- **Features**:
  - Hierarchical S3 partitioning: `year=YYYY/month=MM/day=DD/hour=HH/`
  - Athena-compatible JSON format
  - Metadata tagging for searchability
  - Compliance-ready audit records
  - Handles both violation and remediation events

### 6. **📊 Metrics Publisher Lambda Function** (`metrics_publisher.py`)

- **AWS Resource**: `aws_lambda_function.metrics_publisher` (always enabled)
- **Runtime**: Python 3.13, 256MB memory, 300s timeout
- **Purpose**: CloudWatch metrics and monitoring
- **Trigger**: AWS EventBridge rule (`iam_violations` AND `remediation_status`)
- **IAM Role**: `aws_iam_role.metrics_publisher` - CloudWatch metrics to `IAMPolicyMonitor` namespace
- **Target**: AWS CloudWatch custom metrics
- **Features**:
  - Multi-dimensional metrics by severity/rule/action
  - Violation count tracking with timestamps
  - User/event pattern analysis
  - Risk score trending and anomaly detection
  - Remediation success/failure metrics

### 7. **🏗️ Athena Table Creator Lambda Function** (`athena_table_creator.py`) - Optional

- **AWS Resource**: `aws_lambda_function.athena_table_creator[0]` (conditional: `enable_athena_table`)
- **Runtime**: Python 3.13, 512MB memory, 300s timeout
- **Purpose**: Automated Athena analytics engine for security intelligence
- **Trigger**: Lambda invocation (initial setup) + EventBridge rule (hourly analytics)
- **IAM Role**: `aws_iam_role.athena_table_creator` - Athena queries, Glue catalog, S3 read/write, CloudWatch metrics
- **Configuration**: Uses S3 audit logs from `aws_s3_bucket.rules_and_logs`
- **Features**:
  - **Automated Setup**: Creates violations table and analytics views automatically
  - **Security Analytics**: Detects high-risk principals, attack patterns, violation trends
  - **Threat Intelligence**: Identifies coordinated policy manipulation attempts
  - **CloudWatch Integration**: Publishes analytics metrics to `IAMPolicyMonitor/Analytics` namespace
  - **Views Created**:
    - `violation_trends` - 30-day violation patterns and anomalies
    - `high_risk_principals` - Principals with >3 violations or >2 rule types
    - `policy_attack_patterns` - Coordinated attacks (>5 modifications or >2 source IPs)

### 8. **⏰ Analytics Scheduler Lambda Function** (`athena_table_creator.py`) - Optional

- **AWS Resource**: `aws_lambda_function.analytics_scheduler[0]` (conditional: `enable_athena_table`)
- **Runtime**: Python 3.13, 256MB memory, 300s timeout
- **Purpose**: Hourly execution of security analytics queries
- **Trigger**: EventBridge rule (`analytics_schedule`) - runs every hour
- **IAM Role**: `aws_iam_role.analytics_scheduler` - Same permissions as table creator
- **Handler**: `athena_table_creator.lambda_handler` (shared code with different entry point)
- **Features**:
  - **Continuous Analysis**: Runs security analytics every hour automatically
  - **Proactive Alerting**: Publishes CloudWatch metrics for immediate alerting
  - **Zero Manual Work**: Fully automated security intelligence pipeline

### 9. **🛠️ Remediator Lambda Function** (`remediator.py`) - Optional

- **AWS Resource**: `aws_lambda_function.remediator[0]` (conditional: `enable_remediation`)
- **Runtime**: Python 3.13, 512MB memory, 300s timeout
- **Purpose**: Automated policy remediation with comprehensive safety controls
- **Trigger**: AWS SQS queue (`aws_sqs_queue.remediation[0]`)
- **IAM Role**: `aws_iam_role.remediator` - Restricted IAM actions, SQS access, S3 audit logging, EventBridge publish
- **Dead Letter Queue**: `aws_sqs_queue.remediation_dlq[0]`
- **Configuration**: S3 object `remediator-config.json`
- **Features**:
  - **Automated Actions**: IAM DetachUserPolicy, DeletePolicy, DeleteUserPolicy
  - **Enhanced**: DetachGroupPolicy & ListEntitiesForPolicy to clean up customer-managed policies
  - **Idempotent**: Treats *NoSuchEntity* errors (policy already gone) as successful remediation
  - **Safety Controls**: Configurable exclusion of principals (users/roles) and policies using wildcards.
  - Dry-run Mode: Test remediation via `DRY_RUN` environment variable
  - Audit Trail: S3 logging with partitioning + CloudWatch metrics + SNS notifications
  - Configuration-Driven: S3-based allow-list for permitted actions
- EventBridge Integration: Publishes remediation status events for full workflow tracking

### 10. **📬 SQS Remediation Queue** (`messaging.tf`)

- **AWS Resource**: `aws_sqs_queue.remediation[0]` (conditional: `enable_remediation`)
- **Name**: `${name_prefix}-remediation`
- **Purpose**: Reliable queuing for remediation actions
- **Configuration**:
  - Message retention: 14 days (1,209,600 seconds)
  - Visibility timeout: 300 seconds (matches Lambda timeout)
  - Batch size: 10 messages per Lambda invocation
- **Dead Letter Queue**: `aws_sqs_queue.remediation_dlq[0]` (max 3 retries)
- **Event Source Mapping**: `aws_lambda_event_source_mapping.remediator_sqs[0]`

### 11. **📧 SNS Topics** (`messaging.tf`)

- **Regular Alerts**: `aws_sns_topic.alerts[0]` (conditional: `enable_sns_alerts`)
  - Purpose: Detailed email notifications for all violations AND remediation status
  - Subscription: `aws_sns_topic_subscription.email_alerts[0]` (conditional)
- **Priority Alerts**: `aws_sns_topic.priority_alerts[0]` (conditional: `enable_priority_alerts`)
  - Purpose: Immediate SMS/pager alerts for HIGH/CRITICAL violations
  - Direct EventBridge target (no Lambda processing delay)

### 12. **📁 S3 Bucket** (`storage.tf`)

- **AWS Resource**: `aws_s3_bucket.rules_and_logs`
- **Name**: `${bucket_name}` or auto-generated based on account/region
- **Purpose**: Configuration storage and audit logging
- **Objects**:
  - `rules.yaml` - Violation detection rules
  - `suppress.yaml` - Suppression patterns
  - `notification-config.yaml` - Slack/SNS formatting
  - `remediator-config.json` - Remediation configuration
- **Audit Paths**:
  - `audit-logs/` - Violation audit trail
  - `remediation/` - Remediation action logs (via remediator)

### 13. **📊 Athena Database** (`storage.tf`) - Optional

- **AWS Resource**: `aws_athena_database.violations[0]` (conditional: `enable_athena_table`)
- **Purpose**: Historical analysis and compliance reporting
- **Features**:
  - `aws_s3_bucket.athena_results[0]` - Separate bucket for query results
  - `aws_athena_named_query.violations_table[0]` - Pre-built table creation query
  - Partitioned by year/month/day for performance
  - Athena-compatible JSON format in S3

## 🛠️ **Remediation System Architecture**

The remediation system provides automated response capabilities for IAM policy violations while maintaining strict safety controls and comprehensive audit trails.

### **Enhanced Remediation Flow with Status Events**

```plaintext
┌─────────────────────────────┐
│ 1. 🔍 Detector              │ ← aws_lambda_function.detector
│    Lambda Function          │   Analyzes IAM events against rules
│    (Python 3.13)            │
└─────────────┬───────────────┘
              │
              ↓
       ┌─────────────────┐
       │ 2. Action Router│ ← Business logic in detector.py
       └─────┬─────┬─────┘
             │     │
        action=    │ action="alert"
      "remediate"  │
             │     ↓
             │ ┌─────────────────────────────┐      ┌─────────────────────────────┐
             │ │ 3a. 📡 EventBridge          │─────→│ 4a. 🔔 Notification         │
             │ │    Custom Bus               │      │    Lambda Functions         │
             │ │    (iam-violations)         │      │    - sns_publisher          │
             │ └─────────────────────────────┘      │    - slack_handler          │
             │                                      │    - audit_logger           │
             ↓                                      │    - metrics_publisher      │
       ┌─────────────────────────────┐              └─────────────────────────────┘
       │ 3b. 📬 SQS Queue             │ ← aws_sqs_queue.remediation[0]
       │    - Main Queue              │   Reliable message queuing
       │    - Dead Letter Queue       │
       │    - 14-day retention        │
       │    - 300s visibility timeout │
       └─────────────┬───────────────┘
                     │
                     ↓
       ┌─────────────────────────────┐
       │ 4b. 🛠️ Remediator            │ ← aws_lambda_function.remediator[0]
       │    Lambda Function           │   (Python 3.13, 512MB, 300s timeout)
       │    (Safety-Controlled)       │
       │                             │
       │ ┌─────────────────────────┐ │      ┌─────────────────────────────┐
       │ │📁 S3 Config Loader     │─┼─────→│ 5. 🛡️ Safety Validation      │
       │ │  remediator-config.json │ │      │   - Critical roles protected│
       │ └─────────────────────────┘ │      │   - Root user excluded      │
       │ ┌─────────────────────────┐ │      │   - Admin policies blocked  │
       │ │🔒 Safety Checks        │ │      │   - Allowed actions list    │
       │ └─────────────────────────┘ │      └─────────────────────────────┘
       │ ┌─────────────────────────┐ │
       │ │⚡ AWS IAM API Actions   │ │ ← iam:DetachUserPolicy
       │ │  - DetachUserPolicy     │ │   iam:DeletePolicy
       │ │  - DeletePolicy         │ │   iam:DeleteUserPolicy
       │ │  - DeleteUserPolicy     │ │
       │ └─────────────────────────┘ │
       └─────────────┬───────────────┘
                     │
                     ↓
       ┌─────────────────────────────┐
       │ 6. 📋 EventBridge Status     │ ← Remediation status events
       │ ┌─────────────────────────┐ │
       │ │📡 EventBridge Publisher │ │ ← "iam.policy.remediator" source
       │ │  "IAM Policy Remediation│ │   "IAM Policy Remediation Status"
       │ │   Status" events        │ │
       │ └─────────────────────────┘ │
       └─────────────┬───────────────┘
                     │
                     ↓
       ┌─────────────────────────────┐
       │ 7. 📋 Audit Trail            │
       │ ┌─────────────────────────┐ │
       │ │📁 S3 Partitioned Logs  │ │ ← aws_s3_bucket.rules_and_logs
       │ │  year=YYYY/month=MM/... │ │   /audit-logs/* path
       │ └─────────────────────────┘ │
       │ ┌─────────────────────────┐ │
       │ │📈 CloudWatch Metrics    │ │ ← aws_cloudwatch (IAMPolicyMonitor)
       │ │  RemediationSuccess/Fail│ │   Custom metrics namespace
       │ └─────────────────────────┘ │
       │ ┌─────────────────────────┐ │
       │ │📧 SNS Notifications     │ │ ← aws_sns_topic.alerts[0]
       │ │  Remediation results    │ │   Email alerts for actions taken
       │ └─────────────────────────┘ │
       │ ┌─────────────────────────┐ │
       │ │💬 Slack Notifications   │ │ ← Slack Handler Lambda
       │ │  Remediation status     │ │   Rich status messages
       │ └─────────────────────────┘ │
       └─────────────────────────────┘
```

## 🔄 **Event Flow**

### **Violation Detection Flow**

1. **CloudTrail** captures IAM API calls
2. **EventBridge rule** (`iam_events`) triggers **Detector Lambda**
3. **Detector** analyzes event against policy rules from S3
4. **Action-based routing** determines response type:

#### **Alert Path** (`action: "alert"`)

5a. Publishes `ViolationEvent` to **Custom EventBridge Bus**
6a. EventBridge routes event to notification handlers based on patterns
7a. Handlers process events in parallel (SNS, Slack, Audit, Metrics)

#### **Remediation Path** (`action: "remediate"`)

5b. Queues `RemediationMessage` to **SQS Remediation Queue**
5c. Also publishes `ViolationEvent` to EventBridge (for immediate alerting)
6b. Remediator Lambda processes queue with safety validations
7b. IAM Actions executed (detach/delete policies) with full audit trail
8b. EventBridge Status Events published for remediation completion

### **Event Schema**

#### **Violation Events**

```json
{
  "source": "iam.policy.monitor",
  "detail-type": "IAM Policy Violation",
  "detail": {
    "eventId": "uuid",
    "timestamp": "2024-01-01T12:00:00Z",
    "correlationId": "uuid",
    "violation": {
      "rule_name": "DangerousInlinePolicy",
      "severity": "HIGH",
      "description": "...",
      "category": "Policy"
    },
    "originalEvent": { /* CloudTrail event */ }
  }
}
```

#### **Remediation Status Events**

```json
{
  "source": "iam.policy.remediator",
  "detail-type": "IAM Policy Remediation Status",
  "detail": {
    "timestamp": "2024-01-01T12:00:00Z",
    "correlationId": "uuid",
    "remediation": {
      "rule_name": "DangerousInlinePolicy",
      "status": "SUCCESS|FAILED",
      "action": "delete_inline_policy",
      "severity": "HIGH",
      "description": "Remediation completed",
      "details": { /* remediation specifics */ },
      "error": null
    },
    "originalViolation": { /* original violation data */ },
    "originalEvent": { /* original CloudTrail event */ }
  }
}
```

### **Handler Routing**

#### **Notification Handlers** (EventBridge-triggered)

- **SNS Publisher**: ALL violations + remediation status (if `enable_sns_alerts = true`)
- **Slack Handler**: ALL violations + remediation status (if `enable_slack_alerts = true`)
- **Audit Logger**: ALL violations + remediation status (always enabled for compliance)
- **Metrics Publisher**: ALL violations + remediation status (always enabled for monitoring)
- **Priority SNS**: HIGH/CRITICAL violations only (if `enable_priority_alerts = true`)

#### **Remediation Handler** (SQS-triggered)

- **Remediator Lambda**: Violations requiring automated response (if `enable_remediation = true`)
  - **Safety Checks**: Critical role protection, root user exclusion
  - **Allowed Actions**: Configurable via S3 (`remediator-config.json`)
  - **Audit Trail**: S3 logging + CloudWatch metrics + SNS notifications + EventBridge status events

## 📊 **Monitoring & Observability**

### **CloudWatch Resources** (`monitoring.tf`)

- **8 Log Groups**: One per Lambda function with configurable retention (some conditional)
- **Dashboard**: `${name_prefix}-dashboard` with 3 widgets
- **6+ Alarms**: High violations, critical violations, Lambda errors, EventBridge failures, analytics alarms

### **CloudWatch Metrics**

- `IAMPolicyMonitor/ViolationCount` by severity
- `IAMPolicyMonitor/RemediationAction` by action type
- `IAMPolicyMonitor/Analytics/HighRiskPrincipals` - Count of suspicious accounts
- `IAMPolicyMonitor/Analytics/PotentialAttacks` - Coordinated attack detection
- `IAMPolicyMonitor/Analytics/ViolationTrends_CRITICAL` - Critical violation patterns
- `IAMPolicyMonitor/Analytics/ViolationTrends_HIGH` - High severity violation patterns
- `IAMPolicyMonitor/Analytics/ViolationTrends_MEDIUM` - Medium severity violation patterns
- `IAMPolicyMonitorTests/EndToEndStatus` 0 = build failed, 1 = all tests passed (emitted by CodeBuild)
- Lambda function metrics (duration, errors, invocations)
- EventBridge rule metrics

### **Dashboard Widgets**

1. **Violations by Severity**: LOW, MEDIUM, HIGH, CRITICAL
2. **Lambda Metrics**: Duration, errors, invocations for detector function
3. **Remediation Actions**: PolicyDetached, PolicyDeleted, RoleModified, UserRemoved
4. **Analytics Intelligence**: High-risk principals, potential attacks, violation trends (when Athena enabled)

### **Alarms**

- **High Violations**: >10 HIGH severity violations in 5 minutes
- **Critical Violations**: Any CRITICAL severity violation
- **Lambda Errors**: >5 errors in 5 minutes
- **EventBridge Failures**: >3 failed invocations in 5 minutes
- **High Risk Principals**: >5 principals showing suspicious activity patterns (when Athena enabled)
- **Potential Attacks**: >2 coordinated policy manipulation attempts detected (when Athena enabled)
- **Critical Violation Trends**: >10 critical violations per hour (when Athena enabled)

### **Testing Infrastructure** (`testing.tf`)

| Component | Description |
|-----------|-------------|
| **CodeBuild Project** | `${name_prefix}-iam-policy-monitor-tests`, invoked manually to run end-to-end tests via `buildspec.yml`. |
| **IAM Role** | Least-privilege: CloudWatch Logs, `cloudwatch:PutMetricData` (namespace-scoped) and IAM actions strictly limited to test resources. |
| **Buildspec Highlights** | Polls every 5 s until detector/remediator finish (max 60 s each), prints JSON summary, and publishes pass/fail metric (`EndToEndStatus`). |
| **Metric Alarm** | Optional CloudWatch alarm on `EndToEndStatus==0` for immediate visibility of failed test runs. |
| **Terraform Mock Tests** | Local-only tests defined in `tests/iam-policy-guard.tftest.hcl` that use `mock_provider` to validate the plan without creating real AWS resources. Ideal for CI. |

## 🚀 **Deployment**

### **Prerequisites**

```bash
# Build unified Lambda package with all functions
./lambdas/build-lambda-packages.sh

# Deploy infrastructure
terraform init
terraform plan
terraform apply
```

### **Package Contents**

The build script creates a unified package containing:

- All 8 Lambda function modules:
  - `detector.py` - Core violation detection
  - `remediator.py` - Automated policy remediation (optional)
  - `sns_publisher.py` - Email/SMS notifications (optional)
  - `slack_handler.py` - Slack notifications (optional)
  - `audit_logger.py` - Compliance audit trail
  - `metrics_publisher.py` - CloudWatch metrics
  - `athena_table_creator.py` - Analytics engine (optional)
  - `violation_event.py` - Shared event utilities
- Optimized dependencies (PyYAML, requests)
- Excludes boto3/botocore (provided by AWS runtime)

### **Configuration Files**

- `templates/rules.yaml`: Violation detection rules
- `templates/suppress.yaml`: Suppression patterns
- `templates/notification-config.yaml`: Slack/SNS formatting
- `templates/remediator-config.json`: Remediation configuration

This architecture provides a robust, scalable foundation for IAM policy monitoring with excellent separation of concerns, comprehensive security, and full observability.
