# Minimal IAM Policy Monitor Example
# This is the absolute simplest deployment - monitoring only, no changes

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

# Using us-east-1 for IAM monitoring as CloudTrail global events originate here
# and it has the most comprehensive AWS service availability
provider "aws" {
  region = "us-east-1"
}

# Generate a random suffix for uniqueness
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  name = "minimal-example-${random_string.suffix.result}"
  tags = {
    Environment = "development"
    Project     = "terraform-aws-iam-policy-guard-minimal"
    Owner       = "terraform"
    Example     = "minimal"
  }
}

# Minimal CloudTrail setup
module "cloudtrail" {
  source = "tfstack/cloudtrail/aws"
  name   = local.name

  # Enable CloudTrail and create the required S3 bucket
  create_s3_bucket = true

  # Force destroy for testing - allows easy cleanup
  s3_bucket_force_destroy = true

  # Minimal S3 lifecycle: expire logs quickly to stay under free tier (5GB/month)
  s3_bucket_lifecycle_configuration = [
    {
      id     = "free-tier-expire-fast"
      status = "Enabled"
      filter = {
        prefix = "" # Or use "AWSLogs/" depending on your CloudTrail config
      }
      expiration = {
        days = 3
      }
    }
  ]

  # Disable optional features that incur cost
  create_cloudwatch_log_group = false
  create_kms_key              = false
  create_sns_topic            = false

  tags = local.tags
}

# MINIMAL monitoring - detection and logging only
module "iam_policy_monitor" {
  source = "../../"

  # Required
  name_prefix     = local.name
  sns_alert_email = var.alert_email

  # MINIMAL features only
  enable_remediation          = false
  enable_slack_alerts         = false
  enable_priority_alerts      = false
  enable_cloudwatch_dashboard = true
  enable_athena_table         = false

  # Enable AI-powered risk analysis
  enable_bedrock_analysis = true
  bedrock_model_id        = "anthropic.claude-3-sonnet-20240229-v1:0"

  # Quick cleanup for testing
  log_retention_days = 3
  force_destroy_logs = true
  force_destroy_s3   = true

  # Automated tests rely on remediation, which is disabled in this minimal example
  # Therefore, leave create_tests as false (default)
  # create_tests = false

  common_tags = {
    Environment = "test"
    Example     = "minimal"
  }
}

output "test_commands" {
  value = <<-EOT

    #################### 🧪 TESTING COMMANDS ####################

    🟢 [1] OPEN DASHBOARD
    https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${module.iam_policy_monitor.name_prefix}-dashboard

    EOT
}
