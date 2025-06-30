# Basic Terraform Test for IAM Policy Guard Module
# This test validates configuration syntax and basic resource planning

variables {
  test_name_prefix = "tftest-iam-policy-guard"
  aws_region       = "us-east-1"
}

# Mock AWS provider to avoid real API calls
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/test"
      user_id    = "AIDABCDEFGHIJKLMN"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{}"
    }
  }
}

# -----------------------------------------------------------------------------

# Test configuration validation only (no actual AWS calls)
run "test_configuration_syntax" {
  command = plan

  variables {
    name_prefix = "${var.test_name_prefix}-syntax"

    # Minimal configuration to test syntax
    enable_slack_alerts     = false
    enable_bedrock_analysis = false
    enable_athena_table     = false
    create_tests            = false

    # Provide explicit bucket name to avoid auto-generation
    bucket_name = "test-bucket-12345"

    # Use minimal Lambda settings
    lambda_memory          = 128
    lambda_timeout         = 30
    remediator_memory_size = 128

    # Disable features that require AWS API calls
    enable_cloudwatch_dashboard = false
    enable_cloudwatch_alarms    = false
    enable_sns_alerts           = false

    common_tags = {
      Environment = "test"
      Purpose     = "syntax-validation"
    }
  }

  # Basic syntax validation - check if plan can be generated
  assert {
    condition     = length(var.name_prefix) > 0
    error_message = "Name prefix should be set"
  }

  assert {
    condition     = var.lambda_memory >= 128
    error_message = "Lambda memory should be at least 128 MB"
  }

  assert {
    condition     = var.lambda_timeout > 0
    error_message = "Lambda timeout should be positive"
  }
}

# Test variable validation
run "test_variable_validation" {
  command = plan

  variables {
    name_prefix = "${var.test_name_prefix}-vars"

    # Test variable constraints
    lambda_runtime         = "python3.13"
    lambda_memory          = 256
    lambda_timeout         = 60
    remediator_memory_size = 512

    # Test boolean variables
    enable_remediation = true
    dry_run_mode       = false
    debug_mode         = true

    # Test list variables
    remediation_actions = ["delete_policy", "detach_user_policy"]

    # Provide explicit bucket name
    bucket_name = "test-validation-bucket-67890"

    # Disable AWS-dependent features
    enable_cloudwatch_dashboard = false
    enable_cloudwatch_alarms    = false
    enable_sns_alerts           = false
    enable_slack_alerts         = false
    enable_athena_table         = false

    common_tags = {
      Environment = "test"
      Purpose     = "variable-validation"
      Owner       = "terraform-test"
    }
  }

  # Test that runtime validation works
  assert {
    condition     = can(regex("^python3\\.(\\d+)$", var.lambda_runtime))
    error_message = "Lambda runtime should be a valid Python version"
  }

  # Test that memory values are reasonable
  assert {
    condition     = var.lambda_memory >= 128 && var.lambda_memory <= 10240
    error_message = "Lambda memory should be between 128 and 10240 MB"
  }

  # Test that timeout is reasonable
  assert {
    condition     = var.lambda_timeout > 0 && var.lambda_timeout <= 900
    error_message = "Lambda timeout should be between 1 and 900 seconds"
  }

  # Test that remediation actions are valid
  assert {
    condition = alltrue([
      for action in var.remediation_actions :
      contains(["delete_policy", "detach_user_policy", "detach_role_policy", "quarantine_policy"], action)
    ])
    error_message = "All remediation actions should be valid"
  }
}

# Test different feature combinations
run "test_feature_combinations" {
  command = plan

  variables {
    name_prefix = "${var.test_name_prefix}-features"

    # Test with different feature flags
    enable_remediation      = true
    enable_slack_alerts     = false
    enable_bedrock_analysis = false
    enable_athena_table     = false

    # Test with custom settings
    lambda_runtime = "python3.13"
    lambda_memory  = 512
    lambda_timeout = 120

    # Provide explicit bucket name
    bucket_name = "test-features-bucket-99999"

    # Disable AWS-dependent features
    enable_cloudwatch_dashboard = false
    enable_cloudwatch_alarms    = false
    enable_sns_alerts           = false

    common_tags = {
      Environment = "development"
      Purpose     = "feature-testing"
      Team        = "security"
    }
  }

  # Test that configuration is internally consistent
  assert {
    condition     = var.enable_remediation == true
    error_message = "Remediation should be enabled for this test"
  }

  assert {
    condition     = length(var.common_tags) >= 3
    error_message = "Should have at least 3 tags defined"
  }

  assert {
    condition     = contains(keys(var.common_tags), "Environment")
    error_message = "Should have Environment tag"
  }
}

# -----------------------------------------------------------------------------
# Athena-specific check (enabled)
run "test_athena_enabled" {
  command = plan

  variables {
    name_prefix         = "iapg-athena-basic"
    enable_athena_table = true

    # Disable features unrelated to this check
    enable_slack_alerts     = false
    enable_bedrock_analysis = false
    create_tests            = false

    bucket_name = "tftest-athena-basic-bucket"

    # Keep config minimal & fast
    enable_cloudwatch_dashboard = false
    enable_cloudwatch_alarms    = false
    enable_sns_alerts           = false

    common_tags = {
      Environment = "test"
      Purpose     = "athena-check"
    }
  }

  assert {
    # Plan-time check: resource count should be 1 when Athena is enabled
    condition     = length(aws_athena_database.violations) == 1
    error_message = "Athena database should be created when enable_athena_table=true"
  }

  assert {
    # Plan-time check: Lambda count is 1 when Athena is enabled
    condition     = length(aws_lambda_function.athena_table_creator) == 1
    error_message = "Athena table-creator Lambda should exist when Athena is enabled"
  }
}

# -----------------------------------------------------------------------------
# Slack-specific check (enabled)
run "test_slack_enabled" {
  command = plan

  variables {
    name_prefix         = "${var.test_name_prefix}-slack-basic"
    enable_slack_alerts = true
    slack_webhook_url   = "https://hooks.slack.com/services/T000000/B000000/XXXXXX"

    enable_athena_table     = false
    enable_bedrock_analysis = false
    create_tests            = false

    bucket_name = "tftest-slack-basic-bucket"

    # Keep other features off for speed
    enable_cloudwatch_dashboard = false
    enable_cloudwatch_alarms    = false
    enable_sns_alerts           = false

    common_tags = {
      Environment = "test"
      Purpose     = "slack-check"
    }
  }

  assert {
    # Plan-time check: Slack handler Lambda count should be 1
    condition     = length(aws_lambda_function.slack_handler) == 1
    error_message = "Slack handler Lambda should be created when Slack alerts are enabled"
  }

  assert {
    # Plan-time check: SSM parameter count should be 1
    condition     = length(aws_ssm_parameter.slack_webhook) == 1
    error_message = "SSM parameter for Slack webhook should be created when Slack alerts are enabled"
  }
}

# -----------------------------------------------------------------------------
