# ============================================================================
# IAM Policy Monitor - Automated Testing Infrastructure
# ============================================================================

# CloudWatch Log Group for CodeBuild
resource "aws_cloudwatch_log_group" "codebuild_testing" {
  count             = var.create_tests ? 1 : 0
  name              = "/aws/codebuild/${var.name_prefix}-iam-policy-monitor-tests"
  retention_in_days = var.log_retention_days

  tags = merge(var.common_tags, {
    Name      = "${var.name_prefix}-codebuild-testing-logs"
    Purpose   = "CodeBuild logs for IAM Policy Monitor testing"
    Component = "testing"
  })
}

# IAM Role for CodeBuild
resource "aws_iam_role" "codebuild_testing" {
  count = var.create_tests ? 1 : 0
  name  = "${var.name_prefix}-codebuild-testing-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name      = "${var.name_prefix}-codebuild-testing-role"
    Purpose   = "CodeBuild execution role for IAM Policy Monitor testing"
    Component = "testing"
  })
}

# IAM Policy for CodeBuild - CloudWatch Logs
resource "aws_iam_role_policy" "codebuild_testing_logs" {
  count = var.create_tests ? 1 : 0
  name  = "${var.name_prefix}-codebuild-testing-logs"
  role  = aws_iam_role.codebuild_testing[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.codebuild_testing[0].arn}:*"
        ]
      }
    ]
  })
}

# IAM Policy for CodeBuild - CloudWatch Metrics
resource "aws_iam_role_policy" "codebuild_testing_metrics" {
  count = var.create_tests ? 1 : 0
  name  = "${var.name_prefix}-codebuild-testing-metrics"
  role  = aws_iam_role.codebuild_testing[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "IAMPolicyMonitorTests"
          }
        }
      }
    ]
  })
}

# IAM Policy for CodeBuild - IAM Testing Permissions
resource "aws_iam_role_policy" "codebuild_testing_iam" {
  count = var.create_tests ? 1 : 0
  name  = "${var.name_prefix}-codebuild-testing-iam"
  role  = aws_iam_role.codebuild_testing[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:CreateGroup",
          "iam:DeleteGroup",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:AttachGroupPolicy",
          "iam:DetachGroupPolicy",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:PutGroupPolicy",
          "iam:DeleteUserPolicy",
          "iam:DeleteRolePolicy",
          "iam:DeleteGroupPolicy",
          "iam:GetUserPolicy",
          "iam:GetRolePolicy",
          "iam:GetGroupPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedGroupPolicies"
        ]
        Resource = [
          "arn:aws:iam::*:user/iam-monitor-test-user",
          "arn:aws:iam::*:role/iam-monitor-test-role",
          "arn:aws:iam::*:group/iam-monitor-test-group",
          "arn:aws:iam::*:policy/iam-monitor-test-policy",
          "arn:aws:iam::*:policy/CustomAdminPolicy"
        ]
      }
    ]
  })
}

# CodeBuild Project
resource "aws_codebuild_project" "iam_policy_monitor_tests" {
  count        = var.create_tests ? 1 : 0
  name         = "${var.name_prefix}-iam-policy-monitor-tests"
  description  = "Automated testing for IAM Policy Monitor"
  service_role = aws_iam_role.codebuild_testing[0].arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.codebuild_testing[0].name
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = file("${path.module}/templates/buildspec.yml")
  }

  tags = merge(var.common_tags, {
    Name      = "${var.name_prefix}-iam-policy-monitor-tests"
    Purpose   = "Automated testing for IAM Policy Monitor"
    Component = "testing"
  })
}

# Manual testing only - no scheduled triggers

# CloudWatch Alarm for Test Failures
resource "aws_cloudwatch_metric_alarm" "test_failures" {
  count               = var.create_tests ? 1 : 0
  alarm_name          = "${var.name_prefix}-iam-policy-monitor-test-failures"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EndToEndStatus"
  namespace           = "IAMPolicyMonitorTests"
  period              = 300
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Alarm if IAM Policy Monitor automated tests report a failure (EndToEndStatus < 1)"
  alarm_actions       = var.enable_sns_alerts && length(aws_sns_topic.alerts) > 0 ? [aws_sns_topic.alerts[0].arn] : []

  tags = merge(var.common_tags, {
    Name      = "${var.name_prefix}-test-failure-alarm"
    Purpose   = "Monitor IAM Policy Monitor test failures"
    Component = "testing"
  })
}
