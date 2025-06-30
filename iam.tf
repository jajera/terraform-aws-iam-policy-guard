# IAM Policy Monitor - IAM Roles and Policies
# Least-privilege IAM permissions for each Lambda function

# ===== COMMON RESOURCES =====

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ===== DETECTOR LAMBDA IAM =====

resource "aws_iam_role" "detector" {
  name               = "${var.name_prefix}-detector-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "detector" {
  name   = "${var.name_prefix}-detector-policy"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

data "aws_iam_policy_document" "detector" {
  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-detector*:*"]
  }

  statement {
    sid    = "AllowS3ReadOnly"
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = [
      "${aws_s3_bucket.rules_and_logs.arn}/rules.yaml",
      "${aws_s3_bucket.rules_and_logs.arn}/suppress.yaml"
    ]
  }

  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    actions = [
      "events:PutEvents"
    ]
    resources = [aws_cloudwatch_event_bus.iam_violations.arn]
  }

  dynamic "statement" {
    for_each = var.enable_remediation ? [1] : []
    content {
      sid       = "AllowSqsQueueing"
      effect    = "Allow"
      actions   = ["sqs:SendMessage"]
      resources = [aws_sqs_queue.remediation[0].arn]
    }
  }

  statement {
    sid    = "AllowIAMPermissions"
    effect = "Allow"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowS3AuditWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = ["${aws_s3_bucket.rules_and_logs.arn}/violations/*"]
  }

  statement {
    sid    = "AllowCloudWatchPublish"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["IAMPolicyMonitor"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_bedrock_analysis ? [1] : []
    content {
      sid    = "AllowBedrockInvocation"
      effect = "Allow"
      actions = [
        "bedrock:InvokeModel"
      ]
      resources = [
        "arn:aws:bedrock:${data.aws_region.current.region}::foundation-model/${var.bedrock_model_id}"
      ]
    }
  }
}

# ===== REMEDIATOR LAMBDA IAM =====

resource "aws_iam_role" "remediator" {
  count              = var.enable_remediation ? 1 : 0
  name               = "${var.name_prefix}-remediator-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "remediator" {
  count  = var.enable_remediation ? 1 : 0
  name   = "${var.name_prefix}-remediator-policy"
  role   = aws_iam_role.remediator[0].id
  policy = data.aws_iam_policy_document.remediator[0].json
}

data "aws_iam_policy_document" "remediator" {
  count = var.enable_remediation ? 1 : 0

  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-remediator*:*"]
  }

  statement {
    sid    = "AllowSqs"
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes"
    ]
    resources = [aws_sqs_queue.remediation[0].arn]
  }

  statement {
    sid    = "AllowS3ConfigRead"
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.rules_and_logs.arn}/remediator-config.json"]
  }

  statement {
    sid    = "AllowS3AuditWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = ["${aws_s3_bucket.rules_and_logs.arn}/remediation/*"]
  }

  statement {
    sid    = "AllowIamRemediation"
    effect = "Allow"
    actions = [
      "iam:DetachUserPolicy",
      "iam:DetachRolePolicy",
      "iam:DetachGroupPolicy",
      "iam:DeletePolicy",
      "iam:DeleteUserPolicy",
      "iam:DeleteRolePolicy"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowIamReadOnly"
    effect = "Allow"
    actions = [
      "iam:ListPolicyVersions",
      "iam:ListEntitiesForPolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetUser",
      "iam:GetRole"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    actions = [
      "events:PutEvents"
    ]
    resources = [aws_cloudwatch_event_bus.iam_violations.arn]
  }

  dynamic "statement" {
    for_each = var.enable_sns_alerts ? [1] : []
    content {
      sid       = "AllowSnsPublish"
      effect    = "Allow"
      actions   = ["sns:Publish"]
      resources = [aws_sns_topic.alerts[0].arn]
    }
  }

  statement {
    sid       = "CloudWatchMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData does not support resource-level permissions
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}


# ===== SNS PUBLISHER LAMBDA IAM =====

resource "aws_iam_role" "sns_publisher" {
  count              = var.enable_sns_alerts ? 1 : 0
  name               = "${var.name_prefix}-sns-publisher-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "sns_publisher" {
  count  = var.enable_sns_alerts ? 1 : 0
  name   = "${var.name_prefix}-sns-publisher-policy"
  role   = aws_iam_role.sns_publisher[0].id
  policy = data.aws_iam_policy_document.sns_publisher[0].json
}

data "aws_iam_policy_document" "sns_publisher" {
  count = var.enable_sns_alerts ? 1 : 0

  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-sns-publisher*:*"]
  }

  statement {
    sid    = "AllowSnsPublish"
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    resources = compact([
      aws_sns_topic.alerts[0].arn,
      var.enable_priority_alerts ? aws_sns_topic.priority_alerts[0].arn : null
    ])
  }
}

# ===== SLACK HANDLER LAMBDA IAM =====

resource "aws_iam_role" "slack_handler" {
  count              = var.enable_slack_alerts ? 1 : 0
  name               = "${var.name_prefix}-slack-handler-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "slack_handler" {
  count  = var.enable_slack_alerts ? 1 : 0
  name   = "${var.name_prefix}-slack-handler-policy"
  role   = aws_iam_role.slack_handler[0].id
  policy = data.aws_iam_policy_document.slack_handler[0].json
}

data "aws_iam_policy_document" "slack_handler" {
  count = var.enable_slack_alerts ? 1 : 0

  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-slack-handler*:*"]
  }

  statement {
    sid    = "AllowSsmParameterRead"
    effect = "Allow"
    actions = [
      "ssm:GetParameter"
    ]
    resources = ["arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/slack-webhook"]
  }

  statement {
    sid    = "AllowS3ConfigRead"
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.rules_and_logs.arn}/notification-config.yaml"]
  }
}

# ===== AUDIT LOGGER LAMBDA IAM =====

resource "aws_iam_role" "audit_logger" {
  name               = "${var.name_prefix}-audit-logger-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "audit_logger" {
  name   = "${var.name_prefix}-audit-logger-policy"
  role   = aws_iam_role.audit_logger.id
  policy = data.aws_iam_policy_document.audit_logger.json
}

data "aws_iam_policy_document" "audit_logger" {
  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-audit-logger*:*"]
  }

  statement {
    sid    = "AllowS3AuditWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.rules_and_logs.arn}/audit-logs/*",
      "${aws_s3_bucket.rules_and_logs.arn}/violations/*"
    ]
  }
}

# ===== METRICS PUBLISHER LAMBDA IAM =====

resource "aws_iam_role" "metrics_publisher" {
  name               = "${var.name_prefix}-metrics-publisher-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "metrics_publisher" {
  name   = "${var.name_prefix}-metrics-publisher-policy"
  role   = aws_iam_role.metrics_publisher.id
  policy = data.aws_iam_policy_document.metrics_publisher.json
}

data "aws_iam_policy_document" "metrics_publisher" {
  statement {
    sid    = "AllowLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-metrics-publisher*:*"]
  }

  statement {
    sid    = "AllowCloudWatchPublish"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["IAMPolicyMonitor"]
    }
  }
}

# ============================================================================
# Athena Table Creator Lambda IAM (conditional)
# ============================================================================

resource "aws_iam_role" "athena_table_creator" {
  count              = var.enable_athena_table ? 1 : 0
  name               = "${var.name_prefix}-athena-table-creator-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

data "aws_iam_policy_document" "athena_table_creator" {
  count = var.enable_athena_table ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:StopQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:CreateNamedQuery",
      "athena:DeleteNamedQuery",
      "athena:GetNamedQuery",
      "athena:ListNamedQueries",
      "athena:BatchGetNamedQuery"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "glue:GetDatabase",
      "glue:GetTable",
      "glue:GetTables",
      "glue:GetPartition",
      "glue:GetPartitions",
      "glue:BatchGetPartition",
      "glue:CreateTable",
      "glue:UpdateTable",
      "glue:DeleteTable"
    ]
    resources = [
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:catalog",
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:database/${replace(var.name_prefix, "-", "_")}_violations",
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${replace(var.name_prefix, "-", "_")}_violations/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
      "s3:CreateBucket",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = [
      var.enable_athena_table ? aws_s3_bucket.athena_results[0].arn : "",
      var.enable_athena_table ? "${aws_s3_bucket.athena_results[0].arn}/*" : "",
      aws_s3_bucket.rules_and_logs.arn,
      "${aws_s3_bucket.rules_and_logs.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["IAMPolicyMonitor/Analytics"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"]
  }
}

resource "aws_iam_role_policy" "athena_table_creator" {
  count  = var.enable_athena_table ? 1 : 0
  name   = "${var.name_prefix}-athena-table-creator-policy"
  role   = aws_iam_role.athena_table_creator[0].id
  policy = data.aws_iam_policy_document.athena_table_creator[0].json
}
