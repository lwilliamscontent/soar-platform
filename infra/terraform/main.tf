data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "soar_kms" {
  statement {
    sid    = "EnableAccountIAMPolicies"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

check "deployment_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "Refusing deployment: active credentials do not belong to aws_account_id."
  }
}

resource "aws_kms_key" "soar" {
  description             = "SOAR queues, logs, and secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.soar_kms.json
}

resource "aws_kms_alias" "soar" {
  name          = "alias/soar-${var.environment}"
  target_key_id = aws_kms_key.soar.key_id
}

# checkov:skip=CKV2_AWS_57: Splunk token rotation requires a vendor-aware workflow; manual rotation is documented until that workflow exists.
resource "aws_secretsmanager_secret" "splunk_soar" {
  name       = "soar/${var.environment}/splunk-soar"
  kms_key_id = aws_kms_key.soar.arn
}

# checkov:skip=CKV2_AWS_57: VirusTotal key rotation requires a provider-aware workflow; manual rotation is documented until that workflow exists.
resource "aws_secretsmanager_secret" "virustotal" {
  name       = "soar/${var.environment}/virustotal"
  kms_key_id = aws_kms_key.soar.arn
}

resource "aws_sqs_queue" "findings_dlq" {
  name                      = "soar-findings-${var.environment}-dlq"
  kms_master_key_id         = aws_kms_key.soar.arn
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "findings" {
  name                       = "soar-findings-${var.environment}"
  kms_master_key_id          = aws_kms_key.soar.arn
  visibility_timeout_seconds = 180
  message_retention_seconds  = 1209600
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.findings_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_iam_role" "ingestor" {
  name = "soar-${var.environment}-ingestor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ingestor" {
  role = aws_iam_role.ingestor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.findings.arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.splunk_soar.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.soar.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/soar-${var.environment}-ingestor:*"
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      }
    ]
  })
}

# checkov:skip=CKV_AWS_117: Public AWS APIs and the vendor HTTPS endpoint require egress; VPC attachment adds no isolation until controlled private egress exists.
# checkov:skip=CKV_AWS_116: The SQS event source owns retries and already has a redrive DLQ; a Lambda asynchronous-invocation DLQ does not apply.
# checkov:skip=CKV_AWS_272: Code signing is a tracked pre-production requirement; enforcing it before the signing pipeline exists would block deployments.
resource "aws_lambda_function" "ingestor" {
  function_name                  = "soar-${var.environment}-ingestor"
  role                           = aws_iam_role.ingestor.arn
  runtime                        = "python3.13"
  handler                        = "handler.lambda_handler"
  s3_bucket                      = var.lambda_artifact_bucket
  s3_key                         = var.ingestor_artifact_key
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = 20
  kms_key_arn                    = aws_kms_key.soar.arn

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      SOAR_SECRET_ARN = aws_secretsmanager_secret.splunk_soar.arn
      DISPATCH_MODE   = "log"
    }
  }
}

resource "aws_lambda_event_source_mapping" "findings" {
  event_source_arn        = aws_sqs_queue.findings.arn
  function_name           = aws_lambda_function.ingestor.arn
  batch_size              = 10
  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_cloudwatch_event_rule" "securityhub" {
  name = "soar-${var.environment}-securityhub-findings"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_iam_role" "eventbridge" {
  name = "soar-${var.environment}-eventbridge"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge" {
  role = aws_iam_role.eventbridge.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.findings.arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "findings_queue" {
  rule     = aws_cloudwatch_event_rule.securityhub.name
  arn      = aws_sqs_queue.findings.arn
  role_arn = aws_iam_role.eventbridge.arn
}

resource "aws_sqs_queue_policy" "findings" {
  queue_url = aws_sqs_queue.findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridge"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.findings.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.securityhub.arn }
      }
    }]
  })
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "soar-${var.environment}-dlq-not-empty"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions = {
    QueueName = aws_sqs_queue.findings_dlq.name
  }
}

resource "aws_budgets_budget" "playground" {
  name         = "soar-${var.environment}-monthly-cost"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Application$soar-platform"]
  }

  dynamic "notification" {
    for_each = var.budget_alert_email == "" ? [] : [var.budget_alert_email]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_email_addresses = [notification.value]
    }
  }

  dynamic "notification" {
    for_each = var.budget_alert_email == "" ? [] : [var.budget_alert_email]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [notification.value]
    }
  }
}
