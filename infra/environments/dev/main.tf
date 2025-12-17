# infra/environments/dev/main.tf

provider "aws" {
  region = var.aws_region
}

# --- 1. GOI CAC MODULE CO SO (INFRASTRUCTURE - PREVENTIVE) ---

module "iam_baseline" {
  source = "../../modules/iam_baseline"
}

# module "securityhub" {
#   source = "../../modules/securityhub"
# }

module "sns_alarms" {
  source      = "../../modules/sns_alarms"
  alarm_email = var.alarm_email # Lay tu tfvars
}

module "cloudtrail" {
  source = "../../modules/cloudtrail"
}

module "rds_secure" {
  source      = "../../modules/rds"
  db_password = var.db_password # Lay tu tfvars
}

module "monitoring_alarms" {
  source = "../../modules/monitoring"
  cloudtrail_log_group_name = module.cloudtrail.log_group_name
  sns_topic_arn_for_alarms  = module.sns_alarms.sns_topic_arn
}

# =========================================================================
# --- PHẦN 2: AUTOMATION & REMEDIATION (DETECTIVE & CORRECTIVE) ---
# =========================================================================

# --- A. Chuan bi Code ---
data "archive_file" "audit_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_audit.py"
  output_path = "${path.module}/lambda/audit.zip"
}

data "archive_file" "remediate_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_remediate.py"
  output_path = "${path.module}/lambda/remediate.zip"
}

# --- B. IAM Role & Policy ---
resource "aws_iam_role" "cis_lambda_role" {
  name = "cis_lambda_exec_role_dev"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "cis_lambda_policy" {
  name        = "cis_lambda_policy_dev"
  description = "Quyen cho Lambda Audit va Remediate cac dich vu AWS"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow",
        Action = [
          # EC2 – regions & security groups (Audit + Remediate)
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",

          # AWS Config (Audit – CIS 4.3)
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",

          # CloudTrail (Audit – CIS 4.1, Remediate StopLogging)
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:StartLogging",

          # S3 Account-level BPA qua s3control (Audit + Remediate – CIS 3.1.4)
          "s3control:GetPublicAccessBlock",
          "s3control:PutPublicAccessBlock",

          # IAM (Audit – CIS 2.x)
          "iam:GetAccountSummary",
          "iam:GetAccountPasswordPolicy",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",

          # STS (lấy AccountId)
          "sts:GetCallerIdentity",

          # SNS (gửi cảnh báo)
          "sns:Publish"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_cis_policy" {
  role       = aws_iam_role.cis_lambda_role.name
  policy_arn = aws_iam_policy.cis_lambda_policy.arn
}

# --- C. Lambda Functions ---

# 1. Audit Function
resource "aws_lambda_function" "cis_audit" {
  filename         = data.archive_file.audit_zip.output_path
  function_name    = "CIS_Auto_Audit_Dev"
  role             = aws_iam_role.cis_lambda_role.arn
  handler          = "lambda_audit.lambda_handler"
  runtime          = "python3.9"
  timeout          = 60
  source_code_hash = data.archive_file.audit_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = module.sns_alarms.sns_topic_arn
    }
  }
}

# 2. Remediate Function
resource "aws_lambda_function" "cis_remediate" {
  filename         = data.archive_file.remediate_zip.output_path
  function_name    = "CIS_Auto_Remediate_Dev"
  role             = aws_iam_role.cis_lambda_role.arn
  handler          = "lambda_remediate.lambda_handler"
  runtime          = "python3.9"
  timeout          = 60
  source_code_hash = data.archive_file.remediate_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = module.sns_alarms.sns_topic_arn
      DRY_RUN       = var.dry_run_mode  # Lay tu tfvars
      # Chuyen list string (trong tfvars) thanh chuoi ngan cach dau phay (cho Python doc)
      WHITELIST_IPS = join(",", var.whitelist_ips) 
    }
  }
}

# --- D. Triggers (EventBridge) ---

# 1. Scheduled Trigger
resource "aws_cloudwatch_event_rule" "daily_audit_trigger" {
  name                = "cis-audit-daily-schedule"
  description         = "Trigger CIS Audit script daily"
  schedule_expression = var.audit_schedule_expression # Lay tu tfvars
}

resource "aws_cloudwatch_event_target" "target_audit_lambda" {
  rule      = aws_cloudwatch_event_rule.daily_audit_trigger.name
  target_id = "CIS_Auto_Audit_Dev"
  arn       = aws_lambda_function.cis_audit.arn
}

resource "aws_lambda_permission" "allow_audit_schedule" {
  statement_id  = "AllowExecutionFromCloudWatchSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cis_audit.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_audit_trigger.arn
}

# 2. Event-Driven Trigger (Real-time Remediation)
resource "aws_cloudwatch_event_rule" "critical_events_trigger" {
  name        = "cis-critical-events-trigger"
  description = "Trigger Remediation for SG, CloudTrail, S3, Root Key events"

  event_pattern = jsonencode({
    "source": ["aws.ec2", "aws.cloudtrail", "aws.s3", "aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": [
        "ec2.amazonaws.com", "cloudtrail.amazonaws.com", 
        "s3.amazonaws.com", "iam.amazonaws.com"
      ],
      "eventName": [
             "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "RevokeSecurityGroupEgress",
      "ModifySecurityGroupRules",          # <— BỔ SUNG cho code của bạn
      "CreateSecurityGroup", "DeleteSecurityGroup",

      # CloudTrail config tampering — CIS 5.5:
      "StopLogging",

      # S3 BPA Account-level — CIS 3.1.4:
      "DeleteAccountPublicAccessBlock",

      # Root key creation — CIS 2.3:
      "CreateAccessKey"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "target_remediate_event" {
  rule      = aws_cloudwatch_event_rule.critical_events_trigger.name
  target_id = "CIS_Auto_Remediate_RealTime"
  arn       = aws_lambda_function.cis_remediate.arn
}

resource "aws_lambda_permission" "allow_remediate_event" {
  statement_id  = "AllowExecutionFromEventBridgeRealTime"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cis_remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.critical_events_trigger.arn
}