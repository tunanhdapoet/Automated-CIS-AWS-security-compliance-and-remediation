# infra/modules/monitoring/main.tf

# Trien khai cac canh bao giam sat (CIS Muc 5)

variable "cloudtrail_log_group_name" {
  description = "Ten cua CloudWatch Log Group"
  type        = string
}

variable "sns_topic_arn_for_alarms" {
  description = "ARN cua SNS Topic de nhan canh bao"
  type        = string
}

# [cite_start]--- [CIS 5.4] Giam sat thay doi IAM Policy --- [cite: 2796]
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "CIS-5.4-IAMPolicyChanges"
  log_group_name = var.cloudtrail_log_group_name
  
  # [cite_start]Filter Pattern tuong ung tu file CIS Doc [cite: 2806]
  pattern = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"

  metric_transformation {
    name      = "CIS-5.4-IAMPolicyChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes_alarm" {
  alarm_name          = "ALARM-CIS-5.4-IAM-Policy-Changes"
  alarm_description   = "Canh bao thay doi IAM policy (CIS 5.4)"
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300 # 5 phut
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn_for_alarms]
  ok_actions          = [var.sns_topic_arn_for_alarms]
}

# [cite_start]--- [CIS 5.10] Giam sat thay doi Security Group --- [cite: 2951]
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "CIS-5.10-SecurityGroupChanges"
  log_group_name = var.cloudtrail_log_group_name
  
  # [cite_start]Filter Pattern tuong ung tu file CIS Doc [cite: 2961]
  pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  
  metric_transformation {
    name      = "CIS-5.10-SecurityGroupChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sg_changes_alarm" {
  alarm_name          = "ALARM-CIS-5.10-Security-Group-Changes"
  alarm_description   = "Canh bao thay doi Security Group (CIS 5.10)"
  metric_name         = aws_cloudwatch_log_metric_filter.sg_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.sg_changes.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn_for_alarms]
  ok_actions          = [var.sns_topic_arn_for_alarms]
}
