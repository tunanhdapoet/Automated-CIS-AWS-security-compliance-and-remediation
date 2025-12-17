# modules/sns_alarms/main.tf

variable "alarm_email" {
  description = "Email de nhan canh bao bao mat."
  type        = string
}

# 1. Tao SNS Topic
resource "aws_sns_topic" "security_alarms" {
  name = "CIS-Security-Alarms-Topic"
}

# 2. Tao Subscription (dang ky) bang email
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}
