# modules/sns_alarms/outputs.tf

output "sns_topic_arn" {
  description = "ARN cua SNS topic de gui canh bao"
  value       = aws_sns_topic.security_alarms.arn
}
