# modules/cloudtrail/outputs.tf

output "log_group_name" {
  description = "Ten cua CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.cloudtrail_log_group.name
}
