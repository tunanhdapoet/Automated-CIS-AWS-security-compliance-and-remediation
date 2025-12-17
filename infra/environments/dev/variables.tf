# infra/environments/dev/variables.tf

variable "aws_region" {
  description = "Region AWS se trien khai ha tang"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Ten du an (dung de dat ten tai nguyen)"
  type        = string
  default     = "CIS-Security"
}

variable "alarm_email" {
  description = "Email nhan canh bao bao mat (SNS)"
  type        = string
}

variable "db_password" {
  description = "Mat khau cho RDS Database (Sensitive)"
  type        = string
  sensitive   = true
}

variable "whitelist_ips" {
  description = "Danh sach IP tin cay (Admin) khong bi tu dong block boi Lambda Remediation"
  type        = list(string)
  default     = ["1.2.3.4/32"] # IP gia lap
}

variable "audit_schedule_expression" {
  description = "Lich chay tu dong cho Audit Lambda (Cron)"
  type        = string
  default     = "cron(0 12 * * ? *)" # 12:00 UTC hang ngay
}

variable "dry_run_mode" {
  description = "Che do chay Remediation: 'True' (Chi bao cao), 'False' (Tu dong sua loi)"
  type        = string
  default     = "False"
}