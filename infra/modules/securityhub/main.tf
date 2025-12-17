# infra/modules/securityhub/main.tf

# [cite_start]Trien khai [CIS 5.16] Bat AWS Security Hub [cite: 3127]

# Bat dich vu Security Hub
resource "aws_securityhub_account" "main" {}

# Tu dong dang ky tieu chuan CIS AWS Foundations Benchmark
# Terraform se dung ARN chuan duoc AWS quan ly.
# [cite_start](Giong nhu muc tieu cua lenh CLI trong bao cao Nhom 17 [cite: 269, 271])
resource "aws_securityhub_standards_subscription" "cis" {
  # Phai cho Security Hub bat xong moi duoc dang ky
  depends_on = [aws_securityhub_account.main]

  # ARN cho CIS AWS Foundations Benchmark v1.2.0 (tieu chuan duoc AWS quan ly)
 standards_arn = "arn:aws:securityhub:${data.aws_region.current.id}::standard/cis-aws-foundations-benchmark/v/1.2.0"
}

data "aws_region" "current" {}
