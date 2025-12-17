# infra/modules/iam_baseline/main.tf

# Trien khai [CIS 2.7] va [CIS 2.8] - Chinh sach mat khau IAM manh
# Thong tin duoc lay tu bao cao Nhom 17
resource "aws_iam_account_password_policy" "cis_policy" {
  minimum_password_length    = 14
  require_symbols            = true
  require_numbers            = true
  require_uppercase_characters = true
  require_lowercase_characters = true
  password_reuse_prevention  = 24

  # Khuyen nghi them: Mat khau het han sau 90 ngay
  max_password_age = 90
}
