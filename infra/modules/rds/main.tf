# infra/modules/rds/main.tf

# Module nay trien khai [CIS 3.2.1] Ma hoa RDS
# va [CIS 3.2.2] Tu dong nang cap phien ban phu

# Dinh nghia cac bien dau vao cho module
variable "db_password" {
  description = "Mat khau cho DB, nen lay tu Secrets Manager"
  type        = string
  sensitive   = true
}

# [cite_start]Tao mot KMS key de ma hoa RDS [cite: 253]
resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 10
}

# Tai nguyen RDS mau, da duoc cau hinh tu dong tuan thu CIS
resource "aws_db_instance" "secure_rds_example" {
  # (Cac cau hinh RDS khac)
  allocated_storage = 20
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  db_name           = "cisdb"
  username          = "admin"
  password          = var.db_password

  # --- CAU HINH TUAN THU CIS ---

  # [cite_start][CIS 3.2.1] Dam bao du lieu duoc ma hoa khi luu tru [cite: 2225]
  # [cite_start]Thuc thi tuong tu bao cao Nhom 17 [cite: 252]
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_key.arn

  # [cite_start][CIS 3.2.2] Dam bao tu dong nang cap phien ban phu [cite: 2281]
  auto_minor_version_upgrade = true
  
  # [cite_start][CIS 3.2.3] Dam bao RDS khong truy cap cong khai [cite: 2312]
  publicly_accessible = false
  
  skip_final_snapshot = true
}
