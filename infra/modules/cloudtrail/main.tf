# infra/modules/cloudtrail/main.tf
# Trien khai [CIS 4.1] va [CIS 4.5]

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# 1. Tao S3 bucket de luu log
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cis-cloudtrail-logs-bucket-${data.aws_caller_identity.current.account_id}"
  # Them dong nay de S3 doi chinh sach bucket
  force_destroy = true 
}

# 2. Tao CloudWatch Log Group
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "CIS-CloudTrail-Log-Group"
  retention_in_days = 365 # Luu log 1 nam
}

# 3. [PHAN SUA LOI] Dinh nghia S3 Bucket Policy
# Dinh nghia chinh sach cho phep CloudTrail GHI vao bucket
data "aws_iam_policy_document" "s3_policy" {
  statement {
    sid = "AWSCloudTrailAclCheck"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid = "AWSCloudTrailWrite"
    actions = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# 4. [PHAN SUA LOI] Gan S3 Bucket Policy vao Bucket
resource "aws_s3_bucket_policy" "main" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.s3_policy.json
}

# 5. Dinh nghia IAM Role de CloudTrail GHI vao CloudWatch
data "aws_iam_policy_document" "cloudtrail_cw_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cw_role" {
  name               = "CIS-CloudTrail-to-CloudWatch-Role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cw_assume_role.json
}

data "aws_iam_policy_document" "cloudtrail_cw_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"]
  }
}

resource "aws_iam_role_policy" "main" {
  name   = "CIS-CloudTrail-to-CloudWatch-Policy"
  role   = aws_iam_role.cloudtrail_cw_role.id
  policy = data.aws_iam_policy_document.cloudtrail_cw_policy.json
}


# 6. Tao Trail (Da cap nhat de su dung cac tai nguyen moi)
resource "aws_cloudtrail" "cis_trail" {
  name                          = "CIS-Multi-Region-Trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true # [CIS 4.1] Bat da vung
  include_global_service_events = true

  # [PHAN SUA LOI] Cung cap Log Group va Role
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw_role.arn

  # [CIS 4.2] Bat xac thuc file log
  enable_log_file_validation = true

  # Phai cho S3 policy duoc tao xong
  depends_on = [aws_s3_bucket_policy.main]
}
