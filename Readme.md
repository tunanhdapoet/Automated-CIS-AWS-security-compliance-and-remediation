# AWS CIS Benchmark Automation v6.0.0 🛡️

![Terraform](https://img.shields.io/badge/IaC-Terraform-purple)
![AWS Lambda](https://img.shields.io/badge/Serverless-Python_Boto3-orange)
![Security](https://img.shields.io/badge/Standard-CIS_v6.0.0-blue)

**NT542.Q11**: Xây dựng hệ thống **DevSecOps** tự động hóa giám sát (Audit) và tự động khắc phục (Auto-Remediate) các vi phạm bảo mật trên AWS theo tiêu chuẩn CIS Benchmark.

Đồ án môn học <img width="2292" height="1027" alt="Untitled diagram-2025-11-25-034314" src="https://github.com/user-attachments/assets/416326b2-f17c-4209-8b09-e4d142f3f56a" />

## 🚀 Cơ chế Hoạt động Chính

### 1. Cơ chế Tự động Khắc phục (Remediate)
[cite_start]Hệ thống hoạt động theo mô hình **Event-driven** (hướng sự kiện) để phản ứng tức thì với các mối đe dọa[cite: 1431]:
* **Trigger:** Lắng nghe sự kiện từ CloudTrail thông qua EventBridge Rule (Real-time).
* **Logic xử lý:**
    * 🔒 **Security Group:** Phân tích sự kiện `AuthorizeSecurityGroupIngress`. [cite_start]Nếu phát hiện mở port SSH (22) hoặc RDP (3389) cho `0.0.0.0/0` mà IP nguồn không nằm trong **Whitelist**, hệ thống sẽ lập tức thu hồi rule đó[cite: 1442, 1466].
    * [cite_start]👁️ **CloudTrail Integrity:** Nếu phát hiện lệnh `StopLogging`, hệ thống sẽ tự động bật lại logging để đảm bảo tính toàn vẹn của nhật ký[cite: 1443].
    * [cite_start]🪣 **S3 Security:** Tự động kích hoạt lại *Block Public Access* ở cấp độ tài khoản nếu bị vô hiệu hóa[cite: 1446].
* [cite_start]**Safety Filter:** Tích hợp chế độ **Dry Run** (chạy thử nghiệm) và **Whitelist IP** để tránh việc chặn nhầm quản trị viên hợp lệ [cite: 1377-1378].

### 2. Cơ chế Kiểm toán Định kỳ (Audit)
[cite_start]Hàm Lambda chạy theo lịch trình (Cronjob) để thực hiện "khám sức khỏe" toàn diện cho hạ tầng [cite: 1391-1397]:
* **Phạm vi quét:** IAM, S3, EC2, CloudTrail, Config trên tất cả các Region (Multi-region scan).
* **Kỹ thuật:**
    * Sử dụng **Asynchronous Polling** để chờ và phân tích báo cáo *IAM Credential Report*, phát hiện User không bật MFA hoặc Access Key cũ (>45 ngày).
    * Kiểm tra tuân thủ Password Policy (độ dài, ký tự đặc biệt).
    * Quét toàn bộ Security Group để tìm các cấu hình rủi ro tiềm ẩn.
* **Báo cáo:** Tổng hợp danh sách vi phạm (Findings) và gửi email cảnh báo chi tiết qua SNS.

## 🛠 Công nghệ sử dụng

* **Infrastructure as Code:** Terraform (Quản lý State, Modules)
* **Compute & Logic:** AWS Lambda (Python 3.9 + Boto3)
* **Detection:** Amazon EventBridge, AWS CloudTrail, AWS Config
* **Scanner:** Prowler (Docker container)
* **Alerting:** Amazon SNS (Email Notifications)

## ⚙️ Hướng dẫn Triển khai (Quick Start)

### Yêu cầu
* AWS CLI v2 (đã config profile Admin)
* Terraform >= 1.0

### Các bước thực hiện
1.  **Clone repository:**
    ```bash
    git clone [https://github.com/username/project-cis-aws.git](https://github.com/username/project-cis-aws.git)
    cd infra/environments/dev
    ```

2.  **Cấu hình biến (`terraform.tfvars`):**
    ```hcl
    aws_region    = "us-east-1"
    admin_email   = "admin@example.com"  # Email nhận cảnh báo
    whitelist_ips = "1.2.3.4/32"         # IP Admin (được phép SSH)
    dry_run       = "False"              # False = Tự động sửa lỗi thật
    ```

3.  **Triển khai:**
    ```bash
    terraform init
    terraform apply -auto-approve
    ```
    *> Kiểm tra email và xác nhận Subscription từ AWS SNS.*
