#!/usr/bin/python3
import boto3, csv, time, os, json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

NOW = lambda: datetime.now(timezone.utc)

def _load_credential_report(iam):
    iam.generate_credential_report()
    for _ in range(15):
        try:
            resp = iam.get_credential_report()
            content = resp['Content'].decode('utf-8')  # bytes -> str (CSV)
            return list(csv.DictReader(content.splitlines()))
        except ClientError as e:
            if e.response['Error']['Code'] == 'ReportInProgress':
                time.sleep(2); continue
            raise
    return []

def _days_since(iso):
    if not iso or iso == 'N/A' or iso == 'no_information':
        return None
    try:
        d = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
        return (NOW() - d).days
    except Exception:
        return None

def _all_regions():
    ec2 = boto3.client('ec2')
    regs = ec2.describe_regions(AllRegions=True)['Regions']
    # chọn những region đang khả dụng với account (opt-in not required / opted-in)
    return [r['RegionName'] for r in regs if r.get('OptInStatus') in (None,'opt-in-not-required','opted-in')]

def lambda_handler(event, context):
    print("--- CIS HYGIENE AUDIT ---")
    iam  = boto3.client('iam')
    ec2  = boto3.client('ec2')
    s3c  = boto3.client('s3control')
    sts  = boto3.client('sts')
    sns  = boto3.client('sns')

    acc_id      = sts.get_caller_identity()['Account']
    topic_arn   = os.environ.get('SNS_TOPIC_ARN')
    findings    = []

    # ===== IAM Summary — Root key (CIS 2.3) ==================================
    try:
        if iam.get_account_summary()['SummaryMap'].get('AccountAccessKeysPresent') == 1:
            findings.append("[CRITICAL][CIS 2.3] Root account có Access Key hoạt động — phải xóa bằng root.")
    except Exception as e:
        findings.append(f"[ERROR] IAM summary: {e}")

    # ===== Password policy (CIS 2.7, 2.8) ====================================
    try:
        pol = iam.get_account_password_policy()['PasswordPolicy']
        if pol.get('MinimumPasswordLength', 0) < 14:
            findings.append("[MAJOR][CIS 2.7] MinimumPasswordLength < 14.")
        if pol.get('PasswordReusePrevention', 0) < 24:
            findings.append("[MAJOR][CIS 2.8] PasswordReusePrevention < 24.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append("[MAJOR][CIS 2.7/2.8] Chưa thiết lập IAM account password policy.")
        else:
            findings.append(f"[ERROR] PasswordPolicy: {e}")

    # ===== Credential report (CIS 2.9, 2.11–2.13) ============================
    try:
        rows = _load_credential_report(iam)
        for r in rows:
            user = r['user']

            # 2.9: MFA cho user có console password
            if r.get('password_enabled') == 'true' and r.get('mfa_active') == 'false':
                findings.append(f"[MAJOR][CIS 2.9] User '{user}' có console password nhưng chưa bật MFA.")

            # 2.12: Chỉ 1 access key active
            k1 = r.get('access_key_1_active') == 'true'
            k2 = r.get('access_key_2_active') == 'true'
            if k1 and k2:
                findings.append(f"[MAJOR][CIS 2.12] User '{user}' có >1 access key active.")

            # 2.11: Disable credential >45 ngày không dùng
            for idx in ('1','2'):
                if r.get(f'access_key_{idx}_active') == 'true':
                    last_used_days = _days_since(r.get(f'access_key_{idx}_last_used_date'))
                    last_rot_days  = _days_since(r.get(f'access_key_{idx}_last_rotated'))
                    # Nếu chưa từng dùng (N/A) => dựa vào last_rotated
                    metric = last_used_days if last_used_days is not None else last_rot_days
                    if metric is not None and metric > 45:
                        findings.append(f"[MAJOR][CIS 2.11] User '{user}' key{idx} không dùng ~{metric} ngày.")

            # 2.13: Rotation ≤ 90 ngày
            for idx in ('1','2'):
                rot_days = _days_since(r.get(f'access_key_{idx}_last_rotated'))
                if r.get(f'access_key_{idx}_active') == 'true' and rot_days is not None and rot_days > 90:
                    findings.append(f"[MINOR][CIS 2.13] User '{user}' key{idx} chưa rotate ~{rot_days} ngày.")
    except Exception as e:
        findings.append(f"[ERROR] Credential report: {e}")

    # ===== 2.15: Không policy *:* ============================================
    try:
        pols = iam.list_policies(Scope='Local', OnlyAttached=True, MaxItems=1000)['Policies']
        for p in pols:
            v = iam.get_policy(PolicyArn=p['Arn'])['Policy']['DefaultVersionId']
            doc = iam.get_policy_version(PolicyArn=p['Arn'], VersionId=v)['PolicyVersion']['Document']
            # Chuẩn hóa Statement thành list
            stmts = doc['Statement'] if isinstance(doc['Statement'], list) else [doc['Statement']]
            for s in stmts:
                if s.get('Effect') == 'Allow':
                    act = s.get('Action'); res = s.get('Resource')
                    if (act == '*' or (isinstance(act, list) and '*' in act)) and (res == '*' or (isinstance(res, list) and '*' in res)):
                        findings.append(f"[MAJOR][CIS 2.15] Policy '{p['PolicyName']}' cho phép *:* (nên thay bằng least-privilege).")
                        break
    except Exception as e:
        findings.append(f"[ERROR] Policy scan: {e}")

    # ===== 2.16: Support role tồn tại? =======================================
    try:
        iam.get_role(RoleName='AWSSupportAccess')
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append("[MINOR][CIS 2.16] Thiếu role 'AWSSupportAccess'.")
        else:
            findings.append(f"[ERROR] GetRole AWSSupportAccess: {e}")

    # ===== S3 BPA (CIS 3.1.4) ===============================================
    try:
        conf = s3c.get_public_access_block(AccountId=acc_id)['PublicAccessBlockConfiguration']
        if not all([conf.get('BlockPublicAcls'), conf.get('IgnorePublicAcls'),
                    conf.get('BlockPublicPolicy'), conf.get('RestrictPublicBuckets')]):
            findings.append(f"[MAJOR][CIS 3.1.4] Account {acc_id} chưa bật đủ S3 BPA.")
    except ClientError:
        findings.append(f"[MAJOR][CIS 3.1.4] Account {acc_id} chưa cấu hình S3 BPA.")

    # ===== AWS Config multi-region (CIS 4.3) =================================
    for reg in _all_regions():
        try:
            cfg = boto3.client('config', region_name=reg)
            recs = cfg.describe_configuration_recorders().get('ConfigurationRecorders', [])
            if not recs:
                findings.append(f"[MAJOR][CIS 4.3] {reg}: Chưa có Configuration Recorder.")
                continue
            sts2 = cfg.describe_configuration_recorder_status(
                ConfigurationRecorderNames=[recs[0]['name']]
            )['ConfigurationRecordersStatus']
            if not sts2 or not sts2[0].get('recording'):
                findings.append(f"[MAJOR][CIS 4.3] {reg}: Recorder tồn tại nhưng KHÔNG recording.")
        except Exception as e:
            findings.append(f"[ERROR] AWS Config ({reg}): {e}")

    # ===== CloudTrail multi-region (CIS 4.1) — kiểm đúng multi-region =======
    try:
        ct = boto3.client('cloudtrail')
        trails = ct.describe_trails(includeShadowTrails=False)['trailList']

        if not trails:
            findings.append("[MAJOR][CIS 4.1] Không có CloudTrail nào được cấu hình.")
        else:
            # tìm 1 multi-region trail
            multi = None
            for t in trails:
                if t.get('IsMultiRegionTrail'):
                    multi = t
                    break

            if not multi:
                findings.append("[MAJOR][CIS 4.1] Chưa có trail multi-region nào.")
            else:
                name = multi['Name']

                # Kiểm tra IsLogging
                status = ct.get_trail_status(Name=name)
                if not status.get('IsLogging'):
                    findings.append(f"[MAJOR][CIS 4.1] Trail '{name}' đang tắt (IsLogging=false).")

                # Kiểm tra EventSelectors: ManagementEvents=ON & ReadWriteType=All
                try:
                    sels = ct.get_event_selectors(TrailName=name)['EventSelectors']
                    include_mgmt = any(es.get('IncludeManagementEvents') for es in sels)
                    rw_all = any(es.get('ReadWriteType', 'All') == 'All' for es in sels)
                    if not include_mgmt or not rw_all:
                        findings.append(
                            f"[MAJOR][CIS 4.1] Trail '{name}' chưa log đầy đủ Management Events "
                            "(IncludeManagementEvents=True, ReadWriteType=All)."
                        )
                except Exception as e:
                    findings.append(f"[ERROR] CloudTrail GetEventSelectors: {e}")
    except Exception as e:
        findings.append(f"[ERROR] CloudTrail: {e}")

    # ===== Default SG & Open Ports (CIS 6.3/6.4/6.5) =========================
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            if sg['GroupName'] == 'default' and (sg.get('IpPermissions') or sg.get('IpPermissionsEgress')):
                findings.append(f"[MAJOR][CIS 6.5] Default SG '{sg['GroupId']}' có rule (phải restrict all).")
            for perm in sg.get('IpPermissions', []):
                fp, tp, proto = perm.get('FromPort'), perm.get('ToPort'), perm.get('IpProtocol')
                sensitive = (proto == '-1') or (fp is not None and tp is not None and (fp <= 22 <= tp or fp <= 3389 <= tp))
                if sensitive:
                    if any(r.get('CidrIp') == '0.0.0.0/0' for r in perm.get('IpRanges', [])):
                        findings.append(f"[MAJOR][CIS 6.3] SG {sg['GroupId']} mở 22/3389 ra 0.0.0.0/0.")
                    if any(r.get('CidrIpv6') == '::/0' for r in perm.get('Ipv6Ranges', [])):
                        findings.append(f"[MAJOR][CIS 6.4] SG {sg['GroupId']} mở 22/3389 ra ::/0.")
    except Exception as e:
        findings.append(f"[ERROR] Network scan: {e}")

    # ===== Send SNS ==========================================================
    if findings and topic_arn:
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject="[CIS AUDIT] Findings",
                Message="\n".join(findings)
            )
        except Exception as e:
            print(f"[ERROR] SNS: {e}")

    print(json.dumps(findings, indent=2))
    return {"statusCode": 200, "body": json.dumps(findings)}
