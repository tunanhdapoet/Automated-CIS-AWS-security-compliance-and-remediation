#!/usr/bin/python3
import boto3, os, json
from botocore.exceptions import ClientError

def _mk_ipv4_badperm(perm):
    bp = {"IpProtocol": perm.get("IpProtocol", "-1")}
    if "FromPort" in perm: bp["FromPort"] = perm["FromPort"]
    if "ToPort"   in perm: bp["ToPort"]   = perm["ToPort"]
    bp["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
    return bp

def _mk_ipv6_badperm(perm):
    bp = {"IpProtocol": perm.get("IpProtocol", "-1")}
    if "FromPort" in perm: bp["FromPort"] = perm["FromPort"]
    if "ToPort"   in perm: bp["ToPort"]   = perm["ToPort"]
    bp["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    return bp

def lambda_handler(event, context):
    print("--- AUTO-REMEDIATE (CIS) ---")
    print("[DEBUG] RAW:", json.dumps(event))

    ec2         = boto3.client('ec2')
    s3_control  = boto3.client('s3control')
    cloudtrail  = boto3.client('cloudtrail')
    iam         = boto3.client('iam')
    sts         = boto3.client('sts')
    sns         = boto3.client('sns')

    account_id    = sts.get_caller_identity()['Account']
    dry_run       = os.environ.get('DRY_RUN', 'true').lower() == 'true'
    whitelist_ips = set([x.strip() for x in os.environ.get('WHITELIST_IPS', '').split(',') if x.strip()])
    topic_arn     = os.environ.get('SNS_TOPIC_ARN')

    detail     = event.get('detail', {})
    ev_name    = detail.get('eventName', '')
    user_type  = detail.get('userIdentity', {}).get('type', 'Unknown')
    req_params = detail.get('requestParameters', {}) or {}

    remediation_log = []
    target_sg_ids   = []

    # ====== SG targets (CIS 6.3/6.4) =========================================
    if ev_name in ['AuthorizeSecurityGroupIngress','ModifySecurityGroupRules',
                   'AuthorizeSecurityGroupEgress','RevokeSecurityGroupIngress',
                   'RevokeSecurityGroupEgress','CreateSecurityGroup']:
        gid = req_params.get('groupId') or req_params.get('group_id') or req_params.get('groupIdSet') or None
        if isinstance(gid, dict) and 'items' in gid and gid['items']:  # một số bản ghi có groupIdSet.items[0]
            gid = gid['items'][0]
        if gid:
            print(f"[DEBUG] target SG from event: {gid}")
            target_sg_ids.append(gid)

    # Scheduled scan (no eventName)
    if not ev_name:
        print("[SCAN] No eventName => full SG sweep")
        try:
            for sg in ec2.describe_security_groups()['SecurityGroups']:
                if sg.get('IpPermissions'):
                    target_sg_ids.append(sg['GroupId'])
        except Exception as e:
            print(f"[ERROR] list SG: {e}")

    # Remediate SG
    risky_ports = {22, 3389}
    for sg_id in set(target_sg_ids):
        try:
            sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
            for perm in sg.get('IpPermissions', []):
                proto  = perm.get('IpProtocol')
                fport  = perm.get('FromPort'); tport = perm.get('ToPort')
                covers_sensitive = (proto == '-1') or (fport is not None and tport is not None and any(fport <= p <= tport for p in risky_ports))
                if not covers_sensitive:
                    continue

                # IPv4: chỉ gỡ 0.0.0.0/0 khi KHÔNG thuộc whitelist
                for r in perm.get('IpRanges', []):
                    if r.get('CidrIp') == '0.0.0.0/0' and r['CidrIp'] not in whitelist_ips:
                        bad = _mk_ipv4_badperm(perm)
                        msg = f"SG {sg_id}: revoke IPv4 0.0.0.0/0 for ports {fport}-{tport or fport}"
                        if dry_run:
                            remediation_log.append(f"[WOULD FIX] {msg}")
                        else:
                            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[bad])
                            remediation_log.append(f"[FIXED] {msg}")

                # IPv6: chỉ gỡ ::/0
                for r in perm.get('Ipv6Ranges', []):
                    if r.get('CidrIpv6') == '::/0':
                        bad = _mk_ipv6_badperm(perm)
                        msg = f"SG {sg_id}: revoke IPv6 ::/0 for ports {fport}-{tport or fport}"
                        if dry_run:
                            remediation_log.append(f"[WOULD FIX] {msg}")
                        else:
                            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[bad])
                            remediation_log.append(f"[FIXED] {msg}")
        except Exception as e:
            print(f"[ERROR] SG {sg_id}: {e}")

    # ====== CloudTrail StopLogging (CIS 4.1) =================================
    if ev_name == 'StopLogging':
        trail_name = req_params.get('name')
        if trail_name:
            msg = f"Detected StopLogging on trail '{trail_name}' — restarting"
            if dry_run:
                remediation_log.append(f"[WOULD FIX] {msg}")
            else:
                try:
                    cloudtrail.start_logging(Name=trail_name)
                    remediation_log.append(f"[FIXED] {msg}")
                except Exception as e:
                    remediation_log.append(f"[ERROR] start_logging: {e}")

    # ====== S3 BPA account-level (CIS 3.1.4) =================================
    if ev_name == 'DeleteAccountPublicAccessBlock':
        msg = "Detected DeleteAccountPublicAccessBlock — re-enabling BPA"
        if dry_run:
            remediation_log.append(f"[WOULD FIX] {msg}")
        else:
            try:
                s3_control.put_public_access_block(
                    AccountId=account_id,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,'RestrictPublicBuckets': True
                    }
                )
                remediation_log.append(f"[FIXED] {msg}")
            except Exception as e:
                remediation_log.append(f"[ERROR] put_public_access_block: {e}")

    # ====== Root CreateAccessKey (CIS 2.3) — ALERT ONLY ======================
    if ev_name == 'CreateAccessKey' and detail.get('userIdentity', {}).get('type') == 'Root':
        msg = "[CRITICAL] Root access key was created — MANUAL removal required by root user"
        remediation_log.append(msg)  # Không cố delete bằng role (không khả thi per CIS)

    # ====== Send SNS ==========================================================
    if remediation_log and topic_arn:
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject=f"[AUTO-REMEDIATE][{'DRY' if dry_run else 'LIVE'}] {ev_name or 'Scheduled'}",
                Message="\n".join(remediation_log)
            )
        except Exception as e:
            print(f"[ERROR] SNS: {e}")

    print(json.dumps(remediation_log))
    return {"statusCode": 200, "body": json.dumps(remediation_log)}
