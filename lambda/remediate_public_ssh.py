import json
import os
import boto3

AWS_ENDPOINT_URL = os.environ.get(
    "AWS_ENDPOINT_URL", "http://localhost:4566"
)
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
TARGET_SG_ID = os.environ.get("TEST_SG_ID", "")

ec2 = boto3.client(
    "ec2",
    endpoint_url=AWS_ENDPOINT_URL,
    region_name=AWS_REGION,
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
)


def lambda_handler(event, context):
    """Revoke public IPv4 SSH ingress from the designated test group."""

    detail = event.get("detail", {})
    request = detail.get("requestParameters", {})

    # Accept the security-group ID from an event, but never allow
    # remediation outside the explicitly configured test group.
    group_id = request.get("groupId") or event.get("groupId")

    if not TARGET_SG_ID:
        return {
            "status": "error",
            "message": "TEST_SG_ID is not configured."
        }

    if group_id != TARGET_SG_ID:
        return {
            "status": "skipped",
            "message": "Event does not target the designated test group.",
            "group_id": group_id
        }

    # Inspect the actual current rules, rather than trusting the event alone.
    response = ec2.describe_security_groups(GroupIds=[TARGET_SG_ID])
    groups = response.get("SecurityGroups", [])

    if not groups:
        return {
            "status": "error",
            "message": "Target security group was not found."
        }

    revoked = []

    for permission in groups[0].get("IpPermissions", []):
        protocol = str(permission.get("IpProtocol", "")).lower()
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        is_ssh = (
            protocol == "tcp"
            and from_port is not None
            and to_port is not None
            and from_port == 22 and to_port == 22
        )

        if not is_ssh:
            continue

        for range_item in permission.get("IpRanges", []):
            if range_item.get("CidrIp") != "0.0.0.0/0":
                continue

            exact_permission = {
                "IpProtocol": "tcp",
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }

            ec2.revoke_security_group_ingress(
                GroupId=TARGET_SG_ID,
                IpPermissions=[exact_permission],
            )

            revoked.append({
                "protocol": "tcp",
                "from_port": from_port,
                "to_port": to_port,
                "cidr": "0.0.0.0/0"
            })

    return {
        "status": "remediated" if revoked else "no_action",
        "group_id": TARGET_SG_ID,
        "revoked_rules": revoked,
        "message": (
            "Public SSH ingress revoked."
            if revoked
            else "No public SSH ingress rule was found."
        )
    }
