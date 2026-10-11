import importlib.util
import json
import os
import boto3

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAMBDA_FILE = os.path.join(
    PROJECT_DIR, "lambda", "remediate_public_ssh.py"
)

os.environ["TEST_SG_ID"] = os.environ.get(
    "TEST_SG_ID",
    open(os.path.join(PROJECT_DIR, "tests", "security-group-id.txt"))
    .read().strip()
)
os.environ["AWS_ENDPOINT_URL"] = "http://localhost:4566"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

spec = importlib.util.spec_from_file_location(
    "remediate_public_ssh", LAMBDA_FILE
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

ec2 = boto3.client(
    "ec2",
    endpoint_url="http://localhost:4566",
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

group_id = os.environ["TEST_SG_ID"]

# Add the intentionally unsafe test rule to the isolated LocalStack group.
ec2.authorize_security_group_ingress(
    GroupId=group_id,
    IpPermissions=[{
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{
            "CidrIp": "0.0.0.0/0",
            "Description": "Temporary remediation test rule"
        }]
    }]
)
print("TEST 1: Added temporary public SSH rule.")

# Verify the unsafe rule exists before remediation.
before = ec2.describe_security_groups(GroupIds=[group_id])
found_before = any(
    r.get("CidrIp") == "0.0.0.0/0"
    for p in before["SecurityGroups"][0]["IpPermissions"]
    if p.get("IpProtocol") == "tcp"
    and p.get("FromPort") == 22
    and p.get("ToPort") == 22
    for r in p.get("IpRanges", [])
)
print("TEST 2: Public SSH rule present before remediation:", found_before)

# Use an event-shaped test input. This is a direct test invocation,
# not proof that CloudTrail or EventBridge generated the event.
event = {
    "source": "aws.ec2",
    "detail": {
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "groupId": group_id
        }
    }
}
result = module.lambda_handler(event, None)
print("TEST 3: Remediation result:")
print(json.dumps(result, indent=2))

# Verify the rule has been removed.
after = ec2.describe_security_groups(GroupIds=[group_id])
found_after = any(
    r.get("CidrIp") == "0.0.0.0/0"
    for p in after["SecurityGroups"][0]["IpPermissions"]
    if p.get("IpProtocol") == "tcp"
    and p.get("FromPort") == 22
    and p.get("ToPort") == 22
    for r in p.get("IpRanges", [])
)
print("TEST 4: Public SSH rule present after remediation:", found_after)

if found_before and not found_after and result.get("status") == "remediated":
    print("PASS: Public SSH rule was successfully remediated.")
else:
    print("FAIL: Review the output above.")
    raise SystemExit(1)
