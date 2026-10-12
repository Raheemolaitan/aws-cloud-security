# AWS Cloud Security & Event-Driven Auto-Remediation

A hands-on cloud security engineering lab demonstrating infrastructure-as-code security checks, event-driven remediation, and evidence-based validation using Terraform, LocalStack, AWS Lambda, Checkov, and Prowler.

> **Lab status:** Tested in LocalStack. This is not a production AWS deployment and does not establish production compliance.

## Project Goals

- Define cloud infrastructure using Terraform.
- Reduce exposure from public SSH and RDP ingress.
- Configure private S3 buckets with encryption and versioning.
- Validate infrastructure using Checkov and Prowler.
- Automatically remove public IPv4 TCP port 22 ingress from an explicitly allow-listed security group.
- Retain test and scan evidence for review.

## Architecture

1. Terraform defines the S3 buckets and security group.
2. Checkov evaluates the Terraform configuration against selected security controls.
3. Prowler runs infrastructure-as-code checks and a separate scan against the emulated LocalStack environment.
4. A Lambda-compatible Python handler evaluates a remediation event.
5. If the security group matches the configured `TEST_SG_ID`, the handler removes public IPv4 TCP port 22 ingress.
6. Test outputs and security scan evidence are retained under `logs/`.

## Technology Stack

- Terraform
- LocalStack Community
- AWS CLI
- Python and AWS Lambda-compatible handler
- Checkov
- Prowler
- pytest
- Git

## Repository Layout

- `terraform/main.tf` — infrastructure configuration.
- `lambda/remediate_public_ssh.py` — SSH remediation handler.
- `lambda/trust-policy.json` — Lambda trust policy.
- `tests/` — remediation tests, event fixtures, and test outputs.
- `logs/EVIDENCE-INDEX.txt` — index of recorded evidence.
- `logs/prowler-iac/prowler-iac-final.html` — Prowler IaC report.
- `logs/prowler-localstack/SUMMARY.txt` — LocalStack scan summary.
- `logs/` — Checkov results and remediation evidence.

## Security Validation Results

### Focused Checkov pre-commit gate

| Result | Count |
|---|---:|
| Passed | 8 |
| Failed | 0 |
| Skipped | 0 |

This focused gate checks selected controls for public SSH/RDP ingress, S3 public-read ACLs, versioning, and encryption. It does not represent a pass of every security control.

### Full Checkov hardening scan

| Result | Count |
|---|---:|
| Passed | 35 |
| Failed | 5 |
| Skipped | 0 |

Outstanding findings include:

- `CKV2_AWS_62` — S3 event notifications are not configured on the dedicated access-logs bucket.
- `CKV_AWS_144` — cross-region replication is not configured for the two buckets.
- `CKV_AWS_145` — KMS-based default encryption is not configured. The buckets currently use SSE-S3 AES256.

These findings are documented rather than suppressed.

### Prowler infrastructure-as-code scan

- Passed: 70
- Failed: 1
- Muted: 0

The outstanding `AWS-0104` finding concerns unrestricted egress destination CIDR. Outbound traffic is limited to TCP 443, but the destination allows any IPv4 address.

### Prowler LocalStack scan

- Total records: 1,160
- Passed: 591
- Failed: 569

The scan targeted LocalStack's emulated account (`000000000000`), not a live AWS account. Some findings may reflect unsupported or incomplete service emulation. These results are not proof of production AWS compliance.

### Functional validation

- The remediation regression test confirmed that public IPv4 TCP port 22 ingress was present before invocation and absent afterward.
- The EventBridge test used a synthetic event; genuine CloudTrail delivery was not validated end to end.
- The S3 access-log lifecycle configuration specifies 90-day object expiration and abortion of incomplete multipart uploads after 7 days. Configuration was verified, but actual access-log delivery was not demonstrated.

See `logs/EVIDENCE-INDEX.txt` for the recorded evidence and its limitations.

## Known Limitations and Next Steps

- The lab has been tested against LocalStack, not a live AWS account.
- The remediation handler does not currently handle public IPv6 SSH ingress (`::/0`).
- EventBridge validation used a synthetic event rather than an end-to-end CloudTrail event.
- Access-log lifecycle settings were verified, but actual access-log delivery was not demonstrated.
- The full Checkov and Prowler scans still have findings, as documented above.
- Consider restricting outbound destinations, evaluating whether KMS encryption and cross-region replication are required, and configuring appropriate S3 event-notification coverage.
- Before production use, review IAM permissions, event delivery, logging, monitoring, rollback, failure handling, and deployment configuration.

## Reproducing the Lab

These are high-level steps; review the actual configuration before executing commands.

1. Install and start LocalStack.
2. Activate the appropriate Python environment and install the required tools.
3. Configure the AWS CLI to use the LocalStack endpoint, lab credentials, and `us-east-1`.
4. Review `terraform/main.tf` and `lambda/remediate_public_ssh.py`.
5. Initialize and validate Terraform, then plan and apply against LocalStack.
6. Run the remediation tests and focused Checkov gate.
7. Review the full Checkov and Prowler reports, including their remaining findings.

**Safety:** Use an isolated lab and test credentials. Do not point these lab commands at a production AWS account without reviewing and adapting the configuration.

## Evidence and Reproducibility

Start with `logs/EVIDENCE-INDEX.txt`. It identifies the recorded scan outputs, test evidence, and known limitations.

## Disclaimer

This repository is an educational cloud security engineering lab. Passing tests and scan results describe only the checks and environment actually tested. They are not a guarantee of security or regulatory compliance.
