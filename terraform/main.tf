terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "test"
  secret_key = "test"

  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = "http://localhost:4566"
    s3  = "http://localhost:4566"
  }
}

variable "vpc_id" {
  description = "Existing LocalStack VPC for the secure test security group"
  type        = string
  default     = "vpc-e1413160276a42523"
}

resource "aws_security_group" "secure_application" {
  name        = "terraform-secure-application"
  description = "Secure application security group managed by Terraform"
  vpc_id      = var.vpc_id

  # No inbound rules are defined by default.
  # Add only the minimum inbound access the application requires.

  egress {
    description = "Allow outbound HTTPS for the lab"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project     = "AWS-Cloud-Security"
    Environment = "LocalStack-Lab"
    ManagedBy   = "Terraform"
  }
}

output "secure_security_group_id" {
  description = "ID of the Terraform-managed secure security group"
  value       = aws_security_group.secure_application.id
}

variable "subnet_id" {
  description = "Existing LocalStack subnet for the test network interface"
  type        = string
  default     = "subnet-88154b214e6b9db10"
}

resource "aws_network_interface" "secure_application" {
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.secure_application.id]

  tags = {
    Project     = "AWS-Cloud-Security"
    Environment = "LocalStack-Lab"
    ManagedBy   = "Terraform"
  }
}

output "secure_network_interface_id" {
  description = "ID of the network interface associated with the secure security group"
  value       = aws_network_interface.secure_application.id
}

# S3 bucket for the cloud security lab
resource "aws_s3_bucket" "secure_evidence" {
  bucket = "aws-cloud-security-evidence-local-lab"

  tags = {
    Project     = "AWS-Cloud-Security"
    Environment = "LocalStack-Lab"
    ManagedBy   = "Terraform"
  }
}

# Block public access to the bucket
resource "aws_s3_bucket_public_access_block" "secure_evidence" {
  bucket = aws_s3_bucket.secure_evidence.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_evidence" {
  bucket = aws_s3_bucket.secure_evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable versioning for evidence recovery
resource "aws_s3_bucket_versioning" "secure_evidence" {
  bucket = aws_s3_bucket.secure_evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
output "secure_evidence_bucket_name" {
  description = "Name of the S3 evidence bucket"
  value       = aws_s3_bucket.secure_evidence.id
}

# Clean up incomplete multipart uploads without deleting completed evidence
resource "aws_s3_bucket_lifecycle_configuration" "secure_evidence" {
  bucket = aws_s3_bucket.secure_evidence.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Send S3 bucket events to EventBridge for event-driven monitoring
resource "aws_s3_bucket_notification" "secure_evidence" {
  bucket      = aws_s3_bucket.secure_evidence.id
  eventbridge = true
}

# Dedicated bucket for S3 access logs
resource "aws_s3_bucket" "access_logs" {
  bucket = "aws-cloud-security-access-logs-local-lab"

  tags = {
    Project     = "AWS-Cloud-Security"
    Environment = "LocalStack-Lab"
    ManagedBy   = "Terraform"
    Purpose     = "S3-Access-Logs"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "secure_evidence" {
  bucket        = aws_s3_bucket.secure_evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access-logs/"
}
