# ============================================================
# Capital One Breach Architecture Replica
# Source: FBI Indictment 2:19-cr-00159, ACM TOPS 2022,
#         Rhino Security Labs (2019), Snyk/Fugue (2019)
# PURPOSE: Swarm threat modeling test only.
# DO NOT DEPLOY to production.
# ============================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ── VPC ──────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = { Name = "capitalone-replica-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ── MISCONFIGURATION 1: Overly permissive security group ─────
# Breach context: WAF EC2 instance was internet-facing
# with no meaningful egress restriction, allowing SSRF
# to reach the metadata service.
resource "aws_security_group" "waf_sg" {
  name        = "waf-security-group"
  description = "Security group for WAF EC2 instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # MISCONFIGURATION: Unrestricted egress allows SSRF
  # to reach 169.254.169.254 (IMDSv1)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Unrestricted egress — allows SSRF to IMDS"
  }

  tags = { Name = "waf-sg" }
}

# ── MISCONFIGURATION 2: Over-provisioned IAM role ────────────
# Breach context: The role "ISRM-WAF-Role" attached to the
# EC2 instance had s3:* permissions across all buckets.
# Source: ACM TOPS 2022, FBI indictment III.A.11
resource "aws_iam_role" "waf_role" {
  name = "ISRM-WAF-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "WAF execution role" }
}

# MISCONFIGURATION: s3:* on all resources — wildcard
# gives list, get, put, delete across every bucket
resource "aws_iam_role_policy" "waf_s3_policy" {
  name = "waf-s3-overpermissive"
  role = aws_iam_role.waf_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["iam:ListRoles", "iam:GetRole",
                    "iam:PassRole"]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "waf_profile" {
  name = "waf-instance-profile"
  role = aws_iam_role.waf_role.name
}

# ── MISCONFIGURATION 3: EC2 with IMDSv1 enabled ──────────────
# Breach context: IMDSv1 was used, which responds to
# unauthenticated GET requests from any process on the instance
# including an SSRF-triggered request from the WAF.
# IMDSv2 would have required a PUT token first.
resource "aws_instance" "waf_ec2" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.waf_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.waf_profile.name
  associate_public_ip_address = true

  # MISCONFIGURATION: IMDSv1 enabled (hop_limit=1 is default
  # but http_tokens = "optional" means IMDSv1 still works)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"   # IMDSv1 allowed
    http_put_response_hop_limit = 1
  }

  user_data = <<-EOF
    #!/bin/bash
    # ModSecurity WAF running as reverse proxy
    # Misconfigured to forward arbitrary host headers
    # including 169.254.169.254
    yum install -y mod_security httpd
    systemctl enable httpd
    systemctl start httpd
  EOF

  tags = { Name = "waf-reverse-proxy" }
}

# ── MISCONFIGURATION 4: S3 buckets with sensitive PII ────────
# Breach context: 700+ S3 buckets were accessible via the
# overpermissive WAF role. Buckets contained credit application
# data, SSNs, bank account numbers.
resource "aws_s3_bucket" "customer_data" {
  bucket = "capitalone-credit-applications-pii"
  tags   = { Name = "PII data store", DataClass = "Restricted" }
}

# MISCONFIGURATION: No public access block configured
resource "aws_s3_bucket" "internal_reports" {
  bucket = "capitalone-internal-financial-reports"
  tags   = { Name = "Financial reports" }
}

resource "aws_s3_bucket" "application_backups" {
  bucket = "capitalone-application-backups"
  tags   = { Name = "App backups" }
}

# MISCONFIGURATION: No server-side encryption configured
# on the primary PII bucket (encryption key was accessible
# via the same over-permissioned role)
resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# MISCONFIGURATION: No bucket policy restricting access
# to specific roles or VPC endpoints only
# (absent = any authenticated AWS principal with s3:* can access)

# ── MISCONFIGURATION 5: No CloudTrail on S3 data events ──────
# Breach context: The attacker exfiltrated 30GB across 700
# buckets and was not detected. CloudTrail S3 data events
# were not enabled, so API calls were not logged.
resource "aws_cloudtrail" "management_trail" {
  name                          = "management-events-only"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false

  # MISCONFIGURATION: No event_selector for S3 data events
  # Management events captured but NOT s3:GetObject,
  # s3:ListBucket — the exact API calls used in the breach
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "capitalone-cloudtrail-logs"
}

# ── MISCONFIGURATION 6: No GuardDuty ─────────────────────────
# GuardDuty would have flagged the unusual IAM credential
# usage and large-volume S3 API calls from an EC2 instance.
# It was not enabled.

# ── APPLICATION LAYER (backend services) ─────────────────────
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_security_group" "app_sg" {
  name   = "app-security-group"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.waf_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app_server" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.waf_profile.name

  # MISCONFIGURATION: Same over-permissioned IAM profile
  # attached to application servers as well
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  tags = { Name = "credit-application-server" }
}

# ── RDS (credit application database) ────────────────────────
resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet"
  subnet_ids = [aws_subnet.private.id]
}

resource "aws_security_group" "rds_sg" {
  name   = "rds-security-group"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}

resource "aws_db_instance" "credit_db" {
  identifier             = "credit-applications-db"
  engine                 = "postgres"
  engine_version         = "14.9"
  instance_class         = "db.t3.large"
  allocated_storage      = 100
  db_name                = "creditapps"
  username               = "dbadmin"
  password               = "change-me-before-deploy"
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # MISCONFIGURATION: Automated backups going to S3
  # accessible by the over-permissioned WAF role
  backup_retention_period    = 7
  skip_final_snapshot        = true
  deletion_protection        = false

  # MISCONFIGURATION: Storage not encrypted
  storage_encrypted = false
}