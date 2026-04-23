# ============================================================
# SCARLETEEL Operation Architecture Replica
# Source: Sysdig Threat Research Team, February 2023
#   https://sysdig.com/blog/cloud-breach-terraform-data-theft
# Corroborated: BleepingComputer, The Stack, Falco blog
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
  tags = { Name = "scarleteel-replica-vpc" }
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

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
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

# ── EKS CLUSTER (self-managed Kubernetes) ────────────────────
# Source: "exploiting a public-facing service in a
# self-managed Kubernetes cluster hosted on AWS"
# Sysdig SCARLETEEL report

resource "aws_eks_cluster" "main" {
  name     = "scarleteel-eks"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public.id,
      aws_subnet.private.id,
    ]
    endpoint_public_access  = true   # MISCONFIGURATION: public
    endpoint_private_access = false
  }
}

# ── MISCONFIGURATION 1: EKS node group with IMDSv1 ──────────
# Source: "Retrieving AWS temporary security credentials
# bound to the EC2 instance role from IMDS v1 is a very
# well-known practice" — Sysdig report
# The attacker used curl to 169.254.169.254 to steal
# the worker node's IAM role credentials

resource "aws_launch_template" "eks_nodes" {
  name_prefix   = "scarleteel-eks-node-"
  instance_type = "t3.large"
  image_id      = "ami-0c02fb55956c7d316"

  # MISCONFIGURATION: IMDSv1 enabled on worker nodes
  # Sysdig: "attacker obtained AccessKeyId, SecretAccessKey
  # and temporary token" via IMDSv1
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2  # hop_limit=2 allows
    # containers to reach IMDS — another misconfiguration
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.eks_node_profile.name
  }
}

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "scarleteel-workers"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private.id]

  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = "$Latest"
  }

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }
}

# ── MISCONFIGURATION 2: EKS node IAM role with              ──
# excessive S3 read permissions                              ──
# Source: "The original intent was to allow the reading of
# a specific S3 bucket, but the permissions allowed the role
# to read everything in the account" — The Stack / Sysdig
# This let the attacker enumerate ALL buckets and extract
# proprietary Lambda code and Terraform state files

resource "aws_iam_role" "eks_node_role" {
  name = "scarleteel-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# MISCONFIGURATION: Overly broad S3 read — should be
# scoped to specific bucket but grants access to ALL
resource "aws_iam_role_policy" "eks_node_s3_policy" {
  name = "eks-node-s3-overpermissive"
  role = aws_iam_role.eks_node_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket",
                    "s3:ListAllMyBuckets"]
        Resource = ["*"]   # should be specific bucket ARN
      },
      # MISCONFIGURATION: Lambda read access enables
      # stealing function code and environment variables
      {
        Effect   = "Allow"
        Action   = ["lambda:GetFunction",
                    "lambda:ListFunctions",
                    "lambda:GetFunctionConfiguration"]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "eks_node_profile" {
  name = "scarleteel-eks-node-profile"
  role = aws_iam_role.eks_node_role.name
}

# ── EKS CLUSTER IAM ROLE ─────────────────────────────────────
resource "aws_iam_role" "eks_cluster_role" {
  name = "scarleteel-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ── LAMBDA FUNCTIONS ─────────────────────────────────────────
# Source: "The Lambda function held proprietary software and
# the keys needed to execute it" — Sysdig
# Attacker exfiltrated Lambda code and found IAM user
# credentials in Lambda environment variables

resource "aws_lambda_function" "proprietary_processor" {
  filename      = "function.zip"
  function_name = "proprietary-data-processor"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  # MISCONFIGURATION: Credentials in environment variables
  # Sysdig: "attacker took the time to look at the Lambda
  # function's environment variables and find additional AWS
  # credentials related to IAM users in the same account"
  environment {
    variables = {
      DB_PASSWORD      = "hardcoded-db-password-123"
      IAM_ACCESS_KEY   = "AKIAIOSFODNN7EXAMPLE"  # exposed key
      IAM_SECRET_KEY   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      ENVIRONMENT      = "production"
      PROPRIETARY_KEY  = "license-key-abc123"
    }
  }
}

resource "aws_lambda_function" "ec2_init" {
  filename      = "ec2init.zip"
  function_name = "EC2-init"
  role          = aws_iam_role.lambda_admin_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  # MISCONFIGURATION: This Lambda runs under an admin role
  # Sysdig 2025: "attacker modified this Lambda function
  # to escalate privileges — injected code to create
  # new access keys for admin user"
}

# MISCONFIGURATION 3: Lambda execution role has IAM write
# Source: "attacker took time to look at Lambda environment
# variables and find credentials for IAM users"
# The proprietary_processor role has excessive permissions

resource "aws_iam_role" "lambda_execution_role" {
  name = "scarleteel-lambda-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_execution_policy" {
  name = "lambda-overpermissive"
  role = aws_iam_role.lambda_execution_role.id

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
        Action   = ["iam:CreateUser", "iam:CreateAccessKey",
                    "iam:AttachUserPolicy", "iam:PutUserPolicy",
                    "iam:CreateRole", "iam:PassRole",
                    "iam:AttachRolePolicy"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:*"]
        Resource = ["*"]
      }
    ]
  })
}

# Lambda admin role — used by EC2-init function
# Source: Sysdig 2025 report — attacker injected code into
# this function to create admin access keys
resource "aws_iam_role" "lambda_admin_role" {
  name = "scarleteel-lambda-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin_policy" {
  role       = aws_iam_role.lambda_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ── S3 BUCKETS ───────────────────────────────────────────────

# MISCONFIGURATION 4: Terraform state file in S3
# Source: "attacker was able to list the bucket and retrieve
# Terraform state files containing a clear-text IAM user
# access key and secret key in the terraform.tfstate file"
# — The Stack / Sysdig
resource "aws_s3_bucket" "terraform_state" {
  bucket = "scarleteel-terraform-state"
  tags   = { Name = "Terraform state", Risk = "Critical" }
  # MISCONFIGURATION: No versioning, no encryption,
  # readable by EKS node role via overpermissive S3 policy
}

# Proprietary software bucket
resource "aws_s3_bucket" "proprietary_software" {
  bucket = "scarleteel-proprietary-software"
  tags   = { Name = "Proprietary code" }
  # No bucket policy restricting access
}

# Customer data bucket
resource "aws_s3_bucket" "customer_data" {
  bucket = "scarleteel-customer-data"
  tags   = { Name = "Customer data", DataClass = "Restricted" }
}

# Log bucket — also readable and contains operational data
resource "aws_s3_bucket" "logs" {
  bucket = "scarleteel-logs"
  tags   = { Name = "Application logs" }
}

# MISCONFIGURATION 5: No encryption on sensitive buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ── CLOUDTRAIL ───────────────────────────────────────────────
# MISCONFIGURATION 6: CloudTrail disabled mid-attack
# Source: "attacker succeeded in disabling some of the
# CloudTrail logs configured in the account because of
# extra permissions assigned to one of the users
# compromised in the previous steps" — Sysdig / Falco

resource "aws_cloudtrail" "main" {
  name                          = "scarleteel-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  include_global_service_events = true
  is_multi_region_trail         = false  # single region only
  # No event_selector for S3 data events
  # No KMS encryption on trail
}

# IAM user with permissions to stop CloudTrail
# This user's credentials were found in compromised Lambda
resource "aws_iam_user" "automation_user" {
  name = "automation-service-user"
  tags = { Purpose = "Automation" }
}

resource "aws_iam_user_policy" "automation_policy" {
  name = "automation-overpermissive"
  user = aws_iam_user.automation_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:InvokeFunction"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["iam:CreateAccessKey",
                    "iam:CreateUser",
                    "iam:AttachUserPolicy"]
        Resource = ["*"]
      }
    ]
  })
}

# ── SECURITY GROUPS ──────────────────────────────────────────
resource "aws_security_group" "eks_public" {
  name   = "eks-public-sg"
  vpc_id = aws_vpc.main.id

  # Public-facing service — the entry point
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: Unrestricted egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── RDS (contains operational data) ─────────────────────────
resource "aws_db_instance" "operations" {
  identifier             = "scarleteel-ops-db"
  engine                 = "mysql"
  engine_version         = "8.0.35"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  db_name                = "operations"
  username               = "admin"
  password               = "change-before-deploy"
  skip_final_snapshot    = true
  storage_encrypted      = false    # MISCONFIGURATION
  publicly_accessible    = false
  deletion_protection    = false

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
}

resource "aws_db_subnet_group" "main" {
  name       = "scarleteel-db-subnet"
  subnet_ids = [aws_subnet.private.id]
}

resource "aws_security_group" "rds_sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_public.id]
  }
}