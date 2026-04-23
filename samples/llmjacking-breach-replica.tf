# ============================================================
# LLMjacking / AI-Assisted Cloud Breach Replica
# Source: Sysdig Threat Research Team, February 2026
#   theregister.com/2026/02/04/aws_cloud_breakin_ai_assist/
#   csoonline.com/article/4126336
# Incident date: November 2025
# PURPOSE: Swarm threat modeling test only.
# DO NOT DEPLOY to production.
# ============================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

# ── VPC ──────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "llmjacking-replica-vpc" }
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

# ── MISCONFIGURATION 1: Public S3 bucket with exposed keys ──
# Source: "attack began with the discovery of valid AWS
# credentials exposed in publicly accessible S3 buckets.
# These buckets were used to store RAG data for AI models"
# — Sysdig / CSO Online

resource "aws_s3_bucket" "rag_data" {
  bucket = "llmjacking-rag-data-public"
  tags   = { Purpose = "RAG data for AI models" }
}

# MISCONFIGURATION: Public access not blocked
resource "aws_s3_bucket_public_access_block" "rag_data" {
  bucket                  = aws_s3_bucket.rag_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# IAM access keys stored in the bucket (in .env files
# and configuration documents uploaded to the RAG bucket)
# This represents the exposed long-lived credentials

resource "aws_s3_bucket" "model_artifacts" {
  bucket = "llmjacking-model-artifacts"
  tags   = { Purpose = "Model artifacts and configs" }
}

resource "aws_s3_bucket" "internal_data" {
  bucket = "llmjacking-internal-data"
  tags   = { DataClass = "Internal" }
}

# ── MISCONFIGURATION 2: IAM user with long-lived keys ───────
# Source: "exposed credentials belonged to an IAM user with
# ReadOnlyAccess policy attached, along with limited
# permissions for Amazon Bedrock"
# Sysdig: "this user was likely created to automate
# Bedrock tasks with Lambda functions"

resource "aws_iam_user" "automation_user" {
  name = "bedrock-automation-user"
  tags = { Purpose = "Bedrock Lambda automation" }
}

# Long-lived access key — never rotated
# Keys uploaded to RAG bucket in config files
resource "aws_iam_access_key" "automation_key" {
  user = aws_iam_user.automation_user.name
  # MISCONFIGURATION: Long-lived key, no rotation policy
}

resource "aws_iam_user_policy_attachment" "readonly" {
  user       = aws_iam_user.automation_user.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Additional Bedrock permissions on the automation user
resource "aws_iam_user_policy" "bedrock_policy" {
  name = "bedrock-automation-policy"
  user = aws_iam_user.automation_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "bedrock:InvokeModel",
          "bedrock:ListFoundationModels",
          "bedrock:GetFoundationModel"
        ]
        Resource = ["*"]
      },
      # MISCONFIGURATION: Lambda modification permissions
      # on a user that also has ReadOnlyAccess
      # Source: "compromised user had UpdateFunctionCode
      # and UpdateFunctionConfiguration permissions"
      {
        Effect   = "Allow"
        Action   = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:InvokeFunction",
          "lambda:GetFunction"
        ]
        Resource = ["*"]
      }
    ]
  })
}

# ── MISCONFIGURATION 3: Lambda with admin execution role ────
# Source: "attacker modified an existing Lambda function
# that ran under an overly permissive execution role.
# Attacker injected malicious code to create new access
# keys for an administrative user" — Sysdig

resource "aws_iam_role" "lambda_exec_role" {
  name = "ec2-init-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# EC2-init Lambda — the function the attacker injected code into
# Source: "attacker modified a function named EC2-init
# three times, iterating on their target user"
resource "aws_lambda_function" "ec2_init" {
  filename         = "ec2init.zip"
  function_name    = "EC2-init"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.11"

  # MISCONFIGURATION: Function runs under AdministratorAccess
  # Any code injected here runs as admin
}

resource "aws_lambda_function" "bedrock_processor" {
  filename         = "bedrock_processor.zip"
  function_name    = "bedrock-rag-processor"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.11"

  environment {
    variables = {
      BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet"
      RAG_BUCKET       = aws_s3_bucket.rag_data.id
      # MISCONFIGURATION: API keys in env vars
      OPENAI_API_KEY   = "sk-exposed-key-example"
    }
  }
}

# ── MISCONFIGURATION 4: Bedrock access without controls ─────
# Source: "they abused the user's Amazon Bedrock access to
# invoke multiple models including Claude, DeepSeek, Llama"
# Sysdig: "invoking Bedrock models that no one in the
# account uses is a red flag"

# No Bedrock model invocation logging configured
# No SCP restricting which models can be invoked
# No spend limit or rate limiting on Bedrock

# ── EC2 FOR GPU WORKLOADS ────────────────────────────────────
# Source: "attackers attempted to initiate high-end GPU
# instances. A costly GPU instance was eventually launched,
# with scripts to install CUDA, deploy training frameworks,
# and expose a public JupyterLab interface"
# — Sysdig / CSO Online

resource "aws_security_group" "gpu_sg" {
  name   = "gpu-instance-sg"
  vpc_id = aws_vpc.main.id

  # MISCONFIGURATION: JupyterLab exposed publicly
  # Source: "expose a public JupyterLab interface,
  # creating a backdoor that would allow continued access
  # to the instance even if AWS credentials were later revoked"
  ingress {
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # JupyterLab open to internet
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SSH open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "gpu_worker" {
  # p4d.24xlarge equivalent for ML workloads
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "p3.2xlarge"
  subnet_id     = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.gpu_sg.id]

  # MISCONFIGURATION: IMDSv1 on GPU instance
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  iam_instance_profile = aws_iam_instance_profile.gpu_profile.name

  user_data = base64encode(<<-EOF
    #!/bin/bash
    pip install torch cuda jupyterlab
    jupyter lab --ip=0.0.0.0 --no-browser &
  EOF
  )

  associate_public_ip_address = true
}

resource "aws_iam_instance_profile" "gpu_profile" {
  name = "gpu-instance-profile"
  role = aws_iam_role.gpu_role.name
}

resource "aws_iam_role" "gpu_role" {
  name = "gpu-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "gpu_admin" {
  role       = aws_iam_role.gpu_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ── CLOUDTRAIL — no Bedrock logging ─────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "llmjacking-trail"
  s3_bucket_name                = aws_s3_bucket.internal_data.id
  include_global_service_events = true
  is_multi_region_trail         = false
  # No Bedrock model invocation logging
  # No S3 data event logging
  # No Lambda invocation logging
}