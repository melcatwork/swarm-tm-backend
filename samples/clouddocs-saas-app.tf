# ==============================================================================
# CloudDocs SaaS Application - Document Management Platform
# ==============================================================================
# This Terraform configuration represents a typical multi-tier SaaS application
# with INTENTIONAL security vulnerabilities for threat modeling demonstration.
#
# Application: CloudDocs - Cloud-based document collaboration platform
# Tier: Production environment serving 10,000+ users
# Attack Surface: Public web application, API endpoints, document storage
# ==============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# ==============================================================================
# VPC and Networking
# ==============================================================================

resource "aws_vpc" "clouddocs_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "clouddocs-vpc"
    Environment = "production"
    Application = "clouddocs"
  }
}

# Public subnets for web tier
resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.clouddocs_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "clouddocs-public-1a"
    Tier = "web"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.clouddocs_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true

  tags = {
    Name = "clouddocs-public-1b"
    Tier = "web"
  }
}

# Private subnets for application tier
resource "aws_subnet" "app_subnet_1" {
  vpc_id            = aws_vpc.clouddocs_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "clouddocs-app-1a"
    Tier = "application"
  }
}

resource "aws_subnet" "app_subnet_2" {
  vpc_id            = aws_vpc.clouddocs_vpc.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "clouddocs-app-1b"
    Tier = "application"
  }
}

# Database subnets
resource "aws_subnet" "db_subnet_1" {
  vpc_id            = aws_vpc.clouddocs_vpc.id
  cidr_block        = "10.0.20.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "clouddocs-db-1a"
    Tier = "database"
  }
}

resource "aws_subnet" "db_subnet_2" {
  vpc_id            = aws_vpc.clouddocs_vpc.id
  cidr_block        = "10.0.21.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "clouddocs-db-1b"
    Tier = "database"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.clouddocs_vpc.id

  tags = {
    Name = "clouddocs-igw"
  }
}

# VULNERABILITY: No NAT Gateway - application tier has no outbound internet
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.clouddocs_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "clouddocs-public-rt"
  }
}

resource "aws_route_table_association" "public_rta_1" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_rta_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

# ==============================================================================
# Security Groups
# ==============================================================================

# VULNERABILITY: Overly permissive web security group
resource "aws_security_group" "web_sg" {
  name        = "clouddocs-web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.clouddocs_vpc.id

  # HTTP from anywhere
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS from anywhere
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: SSH from anywhere for "debugging"
  ingress {
    description = "SSH from internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: All outbound traffic allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "clouddocs-web-sg"
  }
}

# Application tier security group
resource "aws_security_group" "app_sg" {
  name        = "clouddocs-app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.clouddocs_vpc.id

  # VULNERABILITY: Accept all traffic from web tier
  ingress {
    description     = "All from web tier"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.web_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "clouddocs-app-sg"
  }
}

# Database security group
resource "aws_security_group" "db_sg" {
  name        = "clouddocs-db-sg"
  description = "Security group for database"
  vpc_id      = aws_vpc.clouddocs_vpc.id

  # VULNERABILITY: Database accessible from entire VPC
  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "clouddocs-db-sg"
  }
}

# ==============================================================================
# IAM Roles and Policies
# ==============================================================================

# Web server IAM role
resource "aws_iam_role" "web_server_role" {
  name = "clouddocs-web-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "web-server-role"
  }
}

# VULNERABILITY: Web servers have full S3 access including ability to read/write ANY bucket
resource "aws_iam_role_policy" "web_server_s3_policy" {
  name = "web-server-s3-access"
  role = aws_iam_role.web_server_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY: Web servers can read secrets from Secrets Manager
resource "aws_iam_role_policy" "web_server_secrets_policy" {
  name = "web-server-secrets-access"
  role = aws_iam_role.web_server_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "web_server_profile" {
  name = "clouddocs-web-server-profile"
  role = aws_iam_role.web_server_role.name
}

# Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "clouddocs-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY: Lambda has overly broad permissions
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-execution-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "rds:*",
          "logs:*",
          "secretsmanager:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==============================================================================
# S3 Buckets
# ==============================================================================

# VULNERABILITY: Public S3 bucket for user-uploaded documents
resource "aws_s3_bucket" "user_documents" {
  bucket = "clouddocs-user-documents-prod-2024"

  tags = {
    Name        = "user-documents"
    Environment = "production"
    DataClass   = "sensitive"
  }
}

# VULNERABILITY: No versioning for audit trail
resource "aws_s3_bucket_versioning" "user_documents_versioning" {
  bucket = aws_s3_bucket.user_documents.id

  versioning_configuration {
    status = "Disabled"
  }
}

# VULNERABILITY: Bucket ACL allows public read
resource "aws_s3_bucket_public_access_block" "user_documents_pab" {
  bucket = aws_s3_bucket.user_documents.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILITY: No encryption at rest
# (Intentionally not configuring encryption)

# Static assets bucket
resource "aws_s3_bucket" "static_assets" {
  bucket = "clouddocs-static-assets-prod-2024"

  tags = {
    Name        = "static-assets"
    Environment = "production"
  }
}

# Backup bucket - VULNERABILITY: Same account, accessible by compromised credentials
resource "aws_s3_bucket" "backups" {
  bucket = "clouddocs-backups-prod-2024"

  tags = {
    Name        = "backups"
    Environment = "production"
    DataClass   = "critical"
  }
}

# Application logs bucket
resource "aws_s3_bucket" "app_logs" {
  bucket = "clouddocs-app-logs-prod-2024"

  tags = {
    Name        = "app-logs"
    Environment = "production"
  }
}

# ==============================================================================
# RDS Database
# ==============================================================================

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "clouddocs-db-subnet-group"
  subnet_ids = [aws_subnet.db_subnet_1.id, aws_subnet.db_subnet_2.id]

  tags = {
    Name = "clouddocs-db-subnet-group"
  }
}

# VULNERABILITY: Unencrypted database with weak password
resource "aws_db_instance" "documents_db" {
  identifier             = "clouddocs-documents-db"
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.large"
  allocated_storage      = 100
  storage_type           = "gp3"
  db_name                = "clouddocs"
  username               = "dbadmin"
  password               = "CloudDocs2024!Admin" # VULNERABILITY: Hardcoded weak password
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # VULNERABILITY: No encryption
  storage_encrypted = false

  # VULNERABILITY: Single AZ
  multi_az = false

  # VULNERABILITY: Publicly accessible flag (though in private subnet)
  publicly_accessible = false

  # VULNERABILITY: Short backup retention
  backup_retention_period = 3
  backup_window           = "03:00-04:00"

  # VULNERABILITY: Deletion protection disabled
  deletion_protection = false
  skip_final_snapshot = true

  # VULNERABILITY: No performance insights or enhanced monitoring
  enabled_cloudwatch_logs_exports = []

  tags = {
    Name        = "documents-database"
    Environment = "production"
    DataClass   = "user-data"
  }
}

# ==============================================================================
# EC2 Instances - Web Tier
# ==============================================================================

# VULNERABILITY: IMDSv1 enabled, unencrypted volumes, hardcoded credentials
resource "aws_instance" "web_server_1" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.web_server_profile.name

  # VULNERABILITY: IMDSv1 enabled (allows metadata service exploitation)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # VULNERABILITY: Should be "required" for IMDSv2
    http_put_response_hop_limit = 1
  }

  # VULNERABILITY: Unencrypted root volume
  root_block_device {
    volume_size           = 50
    volume_type           = "gp3"
    encrypted             = false
    delete_on_termination = true
  }

  # VULNERABILITY: Hardcoded database credentials in user data
  user_data = <<-EOF
              #!/bin/bash
              echo "export DB_HOST=${aws_db_instance.documents_db.endpoint}" >> /etc/environment
              echo "export DB_NAME=clouddocs" >> /etc/environment
              echo "export DB_USER=dbadmin" >> /etc/environment
              echo "export DB_PASSWORD=CloudDocs2024!Admin" >> /etc/environment
              echo "export AWS_DEFAULT_REGION=us-west-2" >> /etc/environment
              echo "export API_KEY=sk-prod-clouddocs-abc123xyz789" >> /etc/environment
              echo "export JWT_SECRET=super-secret-jwt-key-12345" >> /etc/environment

              # Install application
              apt-get update
              apt-get install -y nginx python3 python3-pip
              pip3 install flask psycopg2-binary boto3
              EOF

  tags = {
    Name        = "clouddocs-web-1"
    Environment = "production"
    Tier        = "web"
  }
}

resource "aws_instance" "web_server_2" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.public_subnet_2.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.web_server_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 50
    encrypted   = false
  }

  user_data = <<-EOF
              #!/bin/bash
              echo "export DB_HOST=${aws_db_instance.documents_db.endpoint}" >> /etc/environment
              echo "export DB_PASSWORD=CloudDocs2024!Admin" >> /etc/environment
              EOF

  tags = {
    Name        = "clouddocs-web-2"
    Environment = "production"
    Tier        = "web"
  }
}

# ==============================================================================
# Application Load Balancer
# ==============================================================================

resource "aws_lb" "web_alb" {
  name               = "clouddocs-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web_sg.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  # VULNERABILITY: No access logs
  # access_logs not configured

  # VULNERABILITY: Deletion protection disabled
  enable_deletion_protection = false

  tags = {
    Name        = "clouddocs-alb"
    Environment = "production"
  }
}

resource "aws_lb_target_group" "web_tg" {
  name     = "clouddocs-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.clouddocs_vpc.id

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 5
    interval            = 30
  }

  tags = {
    Name = "clouddocs-web-tg"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web_alb.arn
  port              = "80"
  protocol          = "HTTP"

  # VULNERABILITY: No HTTPS, plain HTTP only
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

resource "aws_lb_target_group_attachment" "web_1" {
  target_group_arn = aws_lb_target_group.web_tg.arn
  target_id        = aws_instance.web_server_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "web_2" {
  target_group_arn = aws_lb_target_group.web_tg.arn
  target_id        = aws_instance.web_server_2.id
  port             = 80
}

# ==============================================================================
# Lambda Functions
# ==============================================================================

# Document processing Lambda
resource "aws_lambda_function" "document_processor" {
  filename         = "lambda_placeholder.zip"
  function_name    = "clouddocs-document-processor"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("lambda_placeholder.zip")
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 1024

  # VULNERABILITY: Secrets in environment variables
  environment {
    variables = {
      DB_HOST          = aws_db_instance.documents_db.endpoint
      DB_PASSWORD      = "CloudDocs2024!Admin"
      DOCUMENTS_BUCKET = aws_s3_bucket.user_documents.id
      API_KEY          = "sk-external-api-abc123"
      OPENAI_API_KEY   = "sk-openai-xyz789"
    }
  }

  tags = {
    Name        = "document-processor"
    Environment = "production"
  }
}

# ==============================================================================
# Secrets Manager (partial implementation showing inconsistency)
# ==============================================================================

# VULNERABILITY: Some secrets in Secrets Manager, but most are hardcoded
resource "aws_secretsmanager_secret" "api_keys" {
  name        = "clouddocs/api-keys"
  description = "API keys for external services"

  tags = {
    Application = "clouddocs"
  }
}

resource "aws_secretsmanager_secret_version" "api_keys_version" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    stripe_api_key = "sk_live_stripe123456"
    sendgrid_key   = "SG.sendgrid123456"
  })
}

# ==============================================================================
# DynamoDB Table
# ==============================================================================

# VULNERABILITY: No point-in-time recovery, no encryption
resource "aws_dynamodb_table" "user_sessions" {
  name         = "clouddocs-user-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  # VULNERABILITY: No point-in-time recovery
  point_in_time_recovery {
    enabled = false
  }

  # VULNERABILITY: Server-side encryption not explicitly configured
  # (AWS enables default encryption, but not KMS)

  tags = {
    Name        = "user-sessions"
    Environment = "production"
  }
}

# ==============================================================================
# CloudWatch (minimal configuration showing gaps)
# ==============================================================================

# VULNERABILITY: Very short log retention
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/application/clouddocs"
  retention_in_days = 3 # VULNERABILITY: Too short

  tags = {
    Application = "clouddocs"
  }
}

# ==============================================================================
# SNS Topic (for alerts)
# ==============================================================================

resource "aws_sns_topic" "alerts" {
  name = "clouddocs-alerts"

  tags = {
    Application = "clouddocs"
  }
}

# VULNERABILITY: SNS topic not encrypted

# ==============================================================================
# Route53 (DNS)
# ==============================================================================

# Assuming Route53 hosted zone exists
# VULNERABILITY: No DNSSEC enabled

# ==============================================================================
# Outputs
# ==============================================================================

output "alb_dns_name" {
  description = "DNS name of the application load balancer"
  value       = aws_lb.web_alb.dns_name
}

output "database_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.documents_db.endpoint
  sensitive   = true
}

output "user_documents_bucket" {
  description = "S3 bucket for user documents"
  value       = aws_s3_bucket.user_documents.id
}

output "web_server_1_ip" {
  description = "Public IP of web server 1"
  value       = aws_instance.web_server_1.public_ip
}

output "web_server_2_ip" {
  description = "Public IP of web server 2"
  value       = aws_instance.web_server_2.public_ip
}
