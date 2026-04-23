# ==============================================================================
# E-Commerce Platform Infrastructure (OpenCart/Magento-style Architecture)
# ==============================================================================
# This Terraform configuration represents a typical multi-tier e-commerce platform
# with intentional security gaps to demonstrate insider threat attack paths.
#
# Application: CloudMarket - Open Source E-Commerce Platform
# Components: Web tier, API tier, database, file storage, background workers
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
  region = "us-east-1"
}

# ==============================================================================
# VPC and Networking
# ==============================================================================

resource "aws_vpc" "ecommerce_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "ecommerce-vpc"
    Environment = "production"
    Application = "cloudmarket"
  }
}

resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.ecommerce_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "ecommerce-public-1a"
    Tier = "public"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.ecommerce_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "ecommerce-public-1b"
    Tier = "public"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.ecommerce_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "ecommerce-private-1a"
    Tier = "private"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.ecommerce_vpc.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "ecommerce-private-1b"
    Tier = "private"
  }
}

resource "aws_internet_gateway" "ecommerce_igw" {
  vpc_id = aws_vpc.ecommerce_vpc.id

  tags = {
    Name = "ecommerce-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.ecommerce_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ecommerce_igw.id
  }

  tags = {
    Name = "ecommerce-public-rt"
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

resource "aws_security_group" "web_sg" {
  name        = "ecommerce-web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.ecommerce_vpc.id

  # VULNERABILITY: Overly permissive - allows all traffic from internet
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: SSH exposed to internet
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ecommerce-web-sg"
  }
}

resource "aws_security_group" "database_sg" {
  name        = "ecommerce-database-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.ecommerce_vpc.id

  # VULNERABILITY: Database accessible from entire VPC, not just app tier
  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ecommerce-database-sg"
  }
}

# ==============================================================================
# IAM Roles and Policies
# ==============================================================================

# Developer Role - VULNERABILITY: Excessive permissions for day-to-day work
resource "aws_iam_role" "developer_role" {
  name = "ecommerce-developer-role"

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
    Name = "developer-role"
    Team = "engineering"
  }
}

# VULNERABILITY: Developers have broad S3 access including customer data
resource "aws_iam_role_policy" "developer_s3_policy" {
  name = "developer-s3-access"
  role = aws_iam_role.developer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.customer_data.arn}",
          "${aws_s3_bucket.customer_data.arn}/*",
          "${aws_s3_bucket.product_images.arn}",
          "${aws_s3_bucket.product_images.arn}/*",
          "${aws_s3_bucket.order_exports.arn}",
          "${aws_s3_bucket.order_exports.arn}/*"
        ]
      }
    ]
  })
}

# VULNERABILITY: Developers can read secrets
resource "aws_iam_role_policy" "developer_secrets_policy" {
  name = "developer-secrets-access"
  role = aws_iam_role.developer_role.id

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

# Application Server Role
resource "aws_iam_role" "app_server_role" {
  name = "ecommerce-app-server-role"

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
}

# VULNERABILITY: App servers have excessive RDS permissions
resource "aws_iam_role_policy" "app_server_rds_policy" {
  name = "app-rds-access"
  role = aws_iam_role.app_server_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:CreateDBSnapshot",
          "rds:DeleteDBSnapshot",
          "rds:DownloadDBLogFilePortion"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "developer_profile" {
  name = "ecommerce-developer-profile"
  role = aws_iam_role.developer_role.name
}

resource "aws_iam_instance_profile" "app_server_profile" {
  name = "ecommerce-app-server-profile"
  role = aws_iam_role.app_server_role.name
}

# ==============================================================================
# S3 Buckets
# ==============================================================================

# VULNERABILITY: Customer data bucket without encryption at rest
resource "aws_s3_bucket" "customer_data" {
  bucket = "cloudmarket-customer-data-prod"

  tags = {
    Name        = "customer-data"
    Environment = "production"
    DataClass   = "PII"
  }
}

# VULNERABILITY: No versioning for customer data
resource "aws_s3_bucket_versioning" "customer_data_versioning" {
  bucket = aws_s3_bucket.customer_data.id

  versioning_configuration {
    status = "Disabled"
  }
}

# VULNERABILITY: Bucket policy allows overly broad access
resource "aws_s3_bucket_policy" "customer_data_policy" {
  bucket = aws_s3_bucket.customer_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowDeveloperAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.developer_role.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.customer_data.arn}/*"
      }
    ]
  })
}

# Product images bucket - public read
resource "aws_s3_bucket" "product_images" {
  bucket = "cloudmarket-product-images-prod"

  tags = {
    Name        = "product-images"
    Environment = "production"
  }
}

resource "aws_s3_bucket_public_access_block" "product_images_public" {
  bucket = aws_s3_bucket.product_images.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILITY: Order exports bucket - sensitive financial data
resource "aws_s3_bucket" "order_exports" {
  bucket = "cloudmarket-order-exports-prod"

  tags = {
    Name        = "order-exports"
    Environment = "production"
    DataClass   = "Financial"
  }
}

# VULNERABILITY: No encryption for financial data
# VULNERABILITY: Accessible to multiple roles

# ==============================================================================
# RDS Database
# ==============================================================================

resource "aws_db_subnet_group" "ecommerce_db_subnet" {
  name       = "ecommerce-db-subnet"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

  tags = {
    Name = "ecommerce-db-subnet-group"
  }
}

# VULNERABILITY: Database without encryption at rest
# VULNERABILITY: Multi-AZ disabled (availability risk)
# VULNERABILITY: Backup retention too short
resource "aws_db_instance" "ecommerce_db" {
  identifier             = "cloudmarket-prod-db"
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  storage_type           = "gp3"
  db_name                = "cloudmarket"
  username               = "dbadmin"
  password               = "ChangeMeInProduction123!" # VULNERABILITY: Hardcoded password
  db_subnet_group_name   = aws_db_subnet_group.ecommerce_db_subnet.name
  vpc_security_group_ids = [aws_security_group.database_sg.id]

  # VULNERABILITY: Encryption disabled
  storage_encrypted = false

  # VULNERABILITY: Multi-AZ disabled
  multi_az = false

  # VULNERABILITY: Public accessibility (though in private subnet)
  publicly_accessible = false

  # VULNERABILITY: Short backup retention
  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"

  # VULNERABILITY: Auto minor version upgrade disabled
  auto_minor_version_upgrade = false

  # VULNERABILITY: Deletion protection disabled
  deletion_protection = false
  skip_final_snapshot = true

  # VULNERABILITY: Enhanced monitoring disabled
  enabled_cloudwatch_logs_exports = []

  tags = {
    Name        = "cloudmarket-database"
    Environment = "production"
    DataClass   = "Critical"
  }
}

# ==============================================================================
# EC2 Instances
# ==============================================================================

# Web/Application Server
resource "aws_instance" "web_server_1" {
  ami                    = "ami-0c55b159cbfafe1f0" # Amazon Linux 2
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_server_profile.name

  # VULNERABILITY: IMDSv1 enabled (metadata service v1)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # VULNERABILITY: Should be "required" for IMDSv2
    http_put_response_hop_limit = 1
  }

  # VULNERABILITY: No encryption for root volume
  root_block_device {
    volume_size           = 50
    volume_type           = "gp3"
    encrypted             = false
    delete_on_termination = true
  }

  # VULNERABILITY: User data contains sensitive information
  user_data = <<-EOF
              #!/bin/bash
              echo "DB_HOST=${aws_db_instance.ecommerce_db.endpoint}" >> /etc/environment
              echo "DB_PASSWORD=ChangeMeInProduction123!" >> /etc/environment
              echo "API_KEY=sk-prod-1234567890abcdef" >> /etc/environment
              echo "STRIPE_SECRET_KEY=sk_live_51234567890" >> /etc/environment
              EOF

  tags = {
    Name        = "cloudmarket-web-1"
    Environment = "production"
    Role        = "web-app"
  }
}

# Developer workstation instance
resource "aws_instance" "developer_workstation" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.developer_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 100
    encrypted   = false
  }

  tags = {
    Name        = "developer-workstation"
    Environment = "production"
    Owner       = "engineering-team"
  }
}

# ==============================================================================
# Lambda Functions
# ==============================================================================

# Lambda role with excessive permissions
resource "aws_iam_role" "order_processor_lambda_role" {
  name = "order-processor-lambda-role"

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

# VULNERABILITY: Lambda has admin-like permissions
resource "aws_iam_role_policy" "lambda_excessive_policy" {
  name = "lambda-excessive-permissions"
  role = aws_iam_role.order_processor_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "rds:*",
          "secretsmanager:*",
          "lambda:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "order_processor" {
  filename         = "lambda_placeholder.zip"
  function_name    = "cloudmarket-order-processor"
  role             = aws_iam_role.order_processor_lambda_role.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("lambda_placeholder.zip")
  runtime          = "python3.9"
  timeout          = 300
  memory_size      = 512

  # VULNERABILITY: Environment variables contain sensitive data
  environment {
    variables = {
      DB_HOST         = aws_db_instance.ecommerce_db.endpoint
      DB_PASSWORD     = "ChangeMeInProduction123!"
      STRIPE_API_KEY  = "sk_live_51234567890"
      ADMIN_API_TOKEN = "admin-token-abc123xyz"
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_1.id]
    security_group_ids = [aws_security_group.web_sg.id]
  }

  tags = {
    Name        = "order-processor"
    Environment = "production"
  }
}

# ==============================================================================
# Secrets Manager (some secrets, but not all)
# ==============================================================================

# VULNERABILITY: Some secrets in Secrets Manager, but others hardcoded
resource "aws_secretsmanager_secret" "payment_gateway" {
  name        = "cloudmarket/payment-gateway"
  description = "Payment gateway credentials"

  tags = {
    Application = "cloudmarket"
  }
}

resource "aws_secretsmanager_secret_version" "payment_gateway_version" {
  secret_id = aws_secretsmanager_secret.payment_gateway.id
  secret_string = jsonencode({
    api_key    = "pk_live_1234567890"
    api_secret = "sk_live_0987654321"
  })
}

# ==============================================================================
# CloudWatch Logs (minimal logging)
# ==============================================================================

# VULNERABILITY: Short retention period for logs
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/ecommerce/application"
  retention_in_days = 7 # VULNERABILITY: Too short for compliance

  tags = {
    Application = "cloudmarket"
  }
}

# ==============================================================================
# SNS Topic for order notifications
# ==============================================================================

resource "aws_sns_topic" "order_notifications" {
  name = "cloudmarket-order-notifications"

  tags = {
    Application = "cloudmarket"
  }
}

# VULNERABILITY: SNS topic not encrypted
# VULNERABILITY: Overly broad subscription access

# ==============================================================================
# Outputs
# ==============================================================================

output "database_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.ecommerce_db.endpoint
  sensitive   = true
}

output "customer_data_bucket" {
  description = "S3 bucket for customer data"
  value       = aws_s3_bucket.customer_data.id
}

output "web_server_public_ip" {
  description = "Public IP of web server"
  value       = aws_instance.web_server_1.public_ip
}

output "developer_workstation_ip" {
  description = "Public IP of developer workstation"
  value       = aws_instance.developer_workstation.public_ip
}
