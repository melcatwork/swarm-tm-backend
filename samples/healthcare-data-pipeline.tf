# ==============================================================================
# Healthcare Data Processing Pipeline (HIPAA Environment)
# ==============================================================================
# This Terraform configuration represents a medium-complexity healthcare data
# processing system with intentional security gaps for insider threat demonstration.
#
# System: MediFlow - Healthcare Data Analytics Platform
# Components: Data ingestion, ETL pipeline, analytics warehouse, ML processing
# Data Types: PHI (Protected Health Information), PII, billing records
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
# VPC and Network Infrastructure
# ==============================================================================

resource "aws_vpc" "healthcare_vpc" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "mediflow-vpc"
    Environment = "production"
    Compliance  = "HIPAA"
  }
}

resource "aws_subnet" "ingestion_subnet_1" {
  vpc_id                  = aws_vpc.healthcare_vpc.id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "mediflow-ingestion-1a"
    Tier = "ingestion"
  }
}

resource "aws_subnet" "ingestion_subnet_2" {
  vpc_id                  = aws_vpc.healthcare_vpc.id
  cidr_block              = "10.100.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "mediflow-ingestion-1b"
    Tier = "ingestion"
  }
}

resource "aws_subnet" "processing_subnet_1" {
  vpc_id            = aws_vpc.healthcare_vpc.id
  cidr_block        = "10.100.10.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "mediflow-processing-1a"
    Tier = "processing"
  }
}

resource "aws_subnet" "processing_subnet_2" {
  vpc_id            = aws_vpc.healthcare_vpc.id
  cidr_block        = "10.100.11.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "mediflow-processing-1b"
    Tier = "processing"
  }
}

resource "aws_subnet" "data_subnet_1" {
  vpc_id            = aws_vpc.healthcare_vpc.id
  cidr_block        = "10.100.20.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "mediflow-data-1a"
    Tier = "data"
  }
}

resource "aws_subnet" "data_subnet_2" {
  vpc_id            = aws_vpc.healthcare_vpc.id
  cidr_block        = "10.100.21.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "mediflow-data-1b"
    Tier = "data"
  }
}

resource "aws_internet_gateway" "healthcare_igw" {
  vpc_id = aws_vpc.healthcare_vpc.id

  tags = {
    Name = "mediflow-igw"
  }
}

# VULNERABILITY: No NAT Gateway - Lambda functions must use public subnets or have no internet
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.healthcare_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.healthcare_igw.id
  }

  tags = {
    Name = "mediflow-public-rt"
  }
}

resource "aws_route_table_association" "ingestion_rta_1" {
  subnet_id      = aws_subnet.ingestion_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "ingestion_rta_2" {
  subnet_id      = aws_subnet.ingestion_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

# ==============================================================================
# Security Groups
# ==============================================================================

resource "aws_security_group" "api_gateway_sg" {
  name        = "mediflow-api-gateway-sg"
  description = "Security group for API Gateway"
  vpc_id      = aws_vpc.healthcare_vpc.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mediflow-api-sg"
  }
}

resource "aws_security_group" "processing_sg" {
  name        = "mediflow-processing-sg"
  description = "Security group for Lambda processing functions"
  vpc_id      = aws_vpc.healthcare_vpc.id

  # VULNERABILITY: Overly permissive - allows all internal VPC traffic
  ingress {
    description = "All from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.100.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mediflow-processing-sg"
  }
}

resource "aws_security_group" "database_sg" {
  name        = "mediflow-database-sg"
  description = "Security group for RDS databases"
  vpc_id      = aws_vpc.healthcare_vpc.id

  # VULNERABILITY: Database accessible from entire VPC
  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.100.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mediflow-database-sg"
  }
}

resource "aws_security_group" "analyst_workstation_sg" {
  name        = "mediflow-analyst-workstation-sg"
  description = "Security group for data analyst workstations"
  vpc_id      = aws_vpc.healthcare_vpc.id

  # VULNERABILITY: SSH from anywhere
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: RDP from anywhere
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mediflow-analyst-sg"
  }
}

# ==============================================================================
# IAM Roles and Policies
# ==============================================================================

# Data Engineer Role - VULNERABILITY: Excessive S3 permissions
resource "aws_iam_role" "data_engineer_role" {
  name = "mediflow-data-engineer-role"

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
    Name = "data-engineer-role"
    Team = "data-engineering"
  }
}

# VULNERABILITY: Data engineers have full access to all patient data buckets
resource "aws_iam_role_policy" "data_engineer_s3_policy" {
  name = "data-engineer-s3-access"
  role = aws_iam_role.data_engineer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "${aws_s3_bucket.patient_raw_data.arn}",
          "${aws_s3_bucket.patient_raw_data.arn}/*",
          "${aws_s3_bucket.patient_processed_data.arn}",
          "${aws_s3_bucket.patient_processed_data.arn}/*",
          "${aws_s3_bucket.analytics_exports.arn}",
          "${aws_s3_bucket.analytics_exports.arn}/*",
          "${aws_s3_bucket.ml_training_data.arn}",
          "${aws_s3_bucket.ml_training_data.arn}/*"
        ]
      }
    ]
  })
}

# VULNERABILITY: Data engineers can create database snapshots and share them
resource "aws_iam_role_policy" "data_engineer_rds_policy" {
  name = "data-engineer-rds-access"
  role = aws_iam_role.data_engineer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:CreateDBSnapshot",
          "rds:DeleteDBSnapshot",
          "rds:ModifyDBSnapshotAttribute",
          "rds:DescribeDBSnapshots",
          "rds:CopyDBSnapshot"
        ]
        Resource = "*"
      }
    ]
  })
}

# Data Analyst Role - VULNERABILITY: Can query production data directly
resource "aws_iam_role" "data_analyst_role" {
  name = "mediflow-data-analyst-role"

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
    Name = "data-analyst-role"
    Team = "analytics"
  }
}

# VULNERABILITY: Analysts have read access to all S3 data including raw PHI
resource "aws_iam_role_policy" "data_analyst_s3_policy" {
  name = "data-analyst-s3-read"
  role = aws_iam_role.data_analyst_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.patient_raw_data.arn}",
          "${aws_s3_bucket.patient_raw_data.arn}/*",
          "${aws_s3_bucket.patient_processed_data.arn}",
          "${aws_s3_bucket.patient_processed_data.arn}/*",
          "${aws_s3_bucket.analytics_exports.arn}",
          "${aws_s3_bucket.analytics_exports.arn}/*"
        ]
      }
    ]
  })
}

# VULNERABILITY: Analysts can unload Redshift data to S3
resource "aws_iam_role_policy" "data_analyst_redshift_policy" {
  name = "data-analyst-redshift-access"
  role = aws_iam_role.data_analyst_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "redshift:DescribeClusters",
          "redshift:GetClusterCredentials",
          "redshift-data:ExecuteStatement",
          "redshift-data:GetStatementResult"
        ]
        Resource = "*"
      }
    ]
  })
}

# ETL Lambda Role - VULNERABILITY: Overprivileged
resource "aws_iam_role" "etl_lambda_role" {
  name = "mediflow-etl-lambda-role"

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

# VULNERABILITY: Lambda has broad permissions across multiple services
resource "aws_iam_role_policy" "etl_lambda_policy" {
  name = "etl-lambda-permissions"
  role = aws_iam_role.etl_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "rds:*",
          "secretsmanager:*",
          "ssm:*",
          "lambda:InvokeFunction",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# DevOps/CI-CD Role - VULNERABILITY: Can assume production roles
resource "aws_iam_role" "cicd_role" {
  name = "mediflow-cicd-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY: CI/CD can assume other IAM roles including production
resource "aws_iam_role_policy" "cicd_assume_role_policy" {
  name = "cicd-assume-role"
  role = aws_iam_role.cicd_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = [
          aws_iam_role.etl_lambda_role.arn,
          aws_iam_role.data_engineer_role.arn,
          aws_iam_role.data_analyst_role.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "lambda:*",
          "codecommit:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "data_engineer_profile" {
  name = "mediflow-data-engineer-profile"
  role = aws_iam_role.data_engineer_role.name
}

resource "aws_iam_instance_profile" "data_analyst_profile" {
  name = "mediflow-data-analyst-profile"
  role = aws_iam_role.data_analyst_role.name
}

# ==============================================================================
# S3 Buckets for Healthcare Data
# ==============================================================================

# VULNERABILITY: Raw patient data bucket without encryption
resource "aws_s3_bucket" "patient_raw_data" {
  bucket = "mediflow-patient-raw-data-prod"

  tags = {
    Name        = "patient-raw-data"
    Environment = "production"
    DataClass   = "PHI"
    Compliance  = "HIPAA"
  }
}

# VULNERABILITY: No versioning for audit trail
resource "aws_s3_bucket_versioning" "patient_raw_versioning" {
  bucket = aws_s3_bucket.patient_raw_data.id

  versioning_configuration {
    status = "Disabled"
  }
}

# VULNERABILITY: No encryption at rest
# (S3 now enables default encryption, but explicitly showing it's not KMS)

# Processed patient data bucket
resource "aws_s3_bucket" "patient_processed_data" {
  bucket = "mediflow-patient-processed-data-prod"

  tags = {
    Name        = "patient-processed-data"
    Environment = "production"
    DataClass   = "PHI-Processed"
  }
}

# Analytics exports bucket - VULNERABILITY: Used for data exfiltration
resource "aws_s3_bucket" "analytics_exports" {
  bucket = "mediflow-analytics-exports-prod"

  tags = {
    Name        = "analytics-exports"
    Environment = "production"
    DataClass   = "Analytics"
  }
}

# VULNERABILITY: Analytics bucket has loose access policy
resource "aws_s3_bucket_policy" "analytics_exports_policy" {
  bucket = aws_s3_bucket.analytics_exports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAnalystAccess"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.data_analyst_role.arn,
            aws_iam_role.data_engineer_role.arn
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.analytics_exports.arn}/*"
      }
    ]
  })
}

# ML training data bucket
resource "aws_s3_bucket" "ml_training_data" {
  bucket = "mediflow-ml-training-data-prod"

  tags = {
    Name        = "ml-training-data"
    Environment = "production"
    DataClass   = "De-identified"
  }
}

# CodeCommit backup bucket - VULNERABILITY: Contains application code
resource "aws_s3_bucket" "code_backup" {
  bucket = "mediflow-code-backup-prod"

  tags = {
    Name        = "code-backup"
    Environment = "production"
  }
}

# ==============================================================================
# RDS Database for Patient Records
# ==============================================================================

resource "aws_db_subnet_group" "patient_db_subnet" {
  name       = "mediflow-patient-db-subnet"
  subnet_ids = [aws_subnet.data_subnet_1.id, aws_subnet.data_subnet_2.id]

  tags = {
    Name = "mediflow-db-subnet-group"
  }
}

# VULNERABILITY: Database without encryption, weak password, accessible from VPC
resource "aws_db_instance" "patient_records_db" {
  identifier             = "mediflow-patient-records-db"
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.large"
  allocated_storage      = 200
  storage_type           = "gp3"
  db_name                = "patient_records"
  username               = "dbadmin"
  password               = "MediFlow2024!Production" # VULNERABILITY: Weak password
  db_subnet_group_name   = aws_db_subnet_group.patient_db_subnet.name
  vpc_security_group_ids = [aws_security_group.database_sg.id]

  # VULNERABILITY: Encryption disabled
  storage_encrypted = false

  # VULNERABILITY: Multi-AZ disabled
  multi_az = false

  publicly_accessible = false

  # VULNERABILITY: Short backup retention
  backup_retention_period = 3
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"

  # VULNERABILITY: Auto minor version upgrade disabled
  auto_minor_version_upgrade = false

  # VULNERABILITY: Deletion protection disabled
  deletion_protection = false
  skip_final_snapshot = true

  # VULNERABILITY: Performance Insights disabled (no query monitoring)
  enabled_cloudwatch_logs_exports = []

  tags = {
    Name        = "patient-records-database"
    Environment = "production"
    DataClass   = "PHI-Structured"
  }
}

# ==============================================================================
# Redshift Data Warehouse
# ==============================================================================

resource "aws_redshift_subnet_group" "analytics_subnet_group" {
  name       = "mediflow-analytics-subnet-group"
  subnet_ids = [aws_subnet.data_subnet_1.id, aws_subnet.data_subnet_2.id]

  tags = {
    Name = "mediflow-analytics-subnet-group"
  }
}

# VULNERABILITY: Redshift without encryption
resource "aws_redshift_cluster" "analytics_warehouse" {
  cluster_identifier  = "mediflow-analytics-warehouse"
  database_name       = "analytics"
  master_username     = "analytics_admin"
  master_password     = "AnalyticsAdmin2024!" # VULNERABILITY: Weak password
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  cluster_subnet_group_name = aws_redshift_subnet_group.analytics_subnet_group.name
  vpc_security_group_ids    = [aws_security_group.database_sg.id]

  # VULNERABILITY: No encryption
  encrypted = false

  # VULNERABILITY: Publicly accessible set to false but in future could be changed
  publicly_accessible = false

  # VULNERABILITY: No enhanced VPC routing (data goes through internet)
  enhanced_vpc_routing = false

  # VULNERABILITY: Automated snapshots with short retention
  automated_snapshot_retention_period = 1

  skip_final_snapshot = true

  tags = {
    Name        = "analytics-warehouse"
    Environment = "production"
    DataClass   = "PHI-Analytics"
  }
}

# ==============================================================================
# Lambda Functions for ETL Processing
# ==============================================================================

# Patient data ingestion Lambda
resource "aws_lambda_function" "patient_data_ingestion" {
  filename         = "lambda_placeholder.zip"
  function_name    = "mediflow-patient-data-ingestion"
  role             = aws_iam_role.etl_lambda_role.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("lambda_placeholder.zip")
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 1024

  # VULNERABILITY: Database credentials in environment variables
  environment {
    variables = {
      DB_HOST           = aws_db_instance.patient_records_db.endpoint
      DB_NAME           = "patient_records"
      DB_USER           = "dbadmin"
      DB_PASSWORD       = "MediFlow2024!Production"
      RAW_DATA_BUCKET   = aws_s3_bucket.patient_raw_data.id
      PROCESSED_BUCKET  = aws_s3_bucket.patient_processed_data.id
      REDSHIFT_HOST     = aws_redshift_cluster.analytics_warehouse.endpoint
      REDSHIFT_USER     = "analytics_admin"
      REDSHIFT_PASSWORD = "AnalyticsAdmin2024!"
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.processing_subnet_1.id]
    security_group_ids = [aws_security_group.processing_sg.id]
  }

  tags = {
    Name        = "patient-data-ingestion"
    Environment = "production"
  }
}

# Data transformation Lambda
resource "aws_lambda_function" "data_transformation" {
  filename         = "lambda_placeholder.zip"
  function_name    = "mediflow-data-transformation"
  role             = aws_iam_role.etl_lambda_role.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("lambda_placeholder.zip")
  runtime          = "python3.11"
  timeout          = 600
  memory_size      = 2048

  # VULNERABILITY: Contains API keys and credentials
  environment {
    variables = {
      PROCESSED_BUCKET = aws_s3_bucket.patient_processed_data.id
      ML_BUCKET        = aws_s3_bucket.ml_training_data.id
      EXTERNAL_API_KEY = "sk-external-api-key-abc123xyz"
      ANALYTICS_BUCKET = aws_s3_bucket.analytics_exports.id
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.processing_subnet_1.id]
    security_group_ids = [aws_security_group.processing_sg.id]
  }

  tags = {
    Name        = "data-transformation"
    Environment = "production"
  }
}

# ==============================================================================
# EC2 Instances for Data Analysis
# ==============================================================================

# Data Engineer Workstation
resource "aws_instance" "data_engineer_workstation" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.xlarge"
  subnet_id              = aws_subnet.ingestion_subnet_1.id
  vpc_security_group_ids = [aws_security_group.analyst_workstation_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.data_engineer_profile.name

  # VULNERABILITY: IMDSv1 enabled
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # VULNERABILITY: Should be "required"
    http_put_response_hop_limit = 1
  }

  # VULNERABILITY: Unencrypted root volume
  root_block_device {
    volume_size           = 100
    volume_type           = "gp3"
    encrypted             = false
    delete_on_termination = true
  }

  # VULNERABILITY: User data with credentials
  user_data = <<-EOF
              #!/bin/bash
              echo "DB_HOST=${aws_db_instance.patient_records_db.endpoint}" >> /etc/environment
              echo "DB_PASSWORD=MediFlow2024!Production" >> /etc/environment
              echo "REDSHIFT_HOST=${aws_redshift_cluster.analytics_warehouse.endpoint}" >> /etc/environment
              echo "REDSHIFT_PASSWORD=AnalyticsAdmin2024!" >> /etc/environment
              echo "AWS_DEFAULT_REGION=us-east-1" >> /etc/environment
              EOF

  tags = {
    Name        = "data-engineer-workstation"
    Environment = "production"
    Owner       = "data-engineering-team"
  }
}

# Data Analyst Workstation
resource "aws_instance" "data_analyst_workstation" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.ingestion_subnet_1.id
  vpc_security_group_ids = [aws_security_group.analyst_workstation_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.data_analyst_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 50
    encrypted   = false
  }

  tags = {
    Name        = "data-analyst-workstation"
    Environment = "production"
    Owner       = "analytics-team"
  }
}

# ==============================================================================
# Secrets Manager (partial implementation)
# ==============================================================================

# VULNERABILITY: Some secrets in Secrets Manager, but most are hardcoded elsewhere
resource "aws_secretsmanager_secret" "external_api_credentials" {
  name        = "mediflow/external-api-credentials"
  description = "External API credentials for third-party integrations"

  tags = {
    Application = "mediflow"
  }
}

resource "aws_secretsmanager_secret_version" "external_api_version" {
  secret_id = aws_secretsmanager_secret.external_api_credentials.id
  secret_string = jsonencode({
    api_key    = "sk-external-api-key-abc123xyz"
    api_secret = "secret-external-api-xyz789abc"
  })
}

# ==============================================================================
# CloudWatch Logs (minimal configuration)
# ==============================================================================

# VULNERABILITY: Short log retention
resource "aws_cloudwatch_log_group" "etl_logs" {
  name              = "/aws/lambda/mediflow-etl"
  retention_in_days = 3 # VULNERABILITY: Too short for HIPAA compliance

  tags = {
    Application = "mediflow"
  }
}

# VULNERABILITY: No VPC Flow Logs enabled

# ==============================================================================
# SNS Topics for Alerts
# ==============================================================================

resource "aws_sns_topic" "data_processing_alerts" {
  name = "mediflow-data-processing-alerts"

  tags = {
    Application = "mediflow"
  }
}

# VULNERABILITY: SNS topic not encrypted

# ==============================================================================
# CodeCommit Repository
# ==============================================================================

resource "aws_codecommit_repository" "etl_pipeline_code" {
  repository_name = "mediflow-etl-pipeline"
  description     = "ETL pipeline code for healthcare data processing"

  tags = {
    Application = "mediflow"
  }
}

# ==============================================================================
# Step Functions State Machine
# ==============================================================================

resource "aws_iam_role" "step_functions_role" {
  name = "mediflow-step-functions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY: Step Functions can invoke any Lambda
resource "aws_iam_role_policy" "step_functions_policy" {
  name = "step-functions-lambda-invoke"
  role = aws_iam_role.step_functions_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==============================================================================
# Outputs
# ==============================================================================

output "patient_records_db_endpoint" {
  description = "RDS patient records database endpoint"
  value       = aws_db_instance.patient_records_db.endpoint
  sensitive   = true
}

output "analytics_warehouse_endpoint" {
  description = "Redshift analytics warehouse endpoint"
  value       = aws_redshift_cluster.analytics_warehouse.endpoint
  sensitive   = true
}

output "patient_raw_data_bucket" {
  description = "S3 bucket for raw patient data"
  value       = aws_s3_bucket.patient_raw_data.id
}

output "data_engineer_workstation_ip" {
  description = "Public IP of data engineer workstation"
  value       = aws_instance.data_engineer_workstation.public_ip
}

output "data_analyst_workstation_ip" {
  description = "Public IP of data analyst workstation"
  value       = aws_instance.data_analyst_workstation.public_ip
}
