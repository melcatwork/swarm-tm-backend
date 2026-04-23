# Sample Infrastructure Files for Threat Modeling

This directory contains sample Infrastructure as Code (IaC) files designed for testing the Swarm TM threat modeling system.

## Overview

The sample infrastructure describes a **Managed File Transfer Platform** on AWS - a realistic cloud architecture with intentional security weaknesses for comprehensive threat modeling practice.

## System Architecture

### Business Flow

1. **External Partners** upload files via SFTP (AWS Transfer Family)
2. **Files land** in an S3 bucket (`file-transfer-incoming`)
3. **Lambda function** is triggered to:
   - Validate files
   - Store metadata in DynamoDB
   - Copy clean files to processed bucket
   - Send SNS notifications
4. **Internal users** access a web portal (ECS Fargate) to:
   - View transfer history
   - Manage partners
   - Query file metadata
5. **Web portal** is fronted by:
   - Application Load Balancer (ALB)
   - CloudFront CDN
   - PostgreSQL database (RDS)

### Network Architecture

```
                    Internet
                       |
        +--------------+---------------+
        |                              |
   CloudFront                     Partner SFTP
        |                         (203.0.113.0/24)
        |                              |
      ALB (Public)              Transfer Family
        |                         VPC Endpoint
        |                              |
   ECS Fargate                         |
   (Private Subnet)                    |
        |                              |
        +-------> S3 Incoming <--------+
        |              |
        |              +----> Lambda (Private Subnet)
        |                          |
        +----------+               |
                   |               |
              RDS PostgreSQL   DynamoDB
              (Private)        (Managed)
                   |               |
                   +----> S3 Processed
```

### AWS Resources

- **VPC**: 10.0.0.0/16 with public and private subnets across 2 AZs
- **AWS Transfer Family**: SFTP server with VPC endpoint
- **S3 Buckets**:
  - `file-transfer-incoming`: Versioning enabled, triggers Lambda
  - `file-transfer-processed`: Final destination for validated files
- **Lambda**: Python 3.11 function for file processing in VPC
- **DynamoDB**: Metadata storage with encryption and PITR
- **ECS Fargate**: 2 tasks running web portal on port 8080
- **ALB**: Internet-facing load balancer with HTTPS
- **CloudFront**: CDN distribution in front of ALB
- **RDS PostgreSQL**: Multi-AZ database (15.4, db.t3.micro)
- **SNS**: Notification topic for file processing events
- **IAM Roles**: Lambda execution, ECS task, Transfer user roles

## Files in This Directory

### 1. `file-transfer-system.tf`

**Terraform configuration** (HCL syntax) describing the entire platform.

**Usage:**
```bash
# Initialize Terraform
terraform init

# Validate syntax
terraform validate

# Plan deployment (dry-run)
terraform plan

# Apply (creates resources - COSTS MONEY!)
terraform apply

# Destroy all resources
terraform destroy
```

**Variables:**
- `vpc_cidr`: VPC CIDR block (default: `10.0.0.0/16`)
- `environment`: Environment name (default: `production`)
- `partner_cidr`: Partner network CIDR for SFTP access (default: `203.0.113.0/24`)

### 2. `file-transfer-system.yaml`

**AWS CloudFormation template** (YAML syntax) - same architecture as Terraform.

**Usage:**
```bash
# Validate syntax
aws cloudformation validate-template --template-body file://file-transfer-system.yaml

# Create stack (COSTS MONEY!)
aws cloudformation create-stack \
  --stack-name file-transfer-system \
  --template-body file://file-transfer-system.yaml \
  --parameters \
    ParameterKey=VpcCidr,ParameterValue=10.0.0.0/16 \
    ParameterKey=Environment,ParameterValue=production \
    ParameterKey=PartnerCidr,ParameterValue=203.0.113.0/24 \
  --capabilities CAPABILITY_NAMED_IAM

# Check stack status
aws cloudformation describe-stacks --stack-name file-transfer-system

# Delete stack
aws cloudformation delete-stack --stack-name file-transfer-system
```

**Parameters:**
- `VpcCidr`: VPC CIDR block (default: `10.0.0.0/16`)
- `Environment`: Environment name (default: `production`)
- `PartnerCidr`: Partner network CIDR for SFTP access (default: `203.0.113.0/24`)

## Intentional Security Weaknesses

These files contain **realistic security issues** for threat modeling practice:

### 🔴 High Severity

1. **Hardcoded Database Password**
   - Location: RDS instance and ECS task definition
   - Issue: Password `ChangeMe123!` is hardcoded in plain text
   - Impact: Database compromise if IaC is exposed
   - Recommendation: Use AWS Secrets Manager

2. **Overly Permissive IAM Policies**
   - Location: Lambda execution role, ECS task role
   - Issue: Broad S3 permissions including `DeleteObject`
   - Impact: Accidental or malicious data deletion
   - Recommendation: Apply least privilege principle

3. **ALB Open to Internet**
   - Location: ALB security group
   - Issue: Port 443/80 open to `0.0.0.0/0`
   - Impact: Public exposure without WAF
   - Recommendation: Add WAF, CloudFlare, or IP allowlists

### 🟡 Medium Severity

4. **Database Credentials in Environment Variables**
   - Location: ECS task definition
   - Issue: DB password passed as plain text env var
   - Impact: Visible in ECS console and logs
   - Recommendation: Use Secrets Manager integration

5. **Direct S3 Access from ECS Tasks**
   - Location: ECS task role policy
   - Issue: Tasks can directly read/write S3
   - Impact: Bypass Lambda processing logic
   - Recommendation: Restrict to read-only or remove

6. **No VPC Endpoints**
   - Location: VPC configuration
   - Issue: Traffic to S3/DynamoDB goes via NAT Gateway
   - Impact: Data exposure, NAT costs
   - Recommendation: Add VPC endpoints

7. **CloudFront Caching Disabled**
   - Location: CloudFront distribution
   - Issue: TTL set to 0, no caching benefit
   - Impact: High origin load, slow performance
   - Recommendation: Enable caching for static assets

### 🟢 Low Severity

8. **S3 Bucket Names Include Account ID**
   - Location: S3 bucket resources
   - Issue: Predictable naming pattern
   - Impact: Information disclosure
   - Recommendation: Use random suffixes

9. **RDS Deletion Protection Disabled**
   - Location: RDS instance
   - Issue: `DeletionProtection: false`
   - Impact: Accidental database deletion
   - Recommendation: Enable in production

10. **Short Log Retention**
    - Location: CloudWatch log group
    - Issue: Only 7 days retention
    - Impact: Limited forensic capability
    - Recommendation: 90+ days or ship to S3

## Using These Files with Swarm TM

### Step 1: Upload File

1. Open Swarm TM frontend: http://localhost:3000
2. Click "Choose File"
3. Select either:
   - `file-transfer-system.tf` (Terraform)
   - `file-transfer-system.yaml` (CloudFormation)
4. Click "Start Threat Modeling"

### Step 2: Review Results

The swarm will generate:

**Attack Paths** - Example:
```
Path 1: External Attacker → Hardcoded Credentials
├─ Attacker obtains IaC files from public repository
├─ Extracts hardcoded password "ChangeMe123!"
├─ Uses password to access RDS from compromised ECS task
└─ Exfiltrates sensitive file metadata

Path 2: Malicious Insider → S3 Data Deletion
├─ Insider has access to ECS task
├─ Uses overly permissive S3 permissions
├─ Deletes files from incoming bucket
└─ Disrupts file transfer operations
```

**Threat Model** - Example threats:
- Credential theft via hardcoded passwords
- Data loss via overly permissive IAM
- DDoS via open ALB without WAF
- MITM via lack of VPC endpoints
- Data exfiltration via ECS direct S3 access

**Recommendations** - Example:
- Rotate RDS credentials and move to Secrets Manager
- Implement least privilege IAM policies
- Add AWS WAF rules to ALB
- Deploy VPC endpoints for S3/DynamoDB
- Enable CloudTrail and GuardDuty

### Step 3: Compare Results

Try uploading both `.tf` and `.yaml` files to see if the LLM:
- Identifies the same issues in both formats
- Understands Terraform vs CloudFormation syntax
- Generates consistent threat models
- Prioritizes risks correctly

## Expected Threat Modeling Outputs

### Layers of Analysis

The 3-layer swarm should produce:

**Layer 1: Attack Surface Analysis**
- Internet-facing: ALB (0.0.0.0/0), CloudFront, Transfer Family endpoint
- Partner-facing: SFTP (203.0.113.0/24)
- Internal: Lambda, ECS, RDS, DynamoDB
- Data flows: Partner → S3 → Lambda → DynamoDB → ECS → User

**Layer 2: Attack Path Generation**
- External attacker scenarios
- Compromised partner scenarios
- Malicious insider scenarios
- Supply chain attack scenarios
- Multi-step attack chains

**Layer 3: Comprehensive Threat Model**
- Asset inventory and classification
- STRIDE analysis per component
- Risk scoring (High/Medium/Low)
- Compensating controls analysis
- Compliance mapping (PCI-DSS, SOC 2)

### Key Questions the Swarm Should Answer

1. What are the most critical attack paths?
2. Which components have the weakest security posture?
3. What is the blast radius of each vulnerability?
4. What security controls are missing?
5. How should risks be prioritized for remediation?

## Modifying the Samples

Feel free to customize these files to test different scenarios:

### Add More Weaknesses
```hcl
# Example: Remove S3 encryption
resource "aws_s3_bucket" "incoming" {
  # Comment out encryption
  # server_side_encryption_configuration { ... }
}
```

### Add Security Controls
```hcl
# Example: Add AWS WAF
resource "aws_wafv2_web_acl" "main" {
  name  = "file-transfer-waf"
  scope = "REGIONAL"
  # ... WAF rules
}
```

### Change Architecture
```hcl
# Example: Add API Gateway
resource "aws_api_gateway_rest_api" "main" {
  name = "file-transfer-api"
  # ... API Gateway config
}
```

## Architecture Patterns Demonstrated

These samples showcase common patterns for threat modeling:

✅ **Multi-tier web application** (CloudFront → ALB → ECS → RDS)
✅ **Event-driven processing** (S3 → Lambda → DynamoDB → SNS)
✅ **External partner integration** (AWS Transfer Family SFTP)
✅ **VPC networking** (Public/private subnets, NAT, security groups)
✅ **Managed services** (S3, Lambda, DynamoDB, ECS Fargate, RDS)
✅ **IAM roles and policies** (Lambda execution, ECS task, Transfer user)
✅ **Encryption at rest** (S3, DynamoDB, RDS)
✅ **High availability** (Multi-AZ RDS, ALB across AZs)

## Cost Estimate

**WARNING:** Deploying these resources will incur AWS costs!

Estimated monthly cost (us-east-1, minimal usage):
- **NAT Gateway**: $32/month (~$1/day)
- **ALB**: $16/month
- **RDS db.t3.micro Multi-AZ**: $30/month
- **ECS Fargate (2 tasks)**: $30/month
- **Transfer Family**: $216/month (server fee)
- **S3, Lambda, DynamoDB**: $5-10/month (usage-based)
- **CloudFront**: $1-5/month (usage-based)

**Total**: ~$330-340/month

**Recommendation**: **DO NOT deploy to AWS** - use for threat modeling practice only!

## Troubleshooting

### Terraform Validation Fails
```bash
# Common issues:
# 1. Missing AWS credentials
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="us-east-1"

# 2. Invalid certificate ARN
# Edit file and update:
certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/placeholder"

# 3. Account ID conflicts in bucket names
# Terraform will auto-populate ${data.aws_caller_identity.current.account_id}
```

### CloudFormation Validation Fails
```bash
# Common issues:
# 1. Missing capabilities flag
aws cloudformation create-stack \
  --capabilities CAPABILITY_NAMED_IAM  # Required for IAM roles

# 2. Invalid certificate ARN
# Edit YAML and update CertificateArn

# 3. Stack already exists
aws cloudformation delete-stack --stack-name file-transfer-system
# Wait for deletion, then retry
```

### Swarm TM Upload Fails
```bash
# File too large (> 1MB)
ls -lh file-transfer-system.tf  # Should be < 1MB

# Unsupported extension
# Must be .tf, .yaml, .yml, or .json

# Backend unreachable
curl http://localhost:8000/api/health
```

## Additional Resources

### AWS Documentation
- [AWS Transfer Family](https://docs.aws.amazon.com/transfer/)
- [Amazon S3 Security](https://docs.aws.amazon.com/s3/security/)
- [AWS Lambda in VPC](https://docs.aws.amazon.com/lambda/latest/dg/vpc.html)
- [ECS Fargate Security](https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security.html)

### Threat Modeling Resources
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [STRIDE Methodology](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

### IaC Security Tools
- [tfsec](https://github.com/aquasecurity/tfsec) - Terraform static analysis
- [Checkov](https://www.checkov.io/) - IaC security scanning
- [cfn-nag](https://github.com/stelligent/cfn_nag) - CloudFormation linting
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment

---

**Happy Threat Modeling! 🔒🔍**

For questions or issues with Swarm TM, see the main [README.md](../README.md).
