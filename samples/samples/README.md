# E-Commerce Platform Test Sample

## Overview

This Terraform file (`ecommerce-platform.tf`) represents a realistic e-commerce platform infrastructure based on open-source applications like Magento, OpenCart, or Spree Commerce. It includes **intentional security vulnerabilities** designed to test the Swarm TM threat modeling tool, particularly the **Insider Threat** agent.

## Application: CloudMarket

**CloudMarket** is a fictional open-source e-commerce platform with the following architecture:

### Components
- **Web/Application Tier**: EC2 instances running the application
- **Database Tier**: PostgreSQL RDS instance storing customer, order, and product data
- **Storage Tier**: S3 buckets for customer data, product images, and order exports
- **Compute Tier**: Lambda functions for background processing
- **Developer Infrastructure**: EC2 workstations for engineering team

### Data Classification
- **PII (Personally Identifiable Information)**: Customer names, addresses, emails
- **Financial Data**: Payment information, order history
- **Business Critical**: Product catalog, inventory data

## Intentional Vulnerabilities & Expected Attack Paths

### 1. Insider Threat: Credential Harvesting & Data Exfiltration

**Attack Path**: Developer → S3 Customer Data Exfiltration
- **Entry Point**: Developer workstation (EC2 with developer IAM role)
- **Technique**: T1078 (Valid Accounts), T1530 (Data from Cloud Storage)
- **Steps**:
  1. Developer has legitimate IAM role with S3 access
  2. IAM policy grants read/write access to `customer_data` S3 bucket
  3. Developer can list and download all customer PII
  4. Data includes unencrypted customer information
  5. No versioning means deleted evidence is unrecoverable
- **Impact**: Confidentiality breach, GDPR/PCI-DSS violation
- **Mitigations**:
  - M1018: User Account Management (least privilege)
  - M1032: Multi-factor Authentication
  - M1057: Data Loss Prevention

### 2. Insider Threat: Secrets Access & Privilege Escalation

**Attack Path**: Developer → Secrets Manager → Database Access
- **Entry Point**: Developer workstation
- **Technique**: T1552.005 (Cloud Instance Metadata), T1078.004 (Cloud Accounts)
- **Steps**:
  1. Developer IAM role has `secretsmanager:GetSecretValue` on all secrets
  2. Can retrieve payment gateway credentials
  3. Can access database password from Secrets Manager
  4. Direct database access via VPC connectivity
- **Impact**: Full system compromise, financial fraud
- **Mitigations**:
  - M1026: Privileged Account Management
  - M1027: Password Policies
  - M1041: Encrypt Sensitive Information

### 3. Insider Threat: Database Snapshot Exfiltration

**Attack Path**: App Server Role → RDS Snapshot → Cross-Account Transfer
- **Entry Point**: Application server EC2 instance
- **Technique**: T1537 (Transfer Data to Cloud Account), T1098 (Account Manipulation)
- **Steps**:
  1. App server IAM role has `rds:CreateDBSnapshot` permission
  2. Create database snapshot containing all customer/order data
  3. Snapshot can be shared with external AWS account
  4. Database not encrypted at rest
  5. Full data exfiltration without detection
- **Impact**: Complete database compromise
- **Mitigations**:
  - M1022: Restrict File and Directory Permissions
  - M1041: Encrypt Sensitive Information (enable RDS encryption)
  - M1047: Audit (CloudTrail logging)

### 4. Insider Threat: Lambda Function Abuse

**Attack Path**: Lambda Environment Variables → Lateral Movement
- **Entry Point**: Lambda function execution environment
- **Technique**: T1552.005 (Unsecured Credentials), T1078.004 (Cloud Accounts)
- **Steps**:
  1. Lambda function has excessive IAM permissions (`s3:*`, `rds:*`, `lambda:*`)
  2. Environment variables contain plaintext credentials
  3. Can invoke other Lambda functions
  4. Can access all S3 buckets
  5. Can create new RDS snapshots
- **Impact**: Privilege escalation, lateral movement
- **Mitigations**:
  - M1026: Privileged Account Management
  - M1041: Encrypt Sensitive Information
  - M1018: User Account Management

### 5. Insider Threat: EC2 Metadata Service Exploitation

**Attack Path**: Web Server → IMDSv1 → IAM Credentials Theft
- **Entry Point**: Web server EC2 instance
- **Technique**: T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts)
- **Steps**:
  1. EC2 instances use IMDSv1 (not IMDSv2)
  2. SSRF vulnerability in web app could access metadata
  3. Retrieve IAM role credentials from metadata service
  4. Use stolen credentials to access AWS resources
  5. Escalate to S3 buckets and RDS snapshots
- **Impact**: Credential theft, privilege escalation
- **Mitigations**:
  - M1035: Limit Access to Resource Over Network
  - M1042: Disable or Remove Feature or Program (enforce IMDSv2)

### 6. Insider Threat: Order Export Data Theft

**Attack Path**: Developer → Order Exports S3 → Financial Data Exfiltration
- **Entry Point**: Developer workstation
- **Technique**: T1530 (Data from Cloud Storage), T1048 (Exfiltration Over Alternative Protocol)
- **Steps**:
  1. Developer role has access to `order_exports` S3 bucket
  2. Bucket contains CSV/JSON files with order history
  3. Files include payment information, customer PII
  4. No encryption at rest
  5. Download via AWS CLI or console
- **Impact**: Financial data breach, PCI-DSS violation
- **Mitigations**:
  - M1022: Restrict File and Directory Permissions
  - M1041: Encrypt Sensitive Information
  - M1057: Data Loss Prevention

### 7. Cross-Service Privilege Escalation

**Attack Path**: Developer → Lambda Update → Elevated Permissions
- **Entry Point**: Developer workstation
- **Technique**: T1525 (Implant Internal Image), T1078.004 (Cloud Accounts)
- **Steps**:
  1. Developer has access to Lambda function configuration
  2. Lambda has excessive IAM permissions
  3. Update Lambda code to create backdoor
  4. Use Lambda's elevated permissions for privilege escalation
  5. Access resources beyond developer's normal scope
- **Impact**: Complete AWS account compromise
- **Mitigations**:
  - M1026: Privileged Account Management
  - M1047: Audit
  - M1018: User Account Management

## Testing Instructions

1. **Upload the file** to the Swarm TM web interface
2. **Select test mode**:
   - **Full Swarm**: All threat actors (comprehensive analysis)
   - **Quick Run**: 2 agents (APT29 + Scattered Spider)
   - **Single Agent**: Select "Insider Threat" from dropdown
3. **Expected Results**:
   - 5-8 attack paths identified
   - Confidence ratings: High/Medium
   - MITRE ATT&CK techniques mapped
   - AWS-specific mitigations suggested

## Key Security Issues

### IAM Misconfigurations
- ✗ Overly permissive developer role
- ✗ Lambda with admin-like permissions
- ✗ Secrets Manager access for all developers
- ✗ RDS snapshot creation by app servers

### Data Protection Gaps
- ✗ No encryption at rest (RDS, S3)
- ✗ Hardcoded credentials in user data
- ✗ Plaintext secrets in Lambda environment
- ✗ No S3 bucket versioning

### Network Security Issues
- ✗ SSH exposed to internet (0.0.0.0/0)
- ✗ Database accessible from entire VPC
- ✗ IMDSv1 enabled (metadata service)

### Monitoring & Compliance
- ✗ Short log retention (7 days)
- ✗ No CloudTrail data events
- ✗ No VPC Flow Logs
- ✗ Deletion protection disabled

## Expected Mitigations

The tool should suggest MITRE ATT&CK mitigations including:
- **M1018**: User Account Management (least privilege)
- **M1022**: Restrict File and Directory Permissions
- **M1026**: Privileged Account Management
- **M1027**: Password Policies
- **M1032**: Multi-factor Authentication
- **M1035**: Limit Access to Resource Over Network
- **M1041**: Encrypt Sensitive Information
- **M1042**: Disable or Remove Feature or Program
- **M1047**: Audit
- **M1057**: Data Loss Prevention

## Architecture Diagram

```
Internet
   |
   v
[Internet Gateway]
   |
   +-- Public Subnet (10.0.1.0/24)
   |     |
   |     +-- Web Server EC2 (IMDSv1, public SSH)
   |     +-- Developer Workstation (excessive IAM)
   |
   +-- Private Subnet (10.0.10.0/24)
         |
         +-- RDS PostgreSQL (unencrypted, weak auth)
         +-- Lambda (excessive perms, plaintext secrets)

[S3 Buckets]
   +-- customer_data (unencrypted, broad access)
   +-- order_exports (financial data, unencrypted)
   +-- product_images (public)

[IAM Roles]
   +-- developer_role (S3 *, Secrets *)
   +-- app_server_role (RDS snapshots)
   +-- lambda_role (S3 *, RDS *, Lambda *)
```

## License

This is a test sample for security demonstration purposes. Not for production use.
