"""
Defense in Depth and Cyber by Design mitigation layers.

This module implements a multi-layered security approach with:
- Preventive controls (stop attacks before they occur)
- Detective controls (identify attacks in progress)
- Corrective controls (respond to and recover from attacks)
- Administrative controls (policies, procedures, training)

Each attack technique has multiple mitigations across different layers,
implementing true defense-in-depth principles.
"""

from typing import Dict, List
from enum import Enum


class DefenseLayer(str, Enum):
    """Defense in depth layers."""
    PREVENTIVE = "preventive"  # Stop attack before it happens
    DETECTIVE = "detective"    # Detect attack in progress
    ADMINISTRATIVE = "administrative"  # Policies, procedures, training
    RESPONSE = "response"      # Respond to active incidents
    RECOVERY = "recovery"      # Recover from successful attacks


class MitigationPriority(str, Enum):
    """Mitigation implementation priority."""
    CRITICAL = "critical"  # Implement immediately
    HIGH = "high"          # Implement within 30 days
    MEDIUM = "medium"      # Implement within 90 days
    LOW = "low"            # Implement as resources allow


# Comprehensive defense-in-depth mitigations for AWS cloud
# Each technique has multiple mitigations across different layers
DEFENSE_IN_DEPTH_MITIGATIONS = {
    "T1078.004": {  # Cloud Accounts
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1078.004-P1",
                "mitigation_name": "Enforce MFA on All Cloud Accounts",
                "description": "Require multi-factor authentication for all IAM users, root account, and federated access. Use hardware MFA tokens for privileged accounts. Implement conditional access policies that enforce MFA based on risk level.",
                "aws_service_action": "Enable MFA on root account and all IAM users via IAM console. Configure AWS SSO with MFA enforcement. Use SCPs to deny API calls without MFA: aws:MultiFactorAuthPresent=false",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Blocks 90%+ of credential-based attacks",
            },
            {
                "mitigation_id": "M1078.004-P2",
                "mitigation_name": "Implement Least Privilege IAM Policies",
                "description": "Grant minimum permissions required for each role. Use permission boundaries to limit maximum permissions. Implement session policies for temporary elevated access. Review and remove unused permissions quarterly.",
                "aws_service_action": "Use IAM Access Analyzer to identify overly permissive policies. Implement permission boundaries. Create fine-grained policies with explicit Allow and Deny statements. Use aws:PrincipalOrgID conditions.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks per application",
                "effectiveness": "High - Reduces blast radius of compromised credentials",
            },
            {
                "mitigation_id": "M1078.004-P3",
                "mitigation_name": "Restrict Access by IP and Context",
                "description": "Use IAM policy conditions to restrict access based on source IP, time of day, and request context. Implement VPN or Private Link for sensitive operations. Deny access from known malicious IP ranges.",
                "aws_service_action": "Add IAM policy conditions: aws:SourceIp, aws:CurrentTime, aws:SecureTransport. Use AWS WAF IP sets for known threats. Implement VPC endpoints for private API access.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "Medium - Reduces attack surface",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1078.004-D1",
                "mitigation_name": "Enable Comprehensive CloudTrail Logging",
                "description": "Log all API calls across all regions. Enable CloudTrail Insights for anomaly detection. Send logs to centralized S3 bucket with encryption and MFA Delete. Forward logs to SIEM for correlation.",
                "aws_service_action": "Enable organization trail with S3 encryption and log validation. Enable CloudTrail Insights. Configure CloudWatch Logs for real-time analysis. Use EventBridge rules for alerting.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Provides visibility into all account activity",
            },
            {
                "mitigation_id": "M1078.004-D2",
                "mitigation_name": "Monitor Authentication Anomalies with GuardDuty",
                "description": "Enable GuardDuty to detect suspicious authentication patterns, compromised credentials, and unusual API calls. Configure findings to trigger automated response workflows. Monitor for impossible travel scenarios.",
                "aws_service_action": "Enable GuardDuty in all accounts and regions. Configure findings severity thresholds. Set up EventBridge rules to trigger Lambda functions for automated response. Export findings to Security Hub.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Detects known attack patterns",
            },
            {
                "mitigation_id": "M1078.004-D3",
                "mitigation_name": "Implement Real-Time IAM Activity Monitoring",
                "description": "Create CloudWatch alarms for critical IAM changes: CreateUser, AttachUserPolicy, CreateAccessKey, AssumeRole from unusual principals. Alert on console sign-ins from new locations.",
                "aws_service_action": "Create CloudWatch metric filters for IAM API calls. Configure SNS topics for critical alerts. Use Lambda for automated response (e.g., suspend user, trigger incident response).",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Rapid detection of account manipulation",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1078.004-R1",
                "mitigation_name": "Automated Credential Rotation and Revocation",
                "description": "Automatically rotate compromised credentials. Revoke suspicious sessions immediately. Use AWS Systems Manager Parameter Store or Secrets Manager for automated rotation. Implement break-glass procedures for emergency access.",
                "aws_service_action": "Use Secrets Manager with automatic rotation. Create Lambda functions to revoke access keys on GuardDuty findings. Implement Systems Manager Session Manager for break-glass access.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Limits exposure time of compromised credentials",
            },
            {
                "mitigation_id": "M1078.004-R2",
                "mitigation_name": "Incident Response Playbooks",
                "description": "Develop and test incident response procedures for compromised credentials. Include isolation steps, forensic data collection, and communication plans. Conduct regular tabletop exercises.",
                "aws_service_action": "Create AWS Systems Manager Automation runbooks for common incidents. Use AWS Step Functions for orchestration. Store playbooks in Wiki or Confluence.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "High - 2-4 weeks",
                "effectiveness": "Medium - Reduces mean time to respond (MTTR)",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1078.004-RV1",
                "mitigation_name": "Account Recovery Procedures",
                "description": "Establish procedures for recovering compromised accounts. Document steps for restoring access, rotating all credentials, and validating system integrity after credential compromise.",
                "aws_service_action": "Create AWS Systems Manager Automation documents for account recovery. Use AWS Backup to restore compromised resources. Document recovery time objectives (RTO).",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Enables rapid recovery from compromise",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1078.004-A1",
                "mitigation_name": "Security Awareness Training",
                "description": "Conduct quarterly phishing simulations and security training. Train developers on secure credential handling. Require security training for cloud console access.",
                "aws_service_action": "Use AWS Training and Certification resources. Implement phishing simulation tools. Track completion in LMS. Make training prerequisite for IAM user creation.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Low - Ongoing",
                "effectiveness": "Medium - Reduces human error",
            },
            {
                "mitigation_id": "M1078.004-A2",
                "mitigation_name": "Regular Access Reviews and Audits",
                "description": "Conduct quarterly access reviews to remove unused accounts and permissions. Implement automated reports for access certification. Document all privileged access approvals.",
                "aws_service_action": "Use IAM Access Analyzer and AWS Config for compliance reports. Create Lambda functions for automated access reviews. Use AWS Audit Manager for continuous auditing.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week setup, ongoing reviews",
                "effectiveness": "Medium - Reduces attack surface over time",
            },
        ],
    },

    "T1190": {  # Exploit Public-Facing Application
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1190-P1",
                "mitigation_name": "Deploy AWS WAF with Managed Rule Groups",
                "description": "Place all public-facing applications behind AWS WAF. Enable managed rule groups for OWASP Top 10, known bad inputs, and IP reputation. Configure rate limiting to prevent brute force attacks.",
                "aws_service_action": "Create WAF WebACL with AWS Managed Rules (Core, OWASP, IP Reputation). Associate with CloudFront, ALB, or API Gateway. Enable request/response logging to S3 or CloudWatch.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Blocks known exploits and attack patterns",
            },
            {
                "mitigation_id": "M1190-P2",
                "mitigation_name": "Implement Application Security Best Practices",
                "description": "Use parameterized queries to prevent SQL injection. Validate and sanitize all user inputs. Implement proper authentication and session management. Keep all frameworks and dependencies up to date.",
                "aws_service_action": "Use AWS CodeGuru for code review. Implement AWS Secrets Manager for credentials. Use RDS with IAM authentication. Regular patching with Systems Manager Patch Manager.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "High - Varies by application",
                "effectiveness": "High - Reduces exploitable vulnerabilities",
            },
            {
                "mitigation_id": "M1190-P3",
                "mitigation_name": "Network Segmentation and Access Controls",
                "description": "Place web tier in public subnet, application tier in private subnet, and data tier in isolated subnet. Use security groups as stateful firewalls. Implement network ACLs for subnet-level protection.",
                "aws_service_action": "Design VPC with public/private/data subnets. Configure security groups with least-privilege rules. Use AWS Network Firewall for deep packet inspection. Enable VPC Flow Logs.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week for new apps",
                "effectiveness": "High - Limits blast radius",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1190-D1",
                "mitigation_name": "Web Application Monitoring and Logging",
                "description": "Enable detailed application logging. Send logs to centralized SIEM. Monitor for suspicious patterns: SQL injection attempts, XSS, authentication failures. Alert on unusual traffic patterns.",
                "aws_service_action": "Enable ALB access logs to S3. Use CloudWatch Logs for application logs. Create CloudWatch alarms for HTTP 4xx/5xx errors. Use AWS WAF logging for attack analysis.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Early warning of attacks",
            },
            {
                "mitigation_id": "M1190-D2",
                "mitigation_name": "Continuous Vulnerability Scanning",
                "description": "Scan applications for vulnerabilities weekly. Use AWS Inspector for EC2 instances and container images. Integrate SAST/DAST tools in CI/CD pipeline. Track and remediate findings.",
                "aws_service_action": "Enable Amazon Inspector automatic scanning. Integrate security scanning in CodePipeline. Use AWS Security Hub for centralized findings. Set up automated ticketing for high-severity issues.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Identifies vulnerabilities before exploitation",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1190-R1",
                "mitigation_name": "Automated Patching and Remediation",
                "description": "Implement automated patching for OS and application dependencies. Use AWS Systems Manager for patch compliance. Deploy security updates within 24 hours of release for critical vulnerabilities.",
                "aws_service_action": "Configure Systems Manager Patch Manager with maintenance windows. Use AWS CloudFormation for immutable infrastructure. Implement blue-green deployments for rapid rollback.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Reduces window of exposure",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1190-RV1",
                "mitigation_name": "Incident Recovery and Business Continuity",
                "description": "Maintain disaster recovery plans for exploited applications. Use AWS Backup and cross-region replication for critical data. Test recovery procedures quarterly.",
                "aws_service_action": "Implement AWS Backup with automated snapshots. Use RDS automated backups with point-in-time recovery. Test failover procedures regularly.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "High - Enables rapid recovery from exploitation",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1190-A1",
                "mitigation_name": "Secure Development Lifecycle (SDL)",
                "description": "Implement security requirements in design phase. Conduct threat modeling for new features. Perform security code reviews. Run penetration tests before production deployment.",
                "aws_service_action": "Use AWS Well-Architected Framework security pillar. Implement CodeGuru Security for automated code review. Conduct quarterly penetration tests. Document security requirements in tickets.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - Cultural change, 3-6 months",
                "effectiveness": "High - Prevents vulnerabilities from reaching production",
            },
        ],
    },

    "T1530": {  # Data from Cloud Storage Object
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1530-P1",
                "mitigation_name": "Enable S3 Block Public Access",
                "description": "Enable S3 Block Public Access at account and bucket level to prevent accidental public exposure. Review existing public buckets and restrict access. Use S3 Access Analyzer to identify unintended access.",
                "aws_service_action": "Enable S3 Block Public Access at account level. Use S3 Access Analyzer. Implement bucket policies with aws:PrincipalOrgID conditions. Use VPC endpoints for private S3 access.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Prevents most data exfiltration scenarios",
            },
            {
                "mitigation_id": "M1530-P2",
                "mitigation_name": "Implement Least Privilege S3 Access",
                "description": "Grant minimum required permissions for S3 bucket access. Use IAM policies, bucket policies, and ACLs together. Implement conditions for source VPC, IP, or MFA. Review permissions quarterly.",
                "aws_service_action": "Use IAM Access Analyzer for S3. Implement S3 bucket policies with conditions. Use SCPs to enforce encryption in transit. Regular access reviews with AWS Config rules.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Reduces unauthorized access",
            },
            {
                "mitigation_id": "M1530-P3",
                "mitigation_name": "Enable S3 Encryption at Rest",
                "description": "Encrypt all S3 objects with SSE-S3, SSE-KMS, or SSE-C. Use KMS for sensitive data with key rotation. Implement bucket policies to deny unencrypted uploads. Use AWS Macie for data classification.",
                "aws_service_action": "Enable default encryption on all buckets with aws:kms. Use bucket policies to deny PutObject without encryption. Enable S3 Object Lock for immutability. Use Macie for sensitive data discovery.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Protects data at rest",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1530-D1",
                "mitigation_name": "Enable S3 Access Logging and Monitoring",
                "description": "Enable S3 server access logging for all buckets. Forward logs to centralized bucket. Create CloudWatch alarms for suspicious patterns: bulk downloads, unusual access times, access from new IPs.",
                "aws_service_action": "Enable S3 server access logging. Use CloudTrail S3 data events. Create CloudWatch metric filters for GetObject requests. Set up GuardDuty S3 protection. Use EventBridge for real-time alerting.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Detects data access anomalies",
            },
            {
                "mitigation_id": "M1530-D2",
                "mitigation_name": "Monitor with AWS Macie",
                "description": "Use AWS Macie to discover and classify sensitive data in S3. Monitor for unusual data access patterns. Alert on discovery of PII, credentials, or financial data in unexpected locations.",
                "aws_service_action": "Enable Macie with automated discovery jobs. Configure custom data identifiers for organization-specific sensitive data. Set up Macie findings to Security Hub. Create automated remediation for sensitive data exposure.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Identifies sensitive data exposure",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1530-R1",
                "mitigation_name": "Automated S3 Access Revocation",
                "description": "Automatically revoke suspicious S3 access when anomalies detected. Quarantine affected buckets. Trigger incident response workflows immediately.",
                "aws_service_action": "Create Lambda functions triggered by GuardDuty S3 findings to revoke IAM permissions. Use EventBridge for automated response. Implement bucket policy updates to block access.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Stops active data exfiltration",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1530-RV1",
                "mitigation_name": "Implement S3 Versioning and Object Lock",
                "description": "Enable S3 versioning to prevent data deletion. Use S3 Object Lock for compliance and ransomware protection. Implement MFA Delete for additional protection. Regular backup to separate account.",
                "aws_service_action": "Enable versioning on all buckets. Configure Object Lock with retention policies. Enable MFA Delete on critical buckets. Use S3 Replication to backup account. Implement lifecycle policies.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Enables recovery from incidents",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1530-A1",
                "mitigation_name": "Data Classification and Handling Policy",
                "description": "Implement data classification scheme (public, internal, confidential, restricted). Define handling requirements for each class. Train employees on proper S3 usage. Regular compliance audits.",
                "aws_service_action": "Use resource tags for data classification. Implement tag-based access control. Use AWS Organizations tag policies. Document policies in Wiki. Automate compliance checks with AWS Config.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "High - 2-3 months",
                "effectiveness": "Medium - Long-term risk reduction",
            },
        ],
    },

    "T1098": {  # Account Manipulation
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1098-P1",
                "mitigation_name": "Implement SCPs to Restrict IAM Changes",
                "description": "Use AWS Organizations Service Control Policies to prevent unauthorized IAM modifications. Restrict CreateUser, AttachUserPolicy, and PutUserPolicy actions to specific roles. Implement break-glass procedures.",
                "aws_service_action": "Create SCPs that deny IAM write actions except for specific admin roles. Use condition keys like aws:PrincipalOrgID and aws:RequestedRegion. Test SCPs in non-production first.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Prevents unauthorized privilege escalation",
            },
            {
                "mitigation_id": "M1098-P2",
                "mitigation_name": "Implement IAM Permission Boundaries",
                "description": "Use permission boundaries to set maximum permissions for IAM entities. Require all IAM users and roles to have boundaries. Implement centralized permission boundary management.",
                "aws_service_action": "Create standard permission boundaries for different roles. Use SCPs to enforce boundary attachment. Implement Lambda functions to automatically attach boundaries to new IAM entities.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-3 weeks",
                "effectiveness": "High - Limits potential damage",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1098-D1",
                "mitigation_name": "Real-Time IAM Change Monitoring",
                "description": "Monitor all IAM API calls in real-time. Alert on CreateUser, AttachUserPolicy, CreateAccessKey, and AssumeRole. Correlate with user context and behavior baselines.",
                "aws_service_action": "Create CloudWatch Events rules for IAM API calls. Use EventBridge to trigger Lambda for automated analysis. Integrate with SIEM. Set up SNS notifications for critical changes.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Rapid detection of account manipulation",
            },
            {
                "mitigation_id": "M1098-D2",
                "mitigation_name": "Enable AWS Config for IAM Compliance",
                "description": "Use AWS Config rules to detect non-compliant IAM configurations. Monitor for users without MFA, over-permissive policies, and unused credentials. Generate compliance reports.",
                "aws_service_action": "Enable AWS Config with managed rules: iam-user-mfa-enabled, iam-user-unused-credentials-check, iam-policy-no-statements-with-admin-access. Create custom rules for organization policies.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Continuous compliance monitoring",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1098-R1",
                "mitigation_name": "Automated IAM Remediation",
                "description": "Automatically remediate non-compliant IAM configurations. Revoke suspicious permissions. Disable compromised users. Implement automated rollback of unauthorized changes.",
                "aws_service_action": "Use AWS Config remediation actions with Systems Manager Automation. Create Lambda functions for custom remediation. Implement approval workflows for sensitive changes. Log all automated actions.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-4 weeks",
                "effectiveness": "High - Reduces exposure time",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1098-RV1",
                "mitigation_name": "IAM Configuration Restoration",
                "description": "Maintain backups of IAM policies and configurations. Implement procedures to restore known-good IAM state after manipulation attacks. Document recovery steps.",
                "aws_service_action": "Use AWS Config to track IAM configuration history. Create Systems Manager Automation for configuration restore. Store policy backups in version-controlled repository.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Enables rapid IAM state restoration",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1098-A1",
                "mitigation_name": "Regular IAM Access Reviews",
                "description": "Conduct quarterly reviews of all IAM users, roles, and policies. Remove unused accounts and permissions. Certify that all access is still required. Document review process and findings.",
                "aws_service_action": "Use IAM credential reports and access advisor. Create automated reports with Lambda and SES. Implement approval workflow for access continuation. Use AWS Audit Manager for audit trail.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week setup, ongoing",
                "effectiveness": "Medium - Reduces attack surface over time",
            },
        ],
    },

    "T1133": {  # External Remote Services
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1133-P1",
                "mitigation_name": "Use AWS Systems Manager Session Manager",
                "description": "Replace SSH/RDP access with Systems Manager Session Manager for secure shell access without exposing ports. No bastion hosts required. All sessions logged to CloudTrail.",
                "aws_service_action": "Install SSM agent on EC2 instances. Create IAM policies for session permissions. Configure Session Manager preferences for logging to S3/CloudWatch. Remove SSH/RDP from security groups.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Eliminates exposed management interfaces",
            },
            {
                "mitigation_id": "M1133-P2",
                "mitigation_name": "Implement Zero Trust Network Access",
                "description": "Use AWS Client VPN with certificate-based authentication and MFA. Implement Private Link for internal service access. Restrict security groups to known IP ranges for legacy remote access.",
                "aws_service_action": "Deploy AWS Client VPN with Mutual TLS. Use AWS Directory Service for authentication. Implement network ACLs for subnet isolation. Use VPC endpoints for private access to AWS services.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-4 weeks",
                "effectiveness": "High - Secure remote access",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1133-D1",
                "mitigation_name": "Monitor Remote Access Sessions",
                "description": "Log all remote access sessions to centralized SIEM. Alert on new session sources, unusual access times, and privilege escalation attempts. Use VPC Flow Logs for network visibility.",
                "aws_service_action": "Enable Session Manager logging to S3 and CloudWatch. Create CloudWatch alarms for remote access from new IPs. Enable VPC Flow Logs. Use GuardDuty for threat intelligence correlation.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Detects unauthorized access",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1133-R1",
                "mitigation_name": "Automated Session Termination",
                "description": "Automatically terminate sessions based on risk signals: access from unusual locations, failed authentication attempts, or suspicious commands. Implement session timeout policies.",
                "aws_service_action": "Use Lambda functions triggered by GuardDuty findings to terminate sessions. Configure Session Manager with idle timeout and max duration. Implement automated incident response workflows.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Limits attacker dwell time",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1133-RV1",
                "mitigation_name": "Remote Access Audit and Restoration",
                "description": "After remote access compromise, audit all accessed systems, rotate credentials, and verify system integrity. Document recovery procedures and lessons learned.",
                "aws_service_action": "Use CloudTrail to audit session activity. Rotate all credentials for accessed systems. Use AWS Inspector to verify system integrity. Generate incident reports.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Ensures complete recovery from compromise",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1133-A1",
                "mitigation_name": "Remote Access Policy and Training",
                "description": "Define and enforce remote access policies. Require MFA and secure endpoints. Train staff on secure remote work practices. Regular policy reviews and updates.",
                "aws_service_action": "Document remote access requirements. Use AWS IAM conditions to enforce policies. Implement AWS SSO for centralized access management. Track compliance with AWS Config.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-4 weeks",
                "effectiveness": "Medium - Reduces human error",
            },
        ],
    },

    "T1562.001": {  # Impair Defenses: Disable or Modify Tools
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1562.001-P1",
                "mitigation_name": "Use SCPs to Protect Security Services",
                "description": "Implement Service Control Policies that prevent disabling CloudTrail, GuardDuty, Config, Security Hub, and Macie. Deny StopLogging, DeleteTrail, DisableSecurityHub, and similar API calls.",
                "aws_service_action": "Create SCPs with explicit deny for security service modifications. Apply to all OUs except designated security team. Use condition keys to allow only specific admin roles. Test thoroughly.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Prevents security tool tampering",
            },
            {
                "mitigation_id": "M1562.001-P2",
                "mitigation_name": "Implement Security Service Redundancy",
                "description": "Deploy logging and monitoring to multiple accounts and regions. Use AWS Control Tower for centralized governance. Implement cross-account log aggregation. Use immutable log storage.",
                "aws_service_action": "Enable organization trail across all accounts. Use S3 Cross-Region Replication for logs. Implement S3 Object Lock on log buckets. Deploy GuardDuty and Security Hub in delegated admin account.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Ensures logging continuity",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1562.001-D1",
                "mitigation_name": "Monitor Security Service Status Changes",
                "description": "Create real-time alerts for any attempts to disable security services. Monitor CloudTrail for StopLogging, DeleteTrail, DisableGuardDuty, and DisableSecurityHub API calls. Alert security team immediately.",
                "aws_service_action": "Create CloudWatch Events rules for security service API calls. Use EventBridge to trigger Lambda for immediate notification. Integrate with incident response tools. Generate high-severity tickets.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Immediate threat detection",
            },
            {
                "mitigation_id": "M1562.001-D2",
                "mitigation_name": "Continuous Security Service Health Checks",
                "description": "Implement automated health checks for all security services. Verify CloudTrail is logging, GuardDuty is enabled, Config is recording. Alert on any service degradation or outage.",
                "aws_service_action": "Create Lambda function to check security service status every 5 minutes. Use CloudWatch Synthetics for API checks. Generate CloudWatch alarms for service failures. Implement automated recovery.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects service failures",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1562.001-R1",
                "mitigation_name": "Automated Security Service Recovery",
                "description": "Automatically re-enable disabled security services. Implement self-healing infrastructure for monitoring and logging. Escalate to security team when automation fails.",
                "aws_service_action": "Use AWS Config remediation to re-enable services. Create Lambda functions for automated recovery. Use Step Functions for complex recovery workflows. Log all recovery actions to Security Hub.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-3 weeks",
                "effectiveness": "High - Minimizes security blind spots",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1562.001-RV1",
                "mitigation_name": "Forensic Analysis and Service Restoration",
                "description": "After security service tampering, conduct forensic analysis to determine what was missed during blind period. Restore full logging and monitoring capabilities. Review and strengthen protections.",
                "aws_service_action": "Use CloudTrail log analysis to identify blind spots. Restore all security services to full functionality. Use AWS Security Hub to verify security posture. Generate incident timeline.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Ensures complete security restoration",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1562.001-A1",
                "mitigation_name": "Security Service Governance Policy",
                "description": "Document requirements for security service availability. Define escalation procedures for service failures. Conduct regular disaster recovery drills. Maintain runbooks for service recovery.",
                "aws_service_action": "Create policy documents and runbooks. Store in centralized wiki or Confluence. Use AWS Organizations tag policies to enforce standards. Regular reviews and updates. Include in onboarding training.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Ensures organizational readiness",
            },
        ],
    },

    "T1552.005": {  # Unsecured Credentials: Cloud Instance Metadata API
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1552.005-P1",
                "mitigation_name": "Enforce IMDSv2 on All Instances",
                "description": "Require Instance Metadata Service Version 2 (IMDSv2) which uses session tokens, making metadata harvesting much harder. Set hop limit to 1 to prevent forwarding attacks.",
                "aws_service_action": "Use EC2 modify-instance-metadata-options to enforce IMDSv2. Set HttpTokens=required and HttpPutResponseHopLimit=1. Use Launch Templates with IMDSv2 enforcement.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Blocks 95%+ of IMDS attacks",
            },
            {
                "mitigation_id": "M1552.005-P2",
                "mitigation_name": "Network Restrictions for Metadata Service",
                "description": "Block access to 169.254.169.254 using security groups and network ACLs where possible. Implement container networking policies to restrict IMDS access.",
                "aws_service_action": "Configure VPC network ACLs to block 169.254.169.254 for non-EC2 workloads. Use ECS task networking policies. Implement Kubernetes Network Policies for EKS.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Defense in depth",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1552.005-D1",
                "mitigation_name": "Monitor IMDSv1 Usage",
                "description": "Create CloudWatch metrics to detect IMDSv1 API calls. Alert on unusual patterns of metadata queries. Use VPC Flow Logs to monitor traffic to 169.254.169.254.",
                "aws_service_action": "Enable VPC Flow Logs and create CloudWatch filters for 169.254.169.254 traffic. Use GuardDuty to detect unusual IMDS queries. Create custom CloudWatch metrics.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Early detection of IMDS abuse",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1552.005-R1",
                "mitigation_name": "Automated IMDSv2 Enforcement",
                "description": "Automatically enforce IMDSv2 on instances detected using IMDSv1. Rotate credentials of instances with suspicious metadata access patterns.",
                "aws_service_action": "Create Lambda function triggered by CloudWatch alarms to enforce IMDSv2. Use AWS Config remediation. Rotate IAM instance profile credentials automatically.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Rapid remediation",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1552.005-RV1",
                "mitigation_name": "Credential Rotation and Incident Analysis",
                "description": "After IMDS compromise, rotate all affected instance profile credentials. Analyze CloudTrail logs to determine what actions were taken with compromised credentials.",
                "aws_service_action": "Use IAM to delete and recreate instance profile roles. Analyze CloudTrail for API calls made with compromised credentials. Use AWS Access Analyzer for blast radius assessment.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Limits credential exposure",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1552.005-A1",
                "mitigation_name": "IMDSv2 Compliance Policy",
                "description": "Establish organization-wide policy requiring IMDSv2 for all EC2 instances. Include in security baselines and deployment standards. Regular compliance audits.",
                "aws_service_action": "Document policy in organization standards. Use AWS Config rules to enforce compliance. Include in onboarding training. Quarterly compliance reports.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Long-term risk reduction",
            },
        ],
    },

    "T1071": {  # Application Layer Protocol (C2)
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1071-P1",
                "mitigation_name": "Deploy AWS Network Firewall",
                "description": "Implement AWS Network Firewall with stateful inspection rules. Block known C2 domains and IPs. Use threat intelligence feeds for dynamic blocking.",
                "aws_service_action": "Deploy Network Firewall in VPC. Configure stateful domain filtering. Enable AWS-managed threat intelligence rule groups. Use custom rules for organization-specific threats.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-4 weeks",
                "effectiveness": "High - Blocks known C2 infrastructure",
            },
            {
                "mitigation_id": "M1071-P2",
                "mitigation_name": "Restrict Egress to Known Destinations",
                "description": "Implement egress filtering to allow only known-good destinations. Use VPC endpoints for AWS services. Require proxy for internet access with TLS inspection.",
                "aws_service_action": "Configure security groups with restrictive egress rules. Deploy VPC endpoints for AWS services. Use AWS Network Firewall or proxy for internet egress. Implement allowlist approach.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 3-4 weeks",
                "effectiveness": "High - Reduces C2 communication channels",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1071-D1",
                "mitigation_name": "Enable Comprehensive Network Monitoring",
                "description": "Enable VPC Flow Logs, Route 53 Resolver Query Logging, and Network Firewall logs. Use GuardDuty for threat intelligence-based detection. Monitor for beaconing and data exfiltration patterns.",
                "aws_service_action": "Enable VPC Flow Logs to CloudWatch. Configure Route 53 Resolver Query Logging. Enable GuardDuty. Send logs to centralized SIEM. Create anomaly detection rules.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Detects C2 communication",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1071-R1",
                "mitigation_name": "Automated C2 Blocking",
                "description": "Automatically block detected C2 domains and IPs. Isolate affected instances. Trigger incident response workflows.",
                "aws_service_action": "Use Lambda to update Network Firewall rules based on GuardDuty findings. Modify security groups to isolate compromised instances. Trigger Step Functions for incident response.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "High - 2-3 weeks",
                "effectiveness": "High - Rapid containment",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1071-RV1",
                "mitigation_name": "Network Forensics and Cleanup",
                "description": "Analyze network logs to determine C2 communication timeline and data exfiltrated. Rebuild affected systems from known-good images. Strengthen network controls.",
                "aws_service_action": "Use CloudWatch Logs Insights for log analysis. Rebuild instances from approved AMIs. Review and strengthen security group rules. Document lessons learned.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 1-2 weeks",
                "effectiveness": "High - Complete incident recovery",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1071-A1",
                "mitigation_name": "Network Security Policy and Training",
                "description": "Establish network security baselines. Document egress requirements. Train teams on secure network architecture. Regular architecture reviews.",
                "aws_service_action": "Create network security standards documentation. Use AWS Service Catalog for approved network patterns. Conduct quarterly network architecture reviews. Include in developer training.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "High - Long-term security improvement",
            },
        ],
    },

    "T1078": {  # Valid Accounts (parent technique)
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1078-P1",
                "mitigation_name": "Enforce MFA on All Accounts",
                "description": "Require multi-factor authentication for all user accounts, service accounts, and privileged access. Use hardware tokens for high-privilege accounts.",
                "aws_service_action": "Enable MFA on all IAM users via IAM console. Configure AWS SSO with MFA enforcement. Use conditional access policies based on risk level.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Blocks 90%+ of credential abuse",
            },
            {
                "mitigation_id": "M1078-P2",
                "mitigation_name": "Implement Least Privilege Access",
                "description": "Grant minimum permissions required for each role. Review and remove unused permissions regularly. Use time-based and condition-based access controls.",
                "aws_service_action": "Use IAM Access Analyzer to identify overly permissive policies. Implement permission boundaries. Create fine-grained policies with explicit conditions.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Reduces blast radius of compromised accounts",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1078-D1",
                "mitigation_name": "Monitor Account Activity with GuardDuty",
                "description": "Enable GuardDuty to detect suspicious authentication patterns, impossible travel, and unusual API calls. Configure real-time alerting for high-severity findings.",
                "aws_service_action": "Enable GuardDuty in all accounts and regions. Configure findings to trigger automated response workflows. Export findings to Security Hub for centralized monitoring.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Detects account abuse in real-time",
            },
            {
                "mitigation_id": "M1078-D2",
                "mitigation_name": "Enable Comprehensive CloudTrail Logging",
                "description": "Log all authentication events and API calls. Enable CloudTrail Insights for anomaly detection. Forward logs to SIEM for correlation and analysis.",
                "aws_service_action": "Enable organization trail with encryption and log validation. Enable CloudTrail Insights. Configure CloudWatch Logs for real-time analysis.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Provides complete audit trail",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1078-R1",
                "mitigation_name": "Automated Credential Rotation",
                "description": "Automatically rotate credentials on detection of suspicious activity. Revoke sessions immediately. Implement break-glass procedures for emergency access.",
                "aws_service_action": "Use Secrets Manager with automatic rotation. Create Lambda functions to revoke access keys on GuardDuty findings. Implement emergency access procedures.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Limits exposure time",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1078-RV1",
                "mitigation_name": "Account Recovery and Forensics",
                "description": "Analyze CloudTrail logs to determine actions taken with compromised credentials. Restore known-good access policies. Document incident for lessons learned.",
                "aws_service_action": "Use CloudTrail log analysis to identify unauthorized actions. Restore IAM policies from backups. Generate incident timeline and report.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Enables complete recovery",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1078-A1",
                "mitigation_name": "Regular Access Reviews and Training",
                "description": "Conduct quarterly access reviews. Remove unused accounts. Train users on credential security and phishing awareness.",
                "aws_service_action": "Use IAM credential reports for access reviews. Implement automated account lifecycle management. Conduct security awareness training quarterly.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - Ongoing",
                "effectiveness": "Medium - Reduces attack surface over time",
            },
        ],
    },

    "T1548": {  # Abuse Elevation Control Mechanism
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1548-P1",
                "mitigation_name": "Implement IAM Permission Boundaries",
                "description": "Use permission boundaries to set maximum permissions that can be granted. Prevent privilege escalation through policy manipulation or role assumption.",
                "aws_service_action": "Create standard permission boundaries for all roles. Use SCPs to enforce boundary attachment. Implement automated checks for boundary compliance.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-3 weeks",
                "effectiveness": "High - Prevents privilege escalation",
            },
            {
                "mitigation_id": "M1548-P2",
                "mitigation_name": "Restrict IAM Write Permissions",
                "description": "Limit who can create, modify, or assume IAM roles. Use SCPs to prevent unauthorized IAM changes. Implement least privilege for IAM administration.",
                "aws_service_action": "Use AWS Organizations SCPs to restrict IAM write actions. Limit iam:PassRole, iam:AttachRolePolicy, and iam:AssumeRole permissions. Implement approval workflows for IAM changes.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Blocks most escalation vectors",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1548-D1",
                "mitigation_name": "Monitor Privilege Escalation Attempts",
                "description": "Create CloudWatch alarms for IAM policy changes, role assumptions, and permission boundary modifications. Alert on AssumeRole calls with elevated permissions.",
                "aws_service_action": "Create CloudWatch Events rules for iam:AttachRolePolicy, iam:PutRolePolicy, iam:AssumeRole. Configure EventBridge to trigger Lambda for analysis. Integrate with Security Hub.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Detects escalation attempts",
            },
            {
                "mitigation_id": "M1548-D2",
                "mitigation_name": "Enable IAM Access Analyzer",
                "description": "Use IAM Access Analyzer to identify overly permissive policies and potential escalation paths. Generate findings for policies granting administrative access.",
                "aws_service_action": "Enable IAM Access Analyzer in all accounts. Configure custom policy checks for privilege escalation patterns. Review findings weekly.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Identifies escalation vectors",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1548-R1",
                "mitigation_name": "Automated Escalation Rollback",
                "description": "Automatically revert unauthorized IAM policy changes. Revoke assumed roles with excessive permissions. Suspend affected users pending investigation.",
                "aws_service_action": "Use AWS Config remediation with Systems Manager Automation to revert IAM changes. Create Lambda functions to revoke suspicious role sessions. Implement automated user suspension.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-4 weeks",
                "effectiveness": "High - Rapid containment",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1548-RV1",
                "mitigation_name": "IAM State Restoration",
                "description": "Restore IAM policies to known-good state from backups. Analyze CloudTrail to determine actions taken with elevated permissions. Strengthen controls to prevent recurrence.",
                "aws_service_action": "Use AWS Config to restore IAM configurations. Analyze CloudTrail for escalation timeline. Implement stricter permission boundaries and SCPs.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "Medium - Enables complete recovery",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1548-A1",
                "mitigation_name": "IAM Security Baseline and Audits",
                "description": "Establish IAM security baseline with documented permission boundaries and escalation controls. Conduct quarterly audits of IAM policies and roles.",
                "aws_service_action": "Document IAM security standards. Use AWS Audit Manager for continuous auditing. Conduct quarterly privilege escalation testing. Train developers on secure IAM practices.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Long-term risk reduction",
            },
        ],
    },

    "T1562": {  # Impair Defenses (parent technique)
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1562-P1",
                "mitigation_name": "Use SCPs to Protect Security Services",
                "description": "Implement Service Control Policies that prevent disabling of security services. Deny API calls to stop logging, disable monitoring, or modify security configurations.",
                "aws_service_action": "Create SCPs with explicit deny for security service modifications (CloudTrail, GuardDuty, Config, Security Hub). Apply to all OUs except security admin. Test thoroughly.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Prevents security tool tampering",
            },
            {
                "mitigation_id": "M1562-P2",
                "mitigation_name": "Implement Cross-Account Logging",
                "description": "Send all logs to separate security account that application teams cannot access. Use S3 Object Lock for immutable log storage.",
                "aws_service_action": "Configure CloudTrail organization trail to dedicated security account. Enable S3 Object Lock on log buckets. Use S3 Cross-Region Replication for redundancy.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Ensures logging continuity",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1562-D1",
                "mitigation_name": "Monitor Security Service Status Changes",
                "description": "Create real-time alerts for attempts to disable security services. Monitor for StopLogging, DeleteTrail, DisableGuardDuty API calls.",
                "aws_service_action": "Create CloudWatch Events rules for security service API calls. Use EventBridge to trigger Lambda for immediate notification. Generate high-severity tickets.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Immediate threat detection",
            },
            {
                "mitigation_id": "M1562-D2",
                "mitigation_name": "Continuous Security Service Health Checks",
                "description": "Implement automated health checks for all security services every 5 minutes. Verify CloudTrail is logging, GuardDuty is enabled, Config is recording.",
                "aws_service_action": "Create Lambda function to check security service status. Use CloudWatch Synthetics for API checks. Generate CloudWatch alarms for service failures.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects service failures",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1562-R1",
                "mitigation_name": "Automated Security Service Recovery",
                "description": "Automatically re-enable disabled security services. Implement self-healing infrastructure. Escalate to security team when automation fails.",
                "aws_service_action": "Use AWS Config remediation to re-enable services. Create Lambda functions for automated recovery. Use Step Functions for complex recovery workflows.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-3 weeks",
                "effectiveness": "High - Minimizes security blind spots",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1562-RV1",
                "mitigation_name": "Forensic Analysis and Service Restoration",
                "description": "Analyze what was missed during blind period. Restore full logging and monitoring capabilities. Review and strengthen protections.",
                "aws_service_action": "Use CloudTrail log analysis to identify blind spots. Restore all security services to full functionality. Generate incident timeline and strengthen SCPs.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Ensures complete recovery",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1562-A1",
                "mitigation_name": "Security Service Governance Policy",
                "description": "Document requirements for security service availability. Define escalation procedures. Conduct regular disaster recovery drills.",
                "aws_service_action": "Create policy documents and runbooks. Use AWS Organizations tag policies to enforce standards. Quarterly DR drills. Include in onboarding training.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Ensures organizational readiness",
            },
        ],
    },

    "T1195": {  # Supply Chain Compromise
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1195-P1",
                "mitigation_name": "Vendor Security Assessment Program",
                "description": "Establish rigorous vendor security assessment process. Require SOC 2 Type II certification, security questionnaires, and third-party audits before onboarding any supplier or software vendor.",
                "aws_service_action": "Use AWS Artifact to access compliance reports. Implement AWS Marketplace Private Marketplace to control which AMIs and third-party software can be deployed. Maintain vendor risk register.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "High - 1-2 months to establish program",
                "effectiveness": "High - Prevents compromised vendor access",
            },
            {
                "mitigation_id": "M1195-P2",
                "mitigation_name": "Code Signing and Verification",
                "description": "Require all third-party libraries, container images, and AMIs to be cryptographically signed. Verify signatures before deployment. Use private artifact repositories with vulnerability scanning.",
                "aws_service_action": "Use Amazon ECR with image scanning enabled. Enable AWS Signer for Lambda functions. Use CodeArtifact with upstream repository filtering. Implement admission controllers in EKS.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "High - Prevents malicious code injection",
            },
            {
                "mitigation_id": "M1195-P3",
                "mitigation_name": "Software Bill of Materials (SBOM)",
                "description": "Generate and maintain SBOM for all applications. Track dependencies and receive alerts for known vulnerabilities. Automate dependency updates and testing.",
                "aws_service_action": "Use Amazon Inspector for container and Lambda vulnerability scanning. Integrate Snyk or similar SBOM tools in CI/CD. Use CodeGuru for code analysis. Enable automated Dependabot.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Identifies supply chain risks",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1195-D1",
                "mitigation_name": "Runtime Behavior Monitoring",
                "description": "Monitor applications for unexpected behavior patterns that may indicate compromised dependencies. Detect anomalous network connections, file access, or API calls.",
                "aws_service_action": "Enable GuardDuty for runtime threat detection. Use VPC Flow Logs to detect unexpected network destinations. Create CloudWatch anomaly detection alarms for application metrics.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects active compromise",
            },
            {
                "mitigation_id": "M1195-D2",
                "mitigation_name": "Continuous Vulnerability Scanning",
                "description": "Continuously scan all deployed resources for newly discovered vulnerabilities. Automate scanning of container images, EC2 instances, and Lambda functions.",
                "aws_service_action": "Enable Amazon Inspector with continuous scanning mode. Use EventBridge to trigger scans on resource creation. Integrate with SIEM for vulnerability trend analysis.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 2-3 days",
                "effectiveness": "High - Early vulnerability detection",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1195-R1",
                "mitigation_name": "Emergency Patching and Rollback",
                "description": "Maintain ability to rapidly patch or rollback affected systems. Implement blue-green deployment for zero-downtime updates. Keep previous versions available for instant rollback.",
                "aws_service_action": "Use CodeDeploy with blue-green deployments. Maintain AMI and container image version history. Use AWS Backup for configuration state preservation. Create automated rollback scripts.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Rapid containment capability",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1195-RV1",
                "mitigation_name": "Supply Chain Incident Recovery",
                "description": "Rebuild compromised systems from trusted sources. Analyze blast radius of supply chain compromise. Implement enhanced monitoring for affected systems.",
                "aws_service_action": "Use AWS Backup to restore from pre-compromise snapshots. Launch new instances from known-good AMIs. Use CloudTrail to identify affected resources. Strengthen artifact verification.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - Varies by incident scope",
                "effectiveness": "High - Complete environment restoration",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1195-A1",
                "mitigation_name": "Supply Chain Security Policy",
                "description": "Establish comprehensive supply chain security policy covering vendor management, dependency tracking, and incident response. Conduct annual supply chain risk assessments.",
                "aws_service_action": "Document supply chain security standards. Use AWS Artifact for compliance documentation. Conduct quarterly vendor security reviews. Include supply chain in threat modeling exercises.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 2-3 months",
                "effectiveness": "Medium - Long-term risk reduction",
            },
        ],
    },

    "T1136.003": {  # Create Account: Cloud Account
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1136.003-P1",
                "mitigation_name": "Restrict IAM User Creation Permissions",
                "description": "Limit IAM user creation to dedicated identity team. Remove CreateUser permissions from all application roles. Enforce MFA for any account with user creation privileges.",
                "aws_service_action": "Create SCP denying CreateUser, CreateAccessKey except for identity admin role. Implement permission boundaries on roles that can create users. Require MFA for identity admin accounts.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Prevents unauthorized account creation",
            },
            {
                "mitigation_id": "M1136.003-P2",
                "mitigation_name": "Centralized Identity Provider Integration",
                "description": "Use AWS IAM Identity Center (SSO) with external identity provider (Okta, Azure AD). Disable long-term IAM user credentials. Enforce federated authentication for human access.",
                "aws_service_action": "Configure IAM Identity Center with SAML 2.0 IdP. Migrate all human users to SSO. Disable IAM user password policies. Use temporary credentials only.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "High - Eliminates persistent credentials",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1136.003-D1",
                "mitigation_name": "Real-Time Account Creation Monitoring",
                "description": "Alert on all IAM user and access key creation events. Trigger automated validation workflow to verify legitimacy of new accounts.",
                "aws_service_action": "Create EventBridge rule for CreateUser, CreateAccessKey API calls. Send alerts to security team via SNS. Use Lambda to auto-query request context and requester identity.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Immediate detection of rogue accounts",
            },
            {
                "mitigation_id": "M1136.003-D2",
                "mitigation_name": "Orphaned Account Detection",
                "description": "Identify IAM users not associated with known employees or service accounts. Detect accounts created outside approved provisioning workflows.",
                "aws_service_action": "Use AWS Config to inventory all IAM users. Compare against HR system or identity provider. Flag accounts without corresponding IdP record. Use Access Analyzer for unused credentials.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Identifies persistent backdoors",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1136.003-R1",
                "mitigation_name": "Automated Rogue Account Suspension",
                "description": "Automatically disable unauthorized IAM users and access keys. Quarantine account for forensic analysis. Notify security team for investigation.",
                "aws_service_action": "Create Lambda function triggered by EventBridge. Disable user login profile and access keys. Add DenyAll inline policy. Move to quarantine OU. Generate incident ticket.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Immediate threat containment",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1136.003-RV1",
                "mitigation_name": "IAM Account Cleanup and Audit",
                "description": "Remove unauthorized accounts. Audit all IAM entities for compromised credentials. Review CloudTrail for actions taken by rogue accounts. Strengthen account creation controls.",
                "aws_service_action": "Delete unauthorized IAM users and access keys. Use CloudTrail Insights to analyze rogue account activity. Review and remediate any resources created or modified. Implement stricter SCPs.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Complete environment sanitization",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1136.003-A1",
                "mitigation_name": "Identity Lifecycle Management Policy",
                "description": "Establish formal identity lifecycle process with provisioning, review, and deprovisioning procedures. Conduct monthly access reviews.",
                "aws_service_action": "Document identity management standards. Use AWS Access Analyzer for periodic access reviews. Implement automated deprovisioning via IdP integration. Quarterly access audits.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Reduces long-term risk",
            },
        ],
    },

    "T1562.008": {  # Impair Defenses: Disable or Modify Cloud Logs
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1562.008-P1",
                "mitigation_name": "Immutable Organization-Wide CloudTrail",
                "description": "Enable AWS Organizations CloudTrail trail with centralized logging to security account. Apply SCPs preventing CloudTrail modification or deletion.",
                "aws_service_action": "Create organization trail in management account. Enable S3 Object Lock on log bucket with compliance mode. Create SCP denying StopLogging, DeleteTrail, PutEventSelectors for all accounts.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Prevents log tampering",
            },
            {
                "mitigation_id": "M1562.008-P2",
                "mitigation_name": "Multi-Region Logging with Replication",
                "description": "Enable CloudTrail in all regions. Replicate logs to secondary region and backup account. Use S3 Cross-Region Replication with replication time control.",
                "aws_service_action": "Configure CloudTrail to log all regions. Enable S3 CRR to backup region. Use S3 Object Lock on both source and destination buckets. Enable CloudTrail log file validation.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "High - Ensures log availability",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1562.008-D1",
                "mitigation_name": "CloudTrail Tampering Detection",
                "description": "Create real-time alerts for any attempts to stop, delete, or modify CloudTrail configurations. Monitor for suspicious log gaps.",
                "aws_service_action": "Create EventBridge rules for CloudTrail modification APIs (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors). Send high-severity alerts via SNS and PagerDuty.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Immediate detection",
            },
            {
                "mitigation_id": "M1562.008-D2",
                "mitigation_name": "Log Integrity Validation",
                "description": "Continuously verify CloudTrail log integrity using built-in validation. Detect missing or tampered log files.",
                "aws_service_action": "Enable CloudTrail log file validation. Create Lambda function to periodically verify log integrity using CloudTrail ValidateLogsIntegrity API. Alert on validation failures.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects log corruption",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1562.008-R1",
                "mitigation_name": "Automated CloudTrail Recovery",
                "description": "Automatically re-enable CloudTrail if stopped. Restore log configuration to known-good state. Escalate to security operations.",
                "aws_service_action": "Use AWS Config remediation to auto-enable CloudTrail. Create Lambda function to restore trail configuration from backup. Use Systems Manager Automation for recovery workflows.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Minimizes blind period",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1562.008-RV1",
                "mitigation_name": "Forensic Analysis of Blind Period",
                "description": "Analyze what activities occurred during logging disruption. Use alternative log sources (VPC Flow Logs, CloudWatch Logs, application logs) to reconstruct timeline.",
                "aws_service_action": "Query VPC Flow Logs for network activity during blind period. Review CloudWatch Logs and application logs. Use GuardDuty findings to identify suspicious activity. Generate incident timeline.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 1-2 weeks",
                "effectiveness": "Medium - Partial visibility restoration",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1562.008-A1",
                "mitigation_name": "Logging and Monitoring Governance",
                "description": "Establish logging requirements and retention policies. Document procedures for log analysis and incident response. Conduct quarterly DR drills for logging infrastructure.",
                "aws_service_action": "Create logging and monitoring standards document. Use AWS Organizations policies to enforce logging. Conduct quarterly tabletop exercises. Include in security training.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Ensures organizational readiness",
            },
        ],
    },

    "T1567.002": {  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1567.002-P1",
                "mitigation_name": "Restrict Outbound Internet Access",
                "description": "Deploy workloads in private subnets without internet gateway access. Route outbound traffic through proxy or NAT gateway with DLP inspection. Whitelist required external destinations only.",
                "aws_service_action": "Use private subnets for application workloads. Deploy AWS Network Firewall or third-party firewall for egress filtering. Create VPC endpoints for AWS services to avoid internet routing.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Limits exfiltration paths",
            },
            {
                "mitigation_id": "M1567.002-P2",
                "mitigation_name": "Data Loss Prevention (DLP)",
                "description": "Implement DLP controls to detect and block sensitive data exfiltration. Classify data based on sensitivity. Monitor and restrict data transfers to external storage services.",
                "aws_service_action": "Use Amazon Macie to discover and classify sensitive data. Deploy third-party DLP solution with network inspection. Create AWS WAF rules to block exfiltration attempts through web applications.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 1-2 months",
                "effectiveness": "High - Prevents data leakage",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1567.002-D1",
                "mitigation_name": "Anomalous Outbound Traffic Detection",
                "description": "Monitor VPC Flow Logs for unusual data transfer patterns. Detect large outbound transfers to external cloud storage services (non-AWS S3, Dropbox, Google Drive).",
                "aws_service_action": "Enable VPC Flow Logs to S3. Use CloudWatch Logs Insights to analyze traffic patterns. Create anomaly detection alarms for unusual outbound volume. Enable GuardDuty Exfiltration findings.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects active exfiltration",
            },
            {
                "mitigation_id": "M1567.002-D2",
                "mitigation_name": "DNS Query Monitoring",
                "description": "Monitor DNS queries for known file-sharing and cloud storage domains. Detect data tunneling via DNS. Use Route 53 Resolver Query Logging.",
                "aws_service_action": "Enable Route 53 Resolver Query Logging. Send logs to CloudWatch Logs. Create metric filters for suspicious domains (dropbox.com, drive.google.com, mega.nz). Alert on matches.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "Medium - Identifies exfiltration attempts",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1567.002-R1",
                "mitigation_name": "Automated Network Isolation",
                "description": "Automatically isolate instances detected performing data exfiltration. Block egress traffic and revoke IAM credentials. Preserve instance for forensics.",
                "aws_service_action": "Create Lambda function triggered by GuardDuty findings. Update security group to deny all egress. Revoke instance IAM role credentials. Create snapshot for investigation. Notify security team.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Stops ongoing exfiltration",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1567.002-RV1",
                "mitigation_name": "Data Exfiltration Impact Assessment",
                "description": "Identify what data was exfiltrated. Assess business impact and compliance implications. Implement enhanced monitoring on recovered systems.",
                "aws_service_action": "Use Macie to identify sensitive data in affected resources. Review VPC Flow Logs to quantify data transfer volume. Analyze CloudTrail to identify data access patterns. Report to stakeholders.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - Varies by incident",
                "effectiveness": "Medium - Enables informed response",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1567.002-A1",
                "mitigation_name": "Data Protection and Classification Policy",
                "description": "Establish data classification framework with handling requirements. Define approved data transfer methods. Conduct annual security awareness training on data protection.",
                "aws_service_action": "Document data classification standards. Use AWS Organizations tag policies to enforce classification tags. Implement least privilege data access. Quarterly data protection training.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "High - 2-3 months",
                "effectiveness": "Medium - Long-term risk reduction",
            },
        ],
    },

    "T1537": {  # Transfer Data to Cloud Account
        DefenseLayer.PREVENTIVE: [
            {
                "mitigation_id": "M1537-P1",
                "mitigation_name": "Restrict Cross-Account Data Transfers",
                "description": "Limit cross-account S3 bucket access using bucket policies and SCPs. Require explicit approval for cross-account access grants. Audit existing cross-account permissions.",
                "aws_service_action": "Create SCP denying s3:PutBucketPolicy, s3:PutObjectAcl unless approved. Use Access Analyzer to identify external S3 access. Implement bucket policies requiring MFA for cross-account access.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Prevents unauthorized data sharing",
            },
            {
                "mitigation_id": "M1537-P2",
                "mitigation_name": "S3 Block Public Access",
                "description": "Enable S3 Block Public Access at organization and account levels. Prevent public buckets and public access grants. Use S3 Access Points with VPC restrictions.",
                "aws_service_action": "Enable S3 Block Public Access for organization in management account. Enforce via SCP. Create AWS Config rule to detect violations. Use VPC endpoints for S3 access.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Low - 1 day",
                "effectiveness": "High - Prevents public data exposure",
            },
        ],
        DefenseLayer.DETECTIVE: [
            {
                "mitigation_id": "M1537-D1",
                "mitigation_name": "S3 Access Pattern Monitoring",
                "description": "Monitor S3 server access logs for unusual cross-account access patterns. Detect large data transfers to external AWS accounts. Alert on bucket policy changes.",
                "aws_service_action": "Enable S3 server access logging to centralized bucket. Use Athena to query logs for cross-account access. Create EventBridge rules for PutBucketPolicy, PutBucketAcl API calls.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "Medium - 1 week",
                "effectiveness": "High - Detects unauthorized sharing",
            },
            {
                "mitigation_id": "M1537-D2",
                "mitigation_name": "Access Analyzer Continuous Monitoring",
                "description": "Use IAM Access Analyzer to continuously monitor for external S3 bucket access. Generate findings for cross-account access grants. Review findings weekly.",
                "aws_service_action": "Enable IAM Access Analyzer for S3. Create EventBridge rule to forward findings to security team. Use Access Analyzer archive rules for approved cross-account access. Review unarchived findings.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Low - 1-2 days",
                "effectiveness": "Medium - Ongoing visibility",
            },
        ],
        DefenseLayer.RESPONSE: [
            {
                "mitigation_id": "M1537-R1",
                "mitigation_name": "Automated Bucket Policy Remediation",
                "description": "Automatically revoke unauthorized cross-account access grants. Restore bucket policies to approved configurations. Quarantine affected buckets for investigation.",
                "aws_service_action": "Use AWS Config auto-remediation to remove unauthorized bucket policies. Create Lambda function to restore known-good policies from backup. Enable S3 Object Lock to prevent data deletion.",
                "priority": MitigationPriority.CRITICAL,
                "implementation_effort": "Medium - 1-2 weeks",
                "effectiveness": "High - Immediate access revocation",
            },
        ],
        DefenseLayer.RECOVERY: [
            {
                "mitigation_id": "M1537-RV1",
                "mitigation_name": "Data Transfer Investigation and Remediation",
                "description": "Identify what data was accessed by external accounts. Assess data sensitivity and business impact. Remove cross-account access and implement enhanced controls.",
                "aws_service_action": "Use S3 access logs and CloudTrail data events to identify accessed objects. Use Macie to classify exposed data. Revoke cross-account access. Implement bucket encryption with KMS.",
                "priority": MitigationPriority.HIGH,
                "implementation_effort": "High - 1-2 weeks",
                "effectiveness": "Medium - Limits ongoing exposure",
            },
        ],
        DefenseLayer.ADMINISTRATIVE: [
            {
                "mitigation_id": "M1537-A1",
                "mitigation_name": "Data Sharing Governance Policy",
                "description": "Establish formal approval process for cross-account data sharing. Document approved external accounts. Conduct quarterly reviews of cross-account access grants.",
                "aws_service_action": "Create data sharing policy and approval workflow. Maintain registry of approved external accounts. Use AWS Organizations tag policies to track sharing approvals. Quarterly access reviews.",
                "priority": MitigationPriority.MEDIUM,
                "implementation_effort": "Medium - 2-3 weeks",
                "effectiveness": "Medium - Reduces long-term risk",
            },
        ],
    },
}



def get_defense_in_depth_mitigations(technique_id: str) -> Dict[DefenseLayer, List[Dict]]:
    """
    Get all defense-in-depth mitigations for a technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078.004")

    Returns:
        Dictionary mapping defense layers to lists of mitigations
    """
    # Try exact match first
    if technique_id in DEFENSE_IN_DEPTH_MITIGATIONS:
        return DEFENSE_IN_DEPTH_MITIGATIONS[technique_id]

    # Try parent technique (e.g., T1078 for T1078.004)
    if "." in technique_id:
        parent_technique = technique_id.split(".")[0]
        if parent_technique in DEFENSE_IN_DEPTH_MITIGATIONS:
            return DEFENSE_IN_DEPTH_MITIGATIONS[parent_technique]

    # Return empty structure if no mitigations found
    return {
        DefenseLayer.PREVENTIVE: [],
        DefenseLayer.DETECTIVE: [],
        DefenseLayer.ADMINISTRATIVE: [],
        DefenseLayer.RESPONSE: [],
        DefenseLayer.RECOVERY: [],
    }


def get_all_mitigations_for_technique(technique_id: str) -> List[Dict]:
    """
    Get all mitigations for a technique across all layers as a flat list.

    Args:
        technique_id: MITRE ATT&CK technique ID

    Returns:
        List of all mitigations with layer information added
    """
    layered_mitigations = get_defense_in_depth_mitigations(technique_id)
    all_mitigations = []

    for layer, mitigations in layered_mitigations.items():
        for mitigation in mitigations:
            mitigation_with_layer = mitigation.copy()
            mitigation_with_layer["defense_layer"] = layer.value
            all_mitigations.append(mitigation_with_layer)

    return all_mitigations


def get_critical_mitigations(technique_id: str) -> List[Dict]:
    """
    Get only critical priority mitigations for a technique.

    Args:
        technique_id: MITRE ATT&CK technique ID

    Returns:
        List of critical priority mitigations
    """
    all_mitigations = get_all_mitigations_for_technique(technique_id)
    return [m for m in all_mitigations if m.get("priority") == MitigationPriority.CRITICAL]
