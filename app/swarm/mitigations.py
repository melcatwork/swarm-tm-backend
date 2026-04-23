"""Mitigation mapping for ATT&CK techniques in attack paths with defense-in-depth support."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from .defense_layers import (
    get_defense_in_depth_mitigations,
    get_all_mitigations_for_technique,
    DefenseLayer,
)

logger = logging.getLogger(__name__)

# AWS-specific contextual mitigations for common techniques
AWS_CONTEXTUAL_MITIGATIONS = {
    "T1078": {
        "mitigation": "Valid Accounts - AWS IAM Hardening",
        "description": "Enable MFA on all IAM users and root account. Implement IAM Access Analyzer to identify overly permissive policies. Use AWS Organizations SCPs to restrict account actions. Enable CloudTrail logging for all API calls. Implement least privilege access with session policies.",
        "aws_service_action": "Enable AWS SSO with MFA, implement permission boundaries, use SCPs to enforce least privilege",
    },
    "T1078.004": {
        "mitigation": "Cloud Accounts - AWS IAM Hardening",
        "description": "Enforce MFA on all IAM users. Review and restrict AssumeRole trust policies. Use IAM conditions to restrict source IP, MFA, and time-based access. Enable CloudTrail and monitor for anomalous authentication patterns. Implement IAM Access Analyzer.",
        "aws_service_action": "Enforce MFA on all IAM users, enable IAM Access Analyzer, review AssumeRole trust policies",
    },
    "T1190": {
        "mitigation": "Exploit Public-Facing Application - AWS Perimeter Defense",
        "description": "Place public-facing resources behind AWS WAF with managed rule groups. Use AWS Shield for DDoS protection. Implement CloudFront with origin access identity. Enable VPC Flow Logs and GuardDuty. Patch applications regularly and use AWS Systems Manager Patch Manager.",
        "aws_service_action": "Deploy AWS WAF with OWASP Top 10 managed rule groups, enable AWS Shield Standard/Advanced",
    },
    "T1133": {
        "mitigation": "External Remote Services - Secure Remote Access",
        "description": "Eliminate direct internet exposure of management interfaces. Use AWS Systems Manager Session Manager instead of SSH/RDP. Implement AWS Client VPN or Private Link. Enforce MFA for all remote access. Restrict security groups to known IP ranges.",
        "aws_service_action": "Use AWS Systems Manager Session Manager, restrict SSH/RDP in security groups to known IPs",
    },
    "T1098": {
        "mitigation": "Account Manipulation - AWS IAM Monitoring",
        "description": "Enable CloudTrail logging for all IAM changes. Create CloudWatch alarms for suspicious IAM modifications (CreateUser, AttachUserPolicy, PutUserPolicy). Implement AWS Config rules to detect policy violations. Use SCPs to prevent privilege escalation.",
        "aws_service_action": "Enable CloudTrail alerts on IAM changes, use AWS Config rules for IAM compliance",
    },
    "T1526": {
        "mitigation": "Cloud Service Discovery - Reduce Attack Surface Visibility",
        "description": "Restrict IAM permissions for List*/Describe* actions. Use VPC endpoints to keep API calls private. Enable CloudTrail and monitor for reconnaissance activities. Implement resource tagging and use tag-based access control.",
        "aws_service_action": "Restrict List*/Describe* IAM permissions, use VPC endpoints for AWS services",
    },
    "T1580": {
        "mitigation": "Cloud Infrastructure Discovery - Limit Cloud Metadata Access",
        "description": "Use IMDSv2 (token-required) for EC2 metadata service. Implement network ACLs and security groups to block 169.254.169.254. Disable unnecessary metadata endpoints. Monitor CloudTrail for suspicious metadata queries.",
        "aws_service_action": "Enforce IMDSv2 on all EC2 instances, restrict metadata service access in security groups",
    },
    "T1530": {
        "mitigation": "Data from Cloud Storage Object - S3 Security Hardening",
        "description": "Enable S3 Block Public Access at account and bucket level. Encrypt all S3 objects at rest with KMS. Use S3 bucket policies and IAM policies with least privilege. Enable S3 access logging and CloudTrail S3 data events. Implement S3 Object Lock for immutable backups.",
        "aws_service_action": "Enable S3 Block Public Access, use S3 bucket policies with least-privilege, enable S3 access logging",
    },
    "T1562.001": {
        "mitigation": "Impair Defenses: Disable or Modify Tools - Protect Security Services",
        "description": "Use SCPs to prevent disabling of CloudTrail, GuardDuty, Config, and Security Hub. Implement CloudWatch alarms for security service changes. Use AWS Control Tower guardrails. Enable AWS Backup for configuration backup.",
        "aws_service_action": "Use SCPs to prevent disabling CloudTrail/GuardDuty, enable AWS Config change tracking",
    },
    "T1552.005": {
        "mitigation": "Unsecured Credentials: Cloud Instance Metadata API",
        "description": "Enforce IMDSv2 (token-required) across all EC2 instances. Use instance profiles and IAM roles instead of hardcoded credentials. Implement hop limit of 1 for metadata service. Monitor CloudTrail for IMDSv1 usage.",
        "aws_service_action": "Enforce IMDSv2 on all EC2/ECS instances, restrict metadata service access in security groups",
    },
    "T1213.003": {
        "mitigation": "Data from Information Repositories: Code Repositories",
        "description": "Enable MFA for AWS CodeCommit access. Use IAM conditions to restrict access. Enable CloudTrail logging for CodeCommit. Scan repositories for secrets with tools like git-secrets or AWS Secrets Manager.",
        "aws_service_action": "Enable MFA for CodeCommit, use IAM conditions for repository access, scan for secrets",
    },
    "T1537": {
        "mitigation": "Transfer Data to Cloud Account - Data Exfiltration Prevention",
        "description": "Implement VPC endpoints to prevent internet data transfer. Use S3 bucket policies to restrict cross-account access. Enable VPC Flow Logs and GuardDuty. Monitor CloudTrail for suspicious S3 API calls (CopyObject to external buckets).",
        "aws_service_action": "Implement VPC endpoints, use S3 bucket policies to block cross-account transfer, enable GuardDuty",
    },
    "T1567.002": {
        "mitigation": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "description": "Restrict outbound internet access via security groups and NACLs. Use VPC endpoints for AWS services. Enable VPC Flow Logs and monitor for unusual data transfer patterns. Implement DLP solutions at network egress points.",
        "aws_service_action": "Restrict outbound internet in security groups/NACLs, use VPC endpoints, enable VPC Flow Logs",
    },
    "T1486": {
        "mitigation": "Data Encrypted for Impact - Ransomware Protection",
        "description": "Enable S3 versioning and Object Lock to prevent deletion/modification. Use AWS Backup with immutable vaults. Implement RDS automated snapshots with cross-region replication. Enable EBS snapshot policies. Use CloudTrail to detect ransomware indicators.",
        "aws_service_action": "Enable S3 versioning and Object Lock, use AWS Backup with immutable vaults, implement RDS automated snapshots",
    },
    "T1485": {
        "mitigation": "Data Destruction - Data Protection",
        "description": "Enable S3 versioning and MFA Delete. Use AWS Backup for automated backups. Implement EBS snapshot lifecycle policies. Enable RDS automated backups with point-in-time recovery. Use AWS Config to detect configuration changes.",
        "aws_service_action": "Enable S3 versioning with MFA Delete, use AWS Backup, implement automated EBS/RDS snapshots",
    },
    "T1496": {
        "mitigation": "Resource Hijacking - Instance Monitoring",
        "description": "Monitor EC2/ECS/Lambda for unusual CPU/network usage with CloudWatch. Enable GuardDuty CryptoCurrency mining detection. Use AWS Cost Anomaly Detection. Implement least privilege IAM for compute resources.",
        "aws_service_action": "Enable GuardDuty CryptoCurrency detection, use CloudWatch alarms for CPU/network anomalies",
    },
    "T1538": {
        "mitigation": "Cloud Service Dashboard - Secure Console Access",
        "description": "Enforce MFA for console access. Use AWS SSO with conditional access policies. Enable CloudTrail to monitor console sign-ins. Implement IP restrictions on console access. Use AWS Control Tower for centralized governance.",
        "aws_service_action": "Enforce MFA for console access, use AWS SSO with MFA, restrict console IPs",
    },
    "T1550.001": {
        "mitigation": "Use Alternate Authentication Material: Application Access Token",
        "description": "Rotate IAM access keys regularly. Use short-lived credentials with IAM roles and STS. Enable CloudTrail to monitor API key usage. Implement IAM Access Analyzer to detect overly permissive tokens.",
        "aws_service_action": "Use IAM roles with STS temporary credentials, rotate access keys regularly, enable IAM Access Analyzer",
    },
    "T1098.001": {
        "mitigation": "Account Manipulation: Additional Cloud Credentials",
        "description": "Monitor IAM credential creation with CloudWatch Events. Use AWS Config rules to detect new access keys. Implement SCPs to restrict credential creation. Enable CloudTrail and alert on suspicious CreateAccessKey API calls.",
        "aws_service_action": "Monitor CreateAccessKey API calls in CloudTrail, use AWS Config rules for credential tracking",
    },
    "T1136.003": {
        "mitigation": "Create Account: Cloud Account",
        "description": "Use SCPs to restrict IAM user creation. Enable CloudTrail monitoring for CreateUser API calls. Implement AWS Config rules for user account compliance. Use AWS Organizations for centralized account management.",
        "aws_service_action": "Use SCPs to restrict user creation, monitor CreateUser API calls, use AWS Organizations",
    },
    "T1562.008": {
        "mitigation": "Impair Defenses: Disable Cloud Logs",
        "description": "Use SCPs to prevent StopLogging, DeleteTrail, and PutEventSelectors. Enable CloudWatch alarms for CloudTrail changes. Implement AWS Control Tower guardrails. Use AWS Config to detect logging changes.",
        "aws_service_action": "Use SCPs to prevent CloudTrail deletion, enable CloudWatch alarms for logging changes",
    },
    "T1071": {
        "mitigation": "Application Layer Protocol - Network Monitoring",
        "description": "Enable VPC Flow Logs to detect command-and-control traffic. Use AWS Network Firewall for deep packet inspection. Enable GuardDuty for threat intelligence-based detection. Monitor unusual DNS queries with Route 53 Resolver Query Logging.",
        "aws_service_action": "Enable VPC Flow Logs, use AWS Network Firewall, enable GuardDuty",
    },
    "T1105": {
        "mitigation": "Ingress Tool Transfer - Network Egress Control",
        "description": "Restrict outbound internet access in security groups. Use VPC endpoints for AWS services. Enable VPC Flow Logs and monitor for unusual file transfers. Implement AWS Network Firewall with domain filtering.",
        "aws_service_action": "Restrict outbound internet in security groups, use AWS Network Firewall with domain filtering",
    },
}


def load_stix_data(stix_path: str = "data/attack_enterprise.json") -> Dict[str, Any]:
    """
    Load ATT&CK STIX data from file.

    Args:
        stix_path: Path to the STIX JSON file (relative to backend directory)

    Returns:
        STIX data dictionary

    Raises:
        FileNotFoundError: If STIX file doesn't exist
        json.JSONDecodeError: If STIX file is invalid JSON
    """
    stix_file = Path(stix_path)

    if not stix_file.exists():
        logger.error(f"STIX file not found: {stix_file}")
        raise FileNotFoundError(f"STIX file not found: {stix_file}")

    logger.info(f"Loading STIX data from {stix_file}")
    with open(stix_file, "r", encoding="utf-8") as f:
        return json.load(f)


def build_mitigation_map(stix_data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """
    Build a map of technique IDs to their mitigations from STIX data.

    Args:
        stix_data: ATT&CK STIX data dictionary

    Returns:
        Dictionary mapping technique IDs (e.g., "T1078") to list of mitigations
    """
    objects = stix_data.get("objects", [])

    # Extract all course-of-action (mitigation) objects
    mitigations = {}
    for obj in objects:
        if obj.get("type") == "course-of-action":
            mitigation_id = obj.get("id")
            name = obj.get("name", "Unnamed Mitigation")
            description = obj.get("description", "")

            # Extract mitigation ID from external references
            external_refs = obj.get("external_references", [])
            mitigation_external_id = None
            if external_refs:
                mitigation_external_id = external_refs[0].get("external_id", "")

            mitigations[mitigation_id] = {
                "mitigation_id": mitigation_external_id or mitigation_id,
                "mitigation_name": name,
                "description": description,
            }

    logger.info(f"Loaded {len(mitigations)} mitigations from STIX data")

    # Build technique-to-mitigation map via relationships
    technique_map = {}

    # First, build attack-pattern ID to technique ID map
    technique_id_map = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            stix_id = obj.get("id")
            external_refs = obj.get("external_references", [])
            if external_refs:
                technique_id = external_refs[0].get("external_id", "")
                if technique_id:
                    technique_id_map[stix_id] = technique_id

    # Extract mitigation relationships
    for obj in objects:
        if obj.get("type") == "relationship":
            rel_type = obj.get("relationship_type")
            if rel_type == "mitigates":
                source_ref = obj.get("source_ref")  # mitigation
                target_ref = obj.get("target_ref")  # technique

                # Get mitigation data
                if source_ref not in mitigations:
                    continue

                mitigation_data = mitigations[source_ref]

                # Get technique ID
                if target_ref not in technique_id_map:
                    continue

                technique_id = technique_id_map[target_ref]

                # Add to map
                if technique_id not in technique_map:
                    technique_map[technique_id] = []

                technique_map[technique_id].append(mitigation_data)

    logger.info(f"Built mitigation map for {len(technique_map)} techniques")
    return technique_map


def map_mitigations(
    paths: List[Dict],
    stix_data_path: str = "data/attack_enterprise.json",
) -> List[Dict]:
    """
    Add mitigation mappings to attack path steps.

    For each technique_id in each path step, verifies/enriches the mitigation field.
    If a step already has an inline mitigation from the agent, it's preserved.
    Otherwise, looks up mitigations from ATT&CK STIX data and adds AWS-specific
    contextual mitigations with aws_service_action fields.

    Args:
        paths: List of attack path dictionaries
        stix_data_path: Path to STIX data file (relative to backend directory)

    Returns:
        List of attack paths with mitigations added/enriched in each step
    """
    if not paths:
        logger.info("No paths to map mitigations for")
        return paths

    try:
        # Load STIX data and build mitigation map
        stix_data = load_stix_data(stix_data_path)
        mitigation_map = build_mitigation_map(stix_data)

        logger.info(f"Mapping mitigations for {len(paths)} attack paths")

        # Process each path
        for path in paths:
            steps = path.get("steps", [])

            for step in steps:
                technique_id = step.get("technique_id", "")

                if not technique_id:
                    # No technique ID, can't map mitigations
                    if "mitigation" not in step or step["mitigation"] is None:
                        step["mitigation"] = None
                        step["mitigations"] = []
                    continue

                # Check if agent already provided an inline mitigation
                existing_mitigation = step.get("mitigation")

                if existing_mitigation and isinstance(existing_mitigation, dict):
                    # Agent provided mitigation - enrich it if needed
                    if not existing_mitigation.get("aws_service_action"):
                        # Try to add AWS service action
                        if technique_id in AWS_CONTEXTUAL_MITIGATIONS:
                            existing_mitigation["aws_service_action"] = AWS_CONTEXTUAL_MITIGATIONS[technique_id]["aws_service_action"]
                        else:
                            parent_technique = technique_id.split(".")[0]
                            if parent_technique in AWS_CONTEXTUAL_MITIGATIONS:
                                existing_mitigation["aws_service_action"] = AWS_CONTEXTUAL_MITIGATIONS[parent_technique]["aws_service_action"]
                            else:
                                existing_mitigation["aws_service_action"] = "Review and implement least-privilege controls"

                    # Keep the agent's mitigation as primary
                    step["mitigation"] = existing_mitigation

                    # Also provide alternative mitigations in array for reference
                    stix_mitigations = mitigation_map.get(technique_id, [])
                    step["mitigations"] = stix_mitigations if stix_mitigations else []

                else:
                    # No inline mitigation from agent - look it up
                    # Get STIX mitigations for this technique
                    stix_mitigations = mitigation_map.get(technique_id, [])

                    # Get defense-in-depth mitigations (preferred for new structured approach)
                    defense_mitigations = get_defense_in_depth_mitigations(technique_id)

                    # Populate mitigations_by_layer with defense-in-depth structure
                    mitigations_by_layer = {}
                    for layer, mitigations in defense_mitigations.items():
                        if mitigations:
                            mitigations_by_layer[layer.value] = mitigations

                    step["mitigations_by_layer"] = mitigations_by_layer if mitigations_by_layer else None

                    # Get all mitigations as flat list
                    all_defense_mitigations = get_all_mitigations_for_technique(technique_id)

                    # Get AWS contextual mitigation (for backward compatibility as primary)
                    aws_mitigation = None

                    # Check for exact match (e.g., T1078.004)
                    if technique_id in AWS_CONTEXTUAL_MITIGATIONS:
                        aws_context = AWS_CONTEXTUAL_MITIGATIONS[technique_id]
                        aws_mitigation = {
                            "mitigation_id": f"AWS-{technique_id}",
                            "mitigation_name": aws_context["mitigation"],
                            "description": aws_context["description"],
                            "aws_service_action": aws_context["aws_service_action"],
                        }

                    # Check for parent technique match (e.g., T1078 for T1078.004)
                    elif technique_id.find(".") > 0:
                        parent_technique = technique_id.split(".")[0]
                        if parent_technique in AWS_CONTEXTUAL_MITIGATIONS:
                            aws_context = AWS_CONTEXTUAL_MITIGATIONS[parent_technique]
                            aws_mitigation = {
                                "mitigation_id": f"AWS-{parent_technique}",
                                "mitigation_name": aws_context["mitigation"],
                                "description": aws_context["description"],
                                "aws_service_action": aws_context["aws_service_action"],
                            }

                    # Set primary mitigation (for backward compatibility)
                    if all_defense_mitigations:
                        # Use first critical mitigation as primary, or first preventive
                        critical_mitigations = [m for m in all_defense_mitigations if m.get("priority") == "critical"]
                        if critical_mitigations:
                            step["mitigation"] = critical_mitigations[0]
                        else:
                            step["mitigation"] = all_defense_mitigations[0]
                    elif aws_mitigation:
                        step["mitigation"] = aws_mitigation
                    elif stix_mitigations:
                        # Use first STIX mitigation, add generic AWS action
                        step["mitigation"] = {
                            **stix_mitigations[0],
                            "aws_service_action": "Review and implement AWS security controls for this technique",
                        }
                    else:
                        # No mitigation found
                        step["mitigation"] = {
                            "mitigation_id": "CUSTOM-001",
                            "mitigation_name": "General Security Hardening",
                            "description": "Implement security best practices and least-privilege access controls",
                            "aws_service_action": "Review AWS security best practices and implement appropriate controls",
                        }

                    # Store all available mitigations for reference
                    step["all_mitigations"] = all_defense_mitigations if all_defense_mitigations else stix_mitigations

        logger.info("Mitigation mapping complete")
        return paths

    except FileNotFoundError as e:
        logger.error(f"Failed to load STIX data: {e}")
        # Return paths with minimal mitigations rather than failing
        for path in paths:
            for step in path.get("steps", []):
                if not step.get("mitigation"):
                    step["mitigation"] = {
                        "mitigation_id": "CUSTOM-001",
                        "mitigation_name": "General Security Hardening",
                        "description": "Implement security best practices",
                        "aws_service_action": "Review AWS security best practices",
                    }
                step.setdefault("mitigations", [])
        return paths

    except Exception as e:
        logger.error(f"Error mapping mitigations: {e}", exc_info=True)
        # Return paths with minimal mitigations rather than failing
        for path in paths:
            for step in path.get("steps", []):
                if not step.get("mitigation"):
                    step["mitigation"] = {
                        "mitigation_id": "CUSTOM-001",
                        "mitigation_name": "General Security Hardening",
                        "description": "Implement security best practices",
                        "aws_service_action": "Review AWS security best practices",
                    }
                step.setdefault("mitigations", [])
        return paths


def analyze_post_mitigation_impact(
    attack_paths: List[Dict],
    selected_mitigations: List[Dict],
) -> Dict[str, Any]:
    """
    Analyze the impact of selected mitigations on attack paths.

    For each attack path, determines which steps are blocked, reduced in effectiveness,
    or remain viable based on the mitigations the user selected to implement.

    Args:
        attack_paths: List of original attack path dictionaries
        selected_mitigations: List of mitigation selections with format:
            [{"path_id": str, "step_number": int, "mitigation_id": str, "selected": bool}, ...]

    Returns:
        Dictionary with:
        - post_mitigation_paths: List of PostMitigationPath objects
        - residual_risk: ResidualRisk assessment
    """
    from app.swarm.models import (
        PostMitigationPath,
        StepImpact,
        ResidualRisk,
    )

    logger.info(f"Analyzing post-mitigation impact for {len(attack_paths)} paths")

    # Build a map of selected mitigations for quick lookup
    # Key: f"{path_id}:{step_number}", Value: list of mitigation_ids
    selected_map = {}
    for sel in selected_mitigations:
        if sel.get("selected", False):
            key = f"{sel['path_id']}:{sel['step_number']}"
            if key not in selected_map:
                selected_map[key] = []
            selected_map[key].append(sel["mitigation_id"])

    logger.info(f"User selected {len(selected_map)} mitigation applications")

    post_mitigation_paths = []
    original_scores = []
    residual_scores = []

    for path in attack_paths:
        # Try multiple fields for path identifier (id, path_id, name as fallback)
        path_id = path.get("id") or path.get("path_id") or path.get("name", "")
        path_name = path.get("name", "Unnamed Path")
        objective = path.get("objective", "")
        original_difficulty = path.get("difficulty", "medium")
        original_score = path.get("composite_score", 5.0)
        original_scores.append(original_score)

        steps = path.get("steps", [])
        step_impacts = []

        blocked_count = 0
        reduced_count = 0
        active_count = 0

        # Track reduction percentage for each step
        step_reduction_percentages = []

        for step in steps:
            step_number = step.get("step_number", 0)
            technique_id = step.get("technique_id", "")
            mitigation = step.get("mitigation", {})

            # Count total recommended mitigations for this step
            # Check all_mitigations first, then mitigations_by_layer, fallback to 1 if only primary mitigation
            all_mitigations = step.get("all_mitigations", [])
            mitigations_by_layer = step.get("mitigations_by_layer", {})

            if all_mitigations:
                total_recommended = len(all_mitigations)
            elif mitigations_by_layer:
                # Count mitigations across all layers (preventive, detective, corrective, administrative)
                total_recommended = sum(len(mits) for mits in mitigations_by_layer.values())
            else:
                # Fallback: only primary mitigation available
                total_recommended = 1 if mitigation else 0

            # Check if this step has selected mitigations
            key = f"{path_id}:{step_number}"
            applied_mitigations = selected_map.get(key, [])
            selected_count = len(applied_mitigations)

            if not applied_mitigations or total_recommended == 0:
                # No mitigations applied to this step - remains active
                step_impacts.append(
                    StepImpact(
                        step_number=step_number,
                        original_status="active",
                        post_mitigation_status="active",
                        effectiveness="none",
                        reasoning="No mitigations selected for this step",
                        applied_mitigations=[],
                    )
                )
                active_count += 1
                step_reduction_percentages.append(0.0)  # 0% reduction
            else:
                # Mitigations applied - determine effectiveness with completeness
                effectiveness, status, reasoning, reduction_pct = _evaluate_mitigation_effectiveness(
                    technique_id, mitigation, applied_mitigations, step,
                    selected_count, total_recommended
                )

                step_impacts.append(
                    StepImpact(
                        step_number=step_number,
                        original_status="active",
                        post_mitigation_status=status,
                        effectiveness=effectiveness,
                        reasoning=reasoning,
                        applied_mitigations=applied_mitigations,
                    )
                )

                step_reduction_percentages.append(reduction_pct)

                if status == "blocked":
                    blocked_count += 1
                elif status == "reduced":
                    reduced_count += 1
                else:
                    active_count += 1

        # Determine overall path status
        total_steps = len(steps)
        if blocked_count == total_steps:
            path_status = "neutralized"
        elif blocked_count >= total_steps * 0.5:
            path_status = "significantly_reduced"
        elif blocked_count > 0 or reduced_count > 0:
            path_status = "partially_mitigated"
        else:
            path_status = "still_viable"

        # Calculate residual risk score based on average step reduction
        # This ensures: full mitigation selection → higher reduction → lower residual risk
        # than partial mitigation selection
        if step_reduction_percentages:
            total_reduction = sum(step_reduction_percentages) / len(step_reduction_percentages)
            total_reduction = min(total_reduction, 0.95)  # Cap at 95%
        else:
            total_reduction = 0.0

        logger.info(
            f"Path '{path_name}': {len(step_reduction_percentages)} steps analyzed, "
            f"average reduction: {total_reduction*100:.1f}% "
            f"(blocked: {blocked_count}, reduced: {reduced_count}, active: {active_count})"
        )

        residual_risk_score = original_score * (1 - total_reduction)
        residual_scores.append(residual_risk_score)

        # Calculate CSA-based residual risk (mitigations reduce LIKELIHOOD, not IMPACT)
        residual_csa_risk_score = None
        csa_score = path.get("csa_risk_score")
        if csa_score:
            # Get original CSA likelihood and impact
            original_likelihood = csa_score.get("likelihood", {}).get("score", 3)
            original_impact = csa_score.get("impact", {}).get("score", 5)
            original_risk_band = csa_score.get("risk_band", "Medium")

            # Reduce likelihood based on mitigation effectiveness
            # Mitigations affect likelihood (how easy to attack), NOT impact (data classification)
            residual_likelihood_float = original_likelihood * (1 - total_reduction)
            residual_likelihood = max(1, min(5, round(residual_likelihood_float)))

            # Calculate residual risk level
            residual_risk_level = residual_likelihood * original_impact

            # Map risk_level to risk_band (CSA CII 5x5 matrix)
            if residual_risk_level >= 20:
                residual_risk_band = 'Very High'
            elif residual_risk_level >= 15:
                residual_risk_band = 'High'
            elif residual_risk_level >= 10:
                residual_risk_band = 'Medium-High'
            elif residual_risk_level >= 5:
                residual_risk_band = 'Medium'
            else:
                residual_risk_band = 'Low'

            residual_csa_risk_score = {
                'likelihood': {
                    'score': residual_likelihood,
                    'label': {1: 'Very Low', 2: 'Low', 3: 'Moderate', 4: 'High', 5: 'Very High'}[residual_likelihood],
                },
                'impact': {
                    'score': original_impact,
                    'label': csa_score.get("impact", {}).get("label", "Very Severe"),
                },
                'risk_level': residual_risk_level,
                'risk_band': residual_risk_band,
            }

            logger.debug(
                f"Path {path_id}: CSA risk reduced from {original_risk_band} "
                f"({original_likelihood}×{original_impact}={csa_score.get('risk_level')}) "
                f"to {residual_risk_band} ({residual_likelihood}×{original_impact}={residual_risk_level})"
            )

        # Adjust difficulty
        if path_status == "neutralized":
            post_mitigation_difficulty = "neutralized"
        elif path_status == "significantly_reduced":
            post_mitigation_difficulty = "very_high"
        elif path_status == "partially_mitigated":
            if original_difficulty == "low":
                post_mitigation_difficulty = "medium"
            elif original_difficulty == "medium":
                post_mitigation_difficulty = "high"
            else:
                post_mitigation_difficulty = "very_high"
        else:
            post_mitigation_difficulty = original_difficulty

        post_mitigation_paths.append(
            PostMitigationPath(
                path_id=path_id,
                path_name=path_name,
                original_objective=objective,
                original_difficulty=original_difficulty,
                post_mitigation_difficulty=post_mitigation_difficulty,
                steps_blocked=blocked_count,
                steps_reduced=reduced_count,
                steps_remaining=active_count,
                step_impacts=step_impacts,
                path_status=path_status,
                residual_risk_score=round(residual_risk_score, 2),
                residual_csa_risk_score=residual_csa_risk_score,
            )
        )

    # Calculate residual risk summary
    paths_by_status = {
        "neutralized": len([p for p in post_mitigation_paths if p.path_status == "neutralized"]),
        "significantly_reduced": len([p for p in post_mitigation_paths if p.path_status == "significantly_reduced"]),
        "partially_mitigated": len([p for p in post_mitigation_paths if p.path_status == "partially_mitigated"]),
        "still_viable": len([p for p in post_mitigation_paths if p.path_status == "still_viable"]),
    }

    # Risk reduction calculation based on CSA risk levels (not composite scores)
    # This aligns with what users see in per-path CSA risk band displays
    # ONLY include primary and alternate attack paths (confirmed_vuln_synthesis)
    # Excludes agent exploration paths
    original_csa_total = sum([
        path.get("csa_risk_score", {}).get("risk_level", 0)
        for path in attack_paths
        if path.get("source") == "confirmed_vuln_synthesis"
    ])
    residual_csa_total = sum([
        p.residual_csa_risk_score.get("risk_level", 0)
        for p in post_mitigation_paths
        if p.residual_csa_risk_score and p.path_id in [
            path.get("id") or path.get("path_id") or path.get("name", "")
            for path in attack_paths
            if path.get("source") == "confirmed_vuln_synthesis"
        ]
    ])

    # Fallback to composite scores if CSA scores not available
    if original_csa_total == 0:
        logger.warning("No CSA risk scores found, falling back to composite score calculation")
        original_mean_score = sum(original_scores) / len(original_scores) if original_scores else 0
        residual_mean_score = sum(residual_scores) / len(residual_scores) if residual_scores else 0
        risk_reduction = ((original_mean_score - residual_mean_score) / original_mean_score * 100) if original_mean_score > 0 else 0
    else:
        risk_reduction = ((original_csa_total - residual_csa_total) / original_csa_total * 100) if original_csa_total > 0 else 0
        logger.info(
            f"CSA-based risk reduction: {original_csa_total} → {residual_csa_total} "
            f"({risk_reduction:.1f}% reduction)"
        )

    # Calculate mean residual risk score (for backward compatibility in API response)
    residual_mean_score = sum(residual_scores) / len(residual_scores) if residual_scores else 0.0

    # Top residual risks (top 3 still viable or partially mitigated paths)
    viable_paths = [
        p for p in post_mitigation_paths
        if p.path_status in ["still_viable", "partially_mitigated"]
    ]
    viable_paths.sort(key=lambda x: x.residual_risk_score, reverse=True)
    top_residual_risks = [
        {
            "path_id": p.path_id,
            "path_name": p.path_name,
            "residual_risk_score": p.residual_risk_score,
            "path_status": p.path_status,
            "steps_remaining": p.steps_remaining,
        }
        for p in viable_paths[:3]
    ]

    # Generate recommendations
    recommendations = _generate_residual_risk_recommendations(
        post_mitigation_paths, attack_paths
    )

    residual_risk = ResidualRisk(
        total_paths_analyzed=len(attack_paths),
        paths_neutralized=paths_by_status["neutralized"],
        paths_significantly_reduced=paths_by_status["significantly_reduced"],
        paths_partially_mitigated=paths_by_status["partially_mitigated"],
        paths_still_viable=paths_by_status["still_viable"],
        highest_residual_risk_score=max(residual_scores) if residual_scores else 0.0,
        mean_residual_risk_score=round(residual_mean_score, 2),
        risk_reduction_percentage=round(risk_reduction, 1),
        top_residual_risks=top_residual_risks,
        recommendations=recommendations,
    )

    logger.info(
        f"Post-mitigation analysis complete: {paths_by_status['neutralized']} neutralized, "
        f"{paths_by_status['still_viable']} still viable"
    )

    return {
        "post_mitigation_paths": [p.model_dump() for p in post_mitigation_paths],
        "residual_risk": residual_risk.model_dump(),
    }


def _evaluate_mitigation_effectiveness(
    technique_id: str,
    mitigation: Dict,
    applied_mitigations: List[str],
    step: Dict,
    selected_count: int,
    total_recommended: int,
) -> tuple[str, str, str, float]:
    """
    Evaluate how effective applied mitigations are against a specific attack step.

    Effectiveness is scaled by completeness: selecting all recommended mitigations
    produces higher reduction than selecting only some.

    Args:
        technique_id: MITRE ATT&CK technique ID
        mitigation: Primary mitigation dictionary
        applied_mitigations: List of selected mitigation IDs/names
        step: Full step dictionary
        selected_count: Number of mitigations selected for this step
        total_recommended: Total mitigations recommended for this step

    Returns:
        Tuple of (effectiveness: str, status: str, reasoning: str, reduction_pct: float)
        effectiveness: "high", "medium", "low", "none"
        status: "blocked", "reduced", "active"
        reduction_pct: 0.0 to 1.0 (percentage reduction for this step)
    """
    # Calculate completeness ratio
    completeness = selected_count / total_recommended if total_recommended > 0 else 0.0

    # Check if applied mitigation IDs or NAMEs match the step's mitigation
    mitigation_name = mitigation.get("mitigation_name", "")
    mitigation_id = mitigation.get("mitigation_id", "")

    # High effectiveness techniques - these are strongly blocked by their mitigations
    high_effectiveness_techniques = {
        "T1552.005": "IMDSv2 enforcement completely blocks metadata service exploitation",
        "T1078": "MFA enforcement significantly raises the bar for credential abuse",
        "T1078.004": "MFA and IAM Access Analyzer make cloud account abuse much harder",
        "T1190": "AWS WAF and Shield provide strong protection against exploitation",
        "T1133": "Session Manager eliminates direct SSH/RDP exposure",
        "T1530": "S3 Block Public Access and encryption prevent unauthorized data access",
        "T1537": "VPC endpoints and bucket policies prevent cross-account data transfer",
        "T1562.001": "SCPs prevent disabling of security services",
        "T1562.008": "SCPs prevent CloudTrail deletion and log tampering",
    }

    # Medium effectiveness techniques - mitigations make attacks harder but not impossible
    medium_effectiveness_techniques = {
        "T1098": "CloudTrail monitoring and alerts detect account manipulation but don't prevent it",
        "T1526": "Restricting List*/Describe* reduces reconnaissance but doesn't eliminate it",
        "T1580": "Network restrictions limit discovery but authenticated users retain some visibility",
        "T1213.003": "MFA and access controls reduce code repository access risk",
        "T1567.002": "Network egress controls make exfiltration harder but not impossible",
        "T1486": "Versioning and backups enable recovery but don't prevent ransomware",
        "T1485": "Backups enable recovery but don't prevent destruction attempts",
        "T1496": "Monitoring detects hijacking but doesn't prevent initial compromise",
        "T1538": "Console MFA adds friction but doesn't prevent authorized user abuse",
        "T1550.001": "Token rotation reduces window but doesn't eliminate token abuse",
        "T1071": "Network monitoring detects C2 but doesn't block all protocols",
        "T1105": "Egress controls make file transfer harder but not impossible",
    }

    if mitigation_name in applied_mitigations or mitigation_id in applied_mitigations:
        # The recommended mitigation for this step was selected
        # Scale effectiveness by completeness ratio
        if technique_id in high_effectiveness_techniques:
            # HIGH effectiveness techniques - scale from 15% to 100% based on completeness
            if completeness >= 1.0:
                reduction_pct = 1.00  # 100% - all mitigations selected, fully blocked
                status = "blocked"
                effectiveness = "high"
            elif completeness >= 0.80:
                reduction_pct = 0.85  # 85% - most mitigations, mostly blocked
                status = "blocked"
                effectiveness = "high"
            elif completeness >= 0.60:
                reduction_pct = 0.70  # 70% - majority, significantly reduced
                status = "reduced"
                effectiveness = "high"
            elif completeness >= 0.40:
                reduction_pct = 0.50  # 50% - half selected, reduced
                status = "reduced"
                effectiveness = "medium"
            elif completeness >= 0.20:
                reduction_pct = 0.30  # 30% - some selected, minimally reduced
                status = "reduced"
                effectiveness = "low"
            else:
                reduction_pct = 0.15  # 15% - very few selected, slightly reduced
                status = "reduced"
                effectiveness = "low"

            reasoning = f"{high_effectiveness_techniques[technique_id]} (Completeness: {completeness*100:.0f}% - {selected_count}/{total_recommended} mitigations)"
            return (effectiveness, status, reasoning, reduction_pct)

        elif technique_id in medium_effectiveness_techniques:
            # MEDIUM effectiveness techniques - scale from 6% to 50% based on completeness
            if completeness >= 1.0:
                reduction_pct = 0.50  # 50% - all selected, reduced
                effectiveness = "medium"
            elif completeness >= 0.80:
                reduction_pct = 0.40  # 40% - most selected, reduced
                effectiveness = "medium"
            elif completeness >= 0.60:
                reduction_pct = 0.30  # 30% - majority, reduced
                effectiveness = "medium"
            elif completeness >= 0.40:
                reduction_pct = 0.20  # 20% - half, minimally reduced
                effectiveness = "low"
            elif completeness >= 0.20:
                reduction_pct = 0.12  # 12% - some, slightly reduced
                effectiveness = "low"
            else:
                reduction_pct = 0.06  # 6% - very few, slightly reduced
                effectiveness = "low"

            reasoning = f"{medium_effectiveness_techniques[technique_id]} (Completeness: {completeness*100:.0f}% - {selected_count}/{total_recommended} mitigations)"
            return (effectiveness, "reduced", reasoning, reduction_pct)

        else:
            # Generic mitigation effectiveness - scale from 3% to 25% based on completeness
            if completeness >= 1.0:
                reduction_pct = 0.25
                effectiveness = "low"
            elif completeness >= 0.80:
                reduction_pct = 0.20
                effectiveness = "low"
            elif completeness >= 0.60:
                reduction_pct = 0.15
                effectiveness = "low"
            elif completeness >= 0.40:
                reduction_pct = 0.10
                effectiveness = "low"
            elif completeness >= 0.20:
                reduction_pct = 0.06
                effectiveness = "low"
            else:
                reduction_pct = 0.03
                effectiveness = "low"

            reasoning = f"Mitigation {mitigation_id} reduces effectiveness of {technique_id} (Completeness: {completeness*100:.0f}% - {selected_count}/{total_recommended} mitigations)"
            return (effectiveness, "reduced", reasoning, reduction_pct)
    else:
        # Different mitigation was selected - assess based on AWS contextual knowledge
        # Apply low effectiveness with completeness scaling
        aws_mitigation = AWS_CONTEXTUAL_MITIGATIONS.get(technique_id)
        if aws_mitigation:
            # Check if any applied mitigation relates to AWS service
            mitigation_name = mitigation.get("mitigation_name", "")
            aws_action = mitigation.get("aws_service_action", "")

            # If the mitigation mentions key AWS services for this technique, it has some effect
            if any(keyword in mitigation_name.lower() + aws_action.lower()
                   for keyword in ["iam", "mfa", "cloudtrail", "guardduty", "waf", "s3", "vpc"]):
                # Scale from 2% to 15% based on completeness
                reduction_pct = 0.02 + (completeness * 0.13)  # 2% to 15%
                reasoning = f"Applied mitigation provides some defense-in-depth against {technique_id} (Completeness: {completeness*100:.0f}%)"
                return ("low", "reduced", reasoning, reduction_pct)

        # Fallback - mitigation provides minimal protection (1% to 8% based on completeness)
        reduction_pct = 0.01 + (completeness * 0.07)
        reasoning = f"Applied mitigation provides limited protection against {technique_id} (Completeness: {completeness*100:.0f}%)"
        return ("low", "reduced", reasoning, reduction_pct)


def _generate_residual_risk_recommendations(
    post_mitigation_paths: List,
    original_paths: List[Dict],
) -> List[str]:
    """
    Generate actionable recommendations based on residual risks.

    Args:
        post_mitigation_paths: List of PostMitigationPath objects
        original_paths: Original attack path dictionaries

    Returns:
        List of recommendation strings
    """
    recommendations = []

    # Find paths that are still viable
    viable_paths = [p for p in post_mitigation_paths if p.path_status == "still_viable"]

    if viable_paths:
        recommendations.append(
            f"Priority: {len(viable_paths)} attack path(s) remain fully viable. "
            "Review unmitigated steps and consider implementing additional controls."
        )

    # Find paths that are partially mitigated
    partial_paths = [p for p in post_mitigation_paths if p.path_status == "partially_mitigated"]

    if partial_paths:
        recommendations.append(
            f"{len(partial_paths)} attack path(s) are partially mitigated. "
            "Consider implementing remaining recommended mitigations to fully neutralize these threats."
        )

    # Identify common unmitigated techniques across paths
    unmitigated_techniques = {}
    for post_path in post_mitigation_paths:
        if post_path.path_status in ["still_viable", "partially_mitigated"]:
            # Find corresponding original path
            original_path = next((p for p in original_paths if p.get("id") == post_path.path_id), None)
            if original_path:
                for step in original_path.get("steps", []):
                    step_num = step.get("step_number")
                    technique_id = step.get("technique_id", "")

                    # Check if this step is still active
                    step_impact = next((si for si in post_path.step_impacts if si.step_number == step_num), None)
                    if step_impact and step_impact.post_mitigation_status == "active":
                        if technique_id not in unmitigated_techniques:
                            unmitigated_techniques[technique_id] = {
                                "count": 0,
                                "name": step.get("technique_name", technique_id)
                            }
                        unmitigated_techniques[technique_id]["count"] += 1

    # Recommend top 3 unmitigated techniques
    if unmitigated_techniques:
        sorted_techniques = sorted(
            unmitigated_techniques.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:3]

        for tech_id, data in sorted_techniques:
            recommendations.append(
                f"Technique {tech_id} ({data['name']}) remains unmitigated in {data['count']} path(s). "
                "Consider implementing controls for this technique."
            )

    # If risk reduction is low, recommend more comprehensive mitigation
    neutralized = len([p for p in post_mitigation_paths if p.path_status == "neutralized"])
    total = len(post_mitigation_paths)

    if neutralized / total < 0.5 if total > 0 else False:
        recommendations.append(
            "Less than 50% of attack paths are neutralized. Consider implementing a more "
            "comprehensive mitigation strategy across multiple kill chain phases."
        )

    # Recommend defense-in-depth
    if len(viable_paths) + len(partial_paths) > 0:
        recommendations.append(
            "Implement defense-in-depth: layer multiple controls (preventive, detective, responsive) "
            "to increase attacker cost and detection likelihood."
        )

    # If no recommendations generated, add a positive note
    if not recommendations:
        recommendations.append(
            "Excellent coverage! All attack paths are neutralized or significantly reduced. "
            "Continue monitoring and adjust controls as infrastructure evolves."
        )

    return recommendations
