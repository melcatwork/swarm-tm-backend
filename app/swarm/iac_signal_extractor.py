"""IaC Signal Extractor for cloud-specific security signals.

Extracts cloud abuse signals from parsed IaC asset graphs.
These signals are used by the vulnerability matcher to identify
specific cloud abuse patterns confirmed in the infrastructure.
"""

import re
import json
from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class CloudSignal:
    """
    A cloud-specific security signal detected in IaC configuration.
    These signals indicate conditions that enable specific cloud abuse patterns.
    """
    signal_id: str
    severity: str          # HIGH / MEDIUM / LOW
    resource_id: str
    resource_type: str
    detail: str
    attribute_path: str    # Path to the problematic attribute
    value: Any             # The actual value that triggered the signal


class IaCSignalExtractor:
    """
    Extracts cloud security signals from asset graphs.

    Signals are specific configuration conditions that enable
    documented cloud abuse patterns (e.g., IMDSv1 enabled,
    wildcard IAM permissions, public ingress).
    """

    def _parse_policy_document(self, policy_value: Any) -> Dict:
        """
        Parse IAM policy document from various formats.

        Handles:
        - Direct dict (already parsed)
        - JSON string
        - Terraform jsonencode() expression string

        Args:
            policy_value: Policy value in any supported format

        Returns:
            Parsed policy dict, or empty dict if unparseable
        """
        if isinstance(policy_value, dict):
            return policy_value

        if isinstance(policy_value, str):
            # Try direct JSON parse first
            try:
                return json.loads(policy_value)
            except:
                pass

            # Try to extract from jsonencode() expression
            # Format: ${jsonencode({Version = "...", Statement = [...]})}
            jsonencode_match = re.search(
                r'\$?\{?jsonencode\((.*)\)\}?',
                policy_value,
                re.DOTALL
            )
            if jsonencode_match:
                hcl_obj = jsonencode_match.group(1).strip()
                # Convert HCL object notation to JSON
                # This is a simplified conversion - works for common cases
                hcl_obj = re.sub(r'(\w+)\s*=\s*', r'"\1": ', hcl_obj)  # key = value -> "key": value
                hcl_obj = re.sub(r':\s*"([^"]+)"', r': "\1"', hcl_obj)  # Fix quoted values
                try:
                    return json.loads(hcl_obj)
                except:
                    pass

        return {}

    def _normalize_metadata_options(self, metadata_opts: Any) -> Dict:
        """
        Normalize metadata_options to dict format.

        Handles:
        - List with single dict (HCL block format)
        - Direct dict

        Args:
            metadata_opts: metadata_options value in any format

        Returns:
            Normalized dict
        """
        if isinstance(metadata_opts, list) and metadata_opts:
            return metadata_opts[0] if isinstance(metadata_opts[0], dict) else {}
        elif isinstance(metadata_opts, dict):
            return metadata_opts
        return {}

    def extract(
        self,
        asset_graph: dict,
        raw_iac: dict = None
    ) -> List[CloudSignal]:
        """
        Extract all cloud security signals from asset graph.

        Args:
            asset_graph: Parsed AssetGraph dictionary
            raw_iac: Optional raw IaC for attribute inspection

        Returns:
            List of CloudSignal objects ordered by severity
        """
        signals = []

        assets = asset_graph.get('assets', [])

        for asset in assets:
            asset_id = asset.get('id', 'unknown')
            asset_type = asset.get('type', '')
            properties = asset.get('properties', {})

            # Get original AWS resource type from properties or use asset_type for backward compatibility
            aws_resource_type = properties.get('resource_type', asset_type)

            # Check for IMDSv1 enabled (EC2 instances)
            # Check both normalized type and AWS resource type for compatibility
            if aws_resource_type == 'aws_instance' or asset_type == 'compute.vm':
                # Try properties dict first (new normalized format), fall back to direct attribute (old format)
                metadata_opts_raw = properties.get('metadata_options') or asset.get('metadata_options')
                if metadata_opts_raw:
                    metadata_opts = self._normalize_metadata_options(metadata_opts_raw)
                    http_tokens = metadata_opts.get('http_tokens', 'optional')
                    if http_tokens == 'optional':
                        signals.append(CloudSignal(
                            signal_id='IMDS_V1_ENABLED',
                            severity='HIGH',
                            resource_id=asset_id,
                            resource_type=aws_resource_type,
                            detail=f'IMDSv1 enabled on {asset_id} (http_tokens=optional)',
                            attribute_path='metadata_options.http_tokens',
                            value=http_tokens
                        ))

            # Check for wildcard IAM permissions in policies
            # Check both AWS resource type and normalized type
            is_iam_resource = (
                aws_resource_type in ['aws_iam_role', 'aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy']
                or asset_type.startswith('identity.')
            )

            if is_iam_resource:
                # Try properties dict first (new format), fall back to direct attribute (old format)
                policy_raw = properties.get('policy') or asset.get('policy')
                if policy_raw:
                    # Parse policy document (handles dict, JSON string, or jsonencode expression)
                    policy = self._parse_policy_document(policy_raw)

                    if policy and isinstance(policy, dict):
                        statements = policy.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]

                        for stmt in statements:
                            resources = stmt.get('Resource', [])
                            if isinstance(resources, str):
                                resources = [resources]
                            actions = stmt.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]

                            # Check for S3 wildcard
                            has_s3_wildcard = any('*' in r or r == 'arn:aws:s3:::*' for r in resources)
                            has_s3_action = any('s3:' in a.lower() for a in actions)

                            if has_s3_wildcard and has_s3_action:
                                signals.append(CloudSignal(
                                    signal_id='IAM_S3_WILDCARD',
                                    severity='HIGH',
                                    resource_id=asset_id,
                                    resource_type=aws_resource_type,
                                    detail=f'Wildcard S3 permissions in {asset_id}',
                                    attribute_path='policy.Statement[].Resource',
                                    value=resources
                                ))

                            # Check for privilege escalation actions
                            priv_esc_actions = [
                                'iam:CreateAccessKey', 'iam:CreateLoginProfile',
                                'iam:UpdateLoginProfile', 'iam:AttachUserPolicy',
                                'iam:AttachRolePolicy', 'iam:PutUserPolicy',
                                'iam:PutRolePolicy', 'iam:AddUserToGroup',
                                'iam:UpdateAssumeRolePolicy', 'lambda:UpdateFunctionCode',
                                'lambda:CreateEventSourceMapping', 'sts:AssumeRole'
                            ]
                            has_priv_esc = any(
                                action in actions or action.lower() in [a.lower() for a in actions]
                                for action in priv_esc_actions
                            )

                            if has_priv_esc:
                                signals.append(CloudSignal(
                                    signal_id='IAM_PRIVILEGE_ESCALATION_ACTIONS',
                                    severity='HIGH',
                                    resource_id=asset_id,
                                    resource_type=aws_resource_type,
                                    detail=f'Privilege escalation actions in {asset_id}',
                                    attribute_path='policy.Statement[].Action',
                                    value=[a for a in actions if a in priv_esc_actions]
                                ))

            # Check for CloudTrail without S3 data events
            if aws_resource_type == 'aws_cloudtrail' or asset_type == 'monitoring.trail':
                # Try properties dict first, fall back to direct attribute
                event_selectors = properties.get('event_selector') or asset.get('event_selector', [])
                has_s3_data_events = False

                for selector in event_selectors:
                    data_resources = selector.get('data_resource', [])
                    for dr in data_resources:
                        if dr.get('type') == 'AWS::S3::Object':
                            has_s3_data_events = True
                            break

                if not has_s3_data_events:
                    signals.append(CloudSignal(
                        signal_id='CLOUDTRAIL_NO_S3_DATA_EVENTS',
                        severity='MEDIUM',
                        resource_id=asset_id,
                        resource_type=aws_resource_type,
                        detail=f'CloudTrail {asset_id} not logging S3 data events',
                        attribute_path='event_selector[].data_resource',
                        value=event_selectors
                    ))

            # Check for S3 buckets without resource policies
            if aws_resource_type == 'aws_s3_bucket' or asset_type == 'storage.object':
                # Check if bucket has a policy attached
                # This would need to check relationships in asset_graph
                relationships = asset_graph.get('relationships', [])
                has_policy = any(
                    r.get('source') == asset_id and r.get('type') == 'has_policy'
                    for r in relationships
                )

                if not has_policy:
                    signals.append(CloudSignal(
                        signal_id='S3_NO_RESOURCE_POLICY',
                        severity='MEDIUM',
                        resource_id=asset_id,
                        resource_type=aws_resource_type,
                        detail=f'S3 bucket {asset_id} has no resource policy',
                        attribute_path='bucket_policy',
                        value=None
                    ))

            # Check for security group with open ingress
            if aws_resource_type == 'aws_security_group' or asset_type == 'network.security_group':
                # Try properties dict first, fall back to direct attribute
                ingress_rules = properties.get('ingress') or asset.get('ingress', [])
                for rule in ingress_rules:
                    cidr_blocks = rule.get('cidr_blocks', [])
                    if '0.0.0.0/0' in cidr_blocks or '::/0' in cidr_blocks:
                        signals.append(CloudSignal(
                            signal_id='PUBLIC_INGRESS_OPEN',
                            severity='HIGH',
                            resource_id=asset_id,
                            resource_type=aws_resource_type,
                            detail=f'Public ingress (0.0.0.0/0) on {asset_id} port {rule.get("from_port")}',
                            attribute_path='ingress[].cidr_blocks',
                            value=cidr_blocks
                        ))

            # Check for unrestricted egress
            if aws_resource_type == 'aws_security_group' or asset_type == 'network.security_group':
                # Try properties dict first, fall back to direct attribute
                egress_rules = properties.get('egress') or asset.get('egress', [])
                for rule in egress_rules:
                    cidr_blocks = rule.get('cidr_blocks', [])
                    protocol = rule.get('protocol', '')
                    if ('0.0.0.0/0' in cidr_blocks or '::/0' in cidr_blocks) and protocol == '-1':
                        signals.append(CloudSignal(
                            signal_id='UNRESTRICTED_EGRESS',
                            severity='MEDIUM',
                            resource_id=asset_id,
                            resource_type=aws_resource_type,
                            detail=f'Unrestricted egress (all protocols to 0.0.0.0/0) on {asset_id}',
                            attribute_path='egress[].cidr_blocks',
                            value=cidr_blocks
                        ))

            # Check for shared IAM instance profiles
            if aws_resource_type == 'aws_iam_instance_profile' or asset_type == 'identity.instance_profile':
                # Check how many instances reference this profile
                referencing_instances = [
                    a.get('id') for a in assets
                    if (a.get('properties', {}).get('resource_type') == 'aws_instance' or
                        a.get('type') in ['aws_instance', 'compute.instance'])
                    and (a.get('properties', {}).get('iam_instance_profile') or
                         a.get('iam_instance_profile')) == asset_id
                ]

                if len(referencing_instances) > 1:
                    signals.append(CloudSignal(
                        signal_id='SHARED_IAM_INSTANCE_PROFILE',
                        severity='MEDIUM',
                        resource_id=asset_id,
                        resource_type=aws_resource_type,
                        detail=f'Instance profile {asset_id} shared across {len(referencing_instances)} instances',
                        attribute_path='iam_instance_profile',
                        value=referencing_instances
                    ))

        # Sort by severity (HIGH > MEDIUM > LOW)
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        signals.sort(key=lambda s: severity_order.get(s.severity, 3))

        return signals

    def format_for_agent_prompt(
        self,
        signals: List[CloudSignal],
        max_signals: int = 15
    ) -> str:
        """
        Format cloud signals for agent prompt injection.

        Args:
            signals: List of CloudSignal objects
            max_signals: Maximum signals to include in prompt

        Returns:
            Formatted string for prompt injection
        """
        if not signals:
            return (
                'CLOUD SIGNALS: No high-risk cloud configuration signals detected. '
                'Analyze the infrastructure for other attack vectors.'
            )

        top_signals = signals[:max_signals]

        lines = [
            'CLOUD CONFIGURATION SIGNALS DETECTED:',
            'These are specific configuration conditions confirmed in this infrastructure',
            'that enable documented cloud abuse patterns.',
            '',
        ]

        # Group by severity
        high = [s for s in top_signals if s.severity == 'HIGH']
        medium = [s for s in top_signals if s.severity == 'MEDIUM']
        low = [s for s in top_signals if s.severity == 'LOW']

        if high:
            lines.append(f'HIGH SEVERITY — {len(high)} signals:')
            for sig in high:
                lines.append(f'  [{sig.signal_id}] {sig.detail}')
                lines.append(f'    Resource: {sig.resource_id} ({sig.resource_type})')
                lines.append(f'    Attribute: {sig.attribute_path}')
            lines.append('')

        if medium:
            lines.append(f'MEDIUM SEVERITY — {len(medium)} signals:')
            for sig in medium:
                lines.append(f'  [{sig.signal_id}] {sig.detail}')
                lines.append(f'    Resource: {sig.resource_id}')
            lines.append('')

        if low:
            lines.append(f'LOW SEVERITY — {len(low)} signals:')
            for sig in low:
                lines.append(f'  [{sig.signal_id}] {sig.detail}')
            lines.append('')

        return '\n'.join(lines)
