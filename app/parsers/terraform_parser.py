"""Terraform HCL2 parser for extracting infrastructure assets and relationships."""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple

import hcl2

from app.utils.timezone import now_gmt8
from .models import (
    Asset,
    Relationship,
    TrustBoundary,
    AssetGraph,
    aws_type_mapper,
)

logger = logging.getLogger(__name__)


class TerraformParser:
    """
    Parser for Terraform HCL2 files.

    Extracts infrastructure assets, relationships, and trust boundaries
    from Terraform configuration files for threat modeling analysis.
    """

    def __init__(self):
        """Initialize the Terraform parser."""
        self.resources = {}  # resource_id -> resource_data
        self.assets = []
        self.relationships = []
        self.trust_boundaries = []

    def _clean_string(self, value: str) -> str:
        """
        Remove HCL2 quotes from string values.

        Args:
            value: String value (may have quotes)

        Returns:
            Cleaned string without surrounding quotes
        """
        if isinstance(value, str) and value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        return value

    def _clean_config(self, config: Any) -> Any:
        """
        Recursively clean HCL2 configuration data by removing quotes.

        Args:
            config: Configuration data (dict, list, or primitive)

        Returns:
            Cleaned configuration data
        """
        if isinstance(config, dict):
            cleaned = {}
            for key, value in config.items():
                # Skip HCL2 metadata
                if key == "__is_block__":
                    continue
                cleaned_key = self._clean_string(key)
                cleaned[cleaned_key] = self._clean_config(value)
            return cleaned

        elif isinstance(config, list):
            return [self._clean_config(item) for item in config]

        elif isinstance(config, str):
            cleaned = self._clean_string(config)
            # Convert string booleans to actual booleans
            if cleaned.lower() == "true":
                return True
            elif cleaned.lower() == "false":
                return False
            return cleaned

        else:
            return config

    def parse(self, file_content: str) -> AssetGraph:
        """
        Parse Terraform HCL2 content into an AssetGraph.

        Args:
            file_content: String content of a Terraform .tf file

        Returns:
            AssetGraph with extracted assets, relationships, and trust boundaries

        Raises:
            ValueError: If HCL2 parsing fails
        """
        try:
            # Parse HCL2 content
            parsed = hcl2.loads(file_content)
            logger.info("Successfully parsed Terraform HCL2 content")

        except Exception as e:
            logger.error(f"Failed to parse HCL2: {e}")
            raise ValueError(f"Invalid HCL2 syntax: {str(e)}")

        # Reset parser state
        self.resources = {}
        self.assets = []
        self.relationships = []
        self.trust_boundaries = []

        # Extract resources
        resources_list = parsed.get("resource", [])
        logger.info(f"Found {len(resources_list)} resource blocks")

        # First pass: extract all resources and build asset catalog
        for resource_block in resources_list:
            self._extract_resources(resource_block)

        # Second pass: build assets from resources
        for resource_id, resource_data in self.resources.items():
            asset = self._build_asset(resource_id, resource_data)
            if asset:
                self.assets.append(asset)

        # Third pass: identify relationships
        self._build_relationships()

        # Fourth pass: group into trust boundaries
        self._build_trust_boundaries()

        # Build metadata
        metadata = {
            "source_file": "terraform",
            "format": "hcl2",
            "parsed_at": now_gmt8().isoformat(),
            "resource_count": len(self.resources),
        }

        logger.info(
            f"Parsed {len(self.assets)} assets, {len(self.relationships)} relationships, "
            f"{len(self.trust_boundaries)} trust boundaries"
        )

        return AssetGraph(
            assets=self.assets,
            relationships=self.relationships,
            trust_boundaries=self.trust_boundaries,
            metadata=metadata,
        )

    def _extract_resources(self, resource_block: Dict[str, Any]) -> None:
        """
        Extract resource definitions from a resource block.

        Args:
            resource_block: Parsed resource block from HCL2
        """
        # Resource block structure: {resource_type: {resource_name: {properties}}}
        # HCL2 adds quotes around keys, so we need to strip them
        for resource_type_quoted, resource_instances in resource_block.items():
            resource_type = self._clean_string(resource_type_quoted)

            if isinstance(resource_instances, dict):
                for resource_name_quoted, resource_config in resource_instances.items():
                    resource_name = self._clean_string(resource_name_quoted)
                    resource_id = f"{resource_type}.{resource_name}"

                    # Clean the config recursively
                    cleaned_config = self._clean_config(resource_config)

                    self.resources[resource_id] = {
                        "type": resource_type,
                        "name": resource_name,
                        "config": cleaned_config,
                    }
                    logger.debug(f"Extracted resource: {resource_id}")

    def _build_asset(self, resource_id: str, resource_data: Dict) -> Asset:
        """
        Build an Asset from a Terraform resource.

        Args:
            resource_id: Resource identifier (type.name)
            resource_data: Resource configuration data

        Returns:
            Asset object or None if resource type is not mappable
        """
        resource_type = resource_data["type"]
        resource_name = resource_data["name"]
        config = resource_data["config"]

        # Map resource type to normalized type
        normalized_type, service = aws_type_mapper(resource_type)

        # Extract security-relevant properties
        properties = self._extract_properties(resource_type, config)

        # Infer data sensitivity
        data_sensitivity = self._infer_sensitivity(normalized_type, resource_type)

        # Infer trust boundary
        trust_boundary = self._infer_trust_boundary(properties, normalized_type)

        asset = Asset(
            id=resource_id,
            name=resource_name,
            type=normalized_type,
            cloud="aws",
            service=service,
            properties=properties,
            data_sensitivity=data_sensitivity,
            trust_boundary=trust_boundary,
        )

        return asset

    def _extract_properties(self, resource_type: str, config: Dict) -> Dict:
        """
        Extract security-relevant properties from resource configuration.

        Args:
            resource_type: Terraform resource type
            config: Resource configuration dict

        Returns:
            Dict of security-relevant properties
        """
        properties = {}

        # Internet facing detection
        if "associate_public_ip_address" in config:
            properties["internet_facing"] = bool(config["associate_public_ip_address"])

        # Port extraction
        if "ingress" in config:
            ports = []
            ingress_rules = config["ingress"]
            if isinstance(ingress_rules, list):
                for rule in ingress_rules:
                    if "from_port" in rule:
                        ports.append(rule["from_port"])
            properties["ports"] = ports

        if "port" in config:
            properties["ports"] = [config["port"]]

        # IAM role extraction
        for iam_field in ["iam_instance_profile", "execution_role_arn", "role", "role_arn"]:
            if iam_field in config:
                properties["iam_role"] = self._extract_reference(config[iam_field])

        # VPC/Subnet extraction
        if "vpc_id" in config:
            properties["vpc"] = self._extract_reference(config["vpc_id"])

        if "subnet_id" in config:
            properties["subnet"] = self._extract_reference(config["subnet_id"])
        elif "subnet_ids" in config:
            subnets = config["subnet_ids"]
            if isinstance(subnets, list) and subnets:
                properties["subnet"] = self._extract_reference(subnets[0])

        # Encryption detection
        if "encrypted" in config:
            properties["encryption_at_rest"] = bool(config["encrypted"])

        if "kms_key_id" in config or "kms_key_arn" in config:
            properties["encryption_at_rest"] = True

        if "server_side_encryption_configuration" in config:
            properties["encryption_at_rest"] = True

        # S3 public access detection
        if resource_type == "aws_s3_bucket":
            if "acl" in config:
                acl = config["acl"]
                properties["public"] = acl in ["public-read", "public-read-write"]
            else:
                properties["public"] = False

        # Load balancer scheme
        if "load_balancer_type" in config or resource_type in ["aws_lb", "aws_alb", "aws_elb"]:
            # Check both 'scheme' and 'internal' fields
            scheme = config.get("scheme", "internal")
            internal = config.get("internal", True)

            # If internal is explicitly set to false, it's internet-facing
            if isinstance(internal, bool):
                properties["internet_facing"] = not internal
            else:
                properties["internet_facing"] = scheme == "internet-facing"

        # Security groups
        if "security_groups" in config:
            sgs = config["security_groups"]
            if isinstance(sgs, list):
                properties["security_groups"] = [self._extract_reference(sg) for sg in sgs]

        if "vpc_security_group_ids" in config:
            sgs = config["vpc_security_group_ids"]
            if isinstance(sgs, list):
                properties["security_groups"] = [self._extract_reference(sg) for sg in sgs]

        # Copy other relevant fields
        for field in ["instance_type", "engine", "allocated_storage", "publicly_accessible"]:
            if field in config:
                properties[field] = config[field]

        # Preserve EC2 metadata_options for IMDS signal detection
        if resource_type == "aws_instance" and "metadata_options" in config:
            properties["metadata_options"] = config["metadata_options"]

        # Preserve security group ingress/egress rules for signal detection
        if resource_type == "aws_security_group":
            if "ingress" in config:
                properties["ingress"] = config["ingress"]
            if "egress" in config:
                properties["egress"] = config["egress"]

        # Preserve IAM policy documents for privilege escalation detection
        if resource_type in ["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
            if "policy" in config:
                properties["policy"] = config["policy"]
            if "assume_role_policy" in config:
                properties["assume_role_policy"] = config["assume_role_policy"]
            # Preserve inline policy for role policies
            if "inline_policy" in config:
                properties["inline_policy"] = config["inline_policy"]

        # Preserve CloudTrail event selectors for logging gap detection
        if resource_type == "aws_cloudtrail" and "event_selector" in config:
            properties["event_selector"] = config["event_selector"]

        # Preserve original resource type for signal matching
        properties["resource_type"] = resource_type

        return properties

    def _extract_reference(self, value: Any) -> str:
        """
        Extract resource reference from a Terraform interpolation.

        Args:
            value: Value that may contain a resource reference

        Returns:
            Extracted reference string or original value
        """
        if isinstance(value, str):
            # Pattern: aws_type.name.attribute or ${aws_type.name.attribute}
            pattern = r'\$?\{?([a-z_]+\.[a-z0-9_\-]+)(?:\.[a-z_]+)?\}?'
            match = re.search(pattern, value)
            if match:
                return match.group(1)
            return value
        return str(value)

    def _infer_sensitivity(self, normalized_type: str, resource_type: str) -> str:
        """
        Infer data sensitivity based on resource type.

        Args:
            normalized_type: Normalized type (e.g., "storage.database")
            resource_type: Original Terraform resource type

        Returns:
            Sensitivity level: "high", "medium", or "low"
        """
        # High sensitivity for data storage
        if "storage" in normalized_type or "database" in resource_type:
            return "high"

        # Medium sensitivity for compute
        if "compute" in normalized_type or "lambda" in resource_type:
            return "medium"

        # Low sensitivity for networking and monitoring
        if "network" in normalized_type or "monitoring" in normalized_type:
            return "low"

        return "medium"

    def _infer_trust_boundary(self, properties: Dict, normalized_type: str) -> str:
        """
        Infer trust boundary based on resource properties.

        Args:
            properties: Extracted resource properties
            normalized_type: Normalized resource type

        Returns:
            Trust boundary: "internet", "private", "management", or "vpc-internal"
        """
        # IAM resources are in management plane
        if "identity" in normalized_type:
            return "management"

        # Internet-facing resources
        if properties.get("internet_facing") or properties.get("public"):
            return "internet"

        # Publicly accessible databases (only if explicitly True)
        if properties.get("publicly_accessible") is True:
            return "internet"

        # Resources with explicit subnet are vpc-internal unless proven otherwise
        if properties.get("subnet"):
            return "vpc-internal"

        # Default to private
        return "private"

    def _build_relationships(self) -> None:
        """
        Build relationships between assets by analyzing resource references.

        Identifies dependencies, network access, IAM bindings, and data flows.
        """
        for asset in self.assets:
            resource_id = asset.id
            resource_data = self.resources.get(resource_id)

            if not resource_data:
                continue

            config = resource_data["config"]

            # Scan for references to other resources
            self._find_references(asset, config)

    def _find_references(self, source_asset: Asset, config: Any, path: str = "") -> None:
        """
        Recursively find references to other resources in configuration.

        Args:
            source_asset: Source asset making references
            config: Configuration to scan
            path: Current path in config (for nested structures)
        """
        if isinstance(config, dict):
            for key, value in config.items():
                # Check for IAM role references
                if key in ["iam_instance_profile", "execution_role_arn", "role", "role_arn"]:
                    target_ref = self._extract_reference(value)
                    if self._is_valid_resource_ref(target_ref):
                        self._add_relationship(
                            source_asset.id,
                            target_ref,
                            "iam_binding",
                            {"permission_type": key},
                        )

                # Check for security group references
                elif key in ["security_groups", "vpc_security_group_ids"]:
                    if isinstance(value, list):
                        for sg_ref in value:
                            target_ref = self._extract_reference(sg_ref)
                            if self._is_valid_resource_ref(target_ref):
                                self._add_relationship(
                                    source_asset.id,
                                    target_ref,
                                    "network_access",
                                    {"type": "security_group"},
                                )

                # Check for S3/database references (data flows)
                elif key in ["bucket", "db_instance_identifier", "cluster_identifier"]:
                    target_ref = self._extract_reference(value)
                    if self._is_valid_resource_ref(target_ref):
                        self._add_relationship(
                            source_asset.id,
                            target_ref,
                            "data_flow",
                            {"direction": "outbound"},
                        )

                # Check for VPC/subnet dependencies
                elif key in ["vpc_id", "subnet_id", "subnet_ids"]:
                    refs = value if isinstance(value, list) else [value]
                    for ref in refs:
                        target_ref = self._extract_reference(ref)
                        if self._is_valid_resource_ref(target_ref):
                            self._add_relationship(
                                source_asset.id,
                                target_ref,
                                "depends_on",
                                {"dependency_type": "network"},
                            )

                # Recurse into nested structures
                else:
                    self._find_references(source_asset, value, f"{path}.{key}")

        elif isinstance(config, list):
            for item in config:
                self._find_references(source_asset, item, path)

    def _is_valid_resource_ref(self, ref: str) -> bool:
        """
        Check if a reference points to a valid resource in the graph.

        Args:
            ref: Resource reference string

        Returns:
            True if reference is valid, False otherwise
        """
        if not ref or not isinstance(ref, str):
            return False

        # Check if it matches a known resource
        return ref in self.resources

    def _add_relationship(
        self, source_id: str, target_id: str, rel_type: str, properties: Dict
    ) -> None:
        """
        Add a relationship to the graph.

        Args:
            source_id: Source asset ID
            target_id: Target asset ID
            rel_type: Relationship type
            properties: Relationship properties
        """
        # Avoid duplicate relationships
        for rel in self.relationships:
            if (
                rel.source == source_id
                and rel.target == target_id
                and rel.type == rel_type
            ):
                return

        relationship = Relationship(
            source=source_id,
            target=target_id,
            type=rel_type,
            properties=properties,
        )
        self.relationships.append(relationship)
        logger.debug(f"Added relationship: {source_id} --[{rel_type}]--> {target_id}")

    def _build_trust_boundaries(self) -> None:
        """
        Build trust boundaries by grouping assets based on exposure level.
        """
        # Group assets by trust boundary
        boundary_assets = {
            "internet": [],
            "vpc-internal": [],
            "private": [],
            "management": [],
        }

        for asset in self.assets:
            boundary = asset.trust_boundary
            if boundary in boundary_assets:
                boundary_assets[boundary].append(asset.id)

        # Create TrustBoundary objects for non-empty boundaries
        boundary_configs = {
            "internet": ("Internet Facing", "internet"),
            "vpc-internal": ("VPC Internal", "vpc-internal"),
            "private": ("Private Network", "private"),
            "management": ("Management Plane", "management"),
        }

        for boundary_id, asset_ids in boundary_assets.items():
            if asset_ids:
                name, exposure = boundary_configs[boundary_id]
                trust_boundary = TrustBoundary(
                    id=f"boundary_{boundary_id}",
                    name=name,
                    assets=asset_ids,
                    exposure=exposure,
                )
                self.trust_boundaries.append(trust_boundary)
                logger.debug(
                    f"Created trust boundary: {name} with {len(asset_ids)} assets"
                )
