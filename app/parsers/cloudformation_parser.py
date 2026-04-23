"""CloudFormation template parser for extracting infrastructure assets and relationships."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional

import yaml

from app.utils.timezone import now_gmt8
from .models import (
    Asset,
    Relationship,
    TrustBoundary,
    AssetGraph,
    cfn_type_mapper,
)

logger = logging.getLogger(__name__)


# Custom YAML constructors for CloudFormation intrinsic functions
def _ref_constructor(loader, node):
    """Handle !Ref tag."""
    return {"Ref": loader.construct_scalar(node)}


def _getatt_constructor(loader, node):
    """Handle !GetAtt tag."""
    if isinstance(node, yaml.ScalarNode):
        # Simple form: !GetAtt LogicalName.AttributeName
        value = loader.construct_scalar(node)
        parts = value.split(".", 1)
        return {"Fn::GetAtt": parts}
    else:
        # List form: !GetAtt [LogicalName, AttributeName]
        return {"Fn::GetAtt": loader.construct_sequence(node)}


def _sub_constructor(loader, node):
    """Handle !Sub tag."""
    if isinstance(node, yaml.ScalarNode):
        return {"Fn::Sub": loader.construct_scalar(node)}
    else:
        return {"Fn::Sub": loader.construct_sequence(node)}


def _join_constructor(loader, node):
    """Handle !Join tag."""
    return {"Fn::Join": loader.construct_sequence(node)}


def _select_constructor(loader, node):
    """Handle !Select tag."""
    return {"Fn::Select": loader.construct_sequence(node)}


def _getazs_constructor(loader, node):
    """Handle !GetAZs tag."""
    return {"Fn::GetAZs": loader.construct_scalar(node)}


def _base64_constructor(loader, node):
    """Handle !Base64 tag."""
    return {"Fn::Base64": loader.construct_scalar(node)}


def _if_constructor(loader, node):
    """Handle !If tag."""
    return {"Fn::If": loader.construct_sequence(node)}


def _equals_constructor(loader, node):
    """Handle !Equals tag."""
    return {"Fn::Equals": loader.construct_sequence(node)}


def _not_constructor(loader, node):
    """Handle !Not tag."""
    return {"Fn::Not": loader.construct_sequence(node)}


def _and_constructor(loader, node):
    """Handle !And tag."""
    return {"Fn::And": loader.construct_sequence(node)}


def _or_constructor(loader, node):
    """Handle !Or tag."""
    return {"Fn::Or": loader.construct_sequence(node)}


# Register custom YAML constructors
yaml.SafeLoader.add_constructor("!Ref", _ref_constructor)
yaml.SafeLoader.add_constructor("!GetAtt", _getatt_constructor)
yaml.SafeLoader.add_constructor("!Sub", _sub_constructor)
yaml.SafeLoader.add_constructor("!Join", _join_constructor)
yaml.SafeLoader.add_constructor("!Select", _select_constructor)
yaml.SafeLoader.add_constructor("!GetAZs", _getazs_constructor)
yaml.SafeLoader.add_constructor("!Base64", _base64_constructor)
yaml.SafeLoader.add_constructor("!If", _if_constructor)
yaml.SafeLoader.add_constructor("!Equals", _equals_constructor)
yaml.SafeLoader.add_constructor("!Not", _not_constructor)
yaml.SafeLoader.add_constructor("!And", _and_constructor)
yaml.SafeLoader.add_constructor("!Or", _or_constructor)


class CloudFormationParser:
    """
    Parser for CloudFormation templates (YAML and JSON).

    Extracts infrastructure assets, relationships, and trust boundaries
    from CloudFormation templates for threat modeling analysis.
    """

    def __init__(self):
        """Initialize the CloudFormation parser."""
        self.resources = {}  # logical_name -> resource_data
        self.parameters = {}  # parameter_name -> default_value
        self.assets = []
        self.relationships = []
        self.trust_boundaries = []

    def parse(self, file_content: str, file_extension: str = "yaml") -> AssetGraph:
        """
        Parse CloudFormation template into an AssetGraph.

        Args:
            file_content: String content of a CloudFormation template
            file_extension: File format ("yaml", "yml", or "json")

        Returns:
            AssetGraph with extracted assets, relationships, and trust boundaries

        Raises:
            ValueError: If template is invalid or missing Resources key
        """
        try:
            # Parse template based on format
            if file_extension.lower() in ["yaml", "yml"]:
                template = yaml.safe_load(file_content)
                logger.info("Successfully parsed CloudFormation YAML template")
            elif file_extension.lower() == "json":
                template = json.loads(file_content)
                logger.info("Successfully parsed CloudFormation JSON template")
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")

        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML: {e}")
            raise ValueError(f"Invalid YAML syntax: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            raise ValueError(f"Invalid JSON syntax: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to parse template: {e}")
            raise ValueError(f"Template parsing error: {str(e)}")

        # Validate template structure
        if not isinstance(template, dict):
            raise ValueError("CloudFormation template must be a dictionary")

        if "Resources" not in template:
            raise ValueError("CloudFormation template missing required 'Resources' key")

        # Reset parser state
        self.resources = {}
        self.parameters = {}
        self.assets = []
        self.relationships = []
        self.trust_boundaries = []

        # Extract parameters with defaults
        if "Parameters" in template:
            self._extract_parameters(template["Parameters"])

        # Extract resources
        resources_dict = template["Resources"]
        logger.info(f"Found {len(resources_dict)} resources")

        # First pass: extract all resources and build catalog
        for logical_name, resource_def in resources_dict.items():
            self._extract_resource(logical_name, resource_def)

        # Second pass: build assets from resources
        for logical_name, resource_data in self.resources.items():
            asset = self._build_asset(logical_name, resource_data)
            if asset:
                self.assets.append(asset)

        # Third pass: identify relationships from Ref and other references
        self._build_relationships()

        # Fourth pass: group into trust boundaries
        self._build_trust_boundaries()

        # Build metadata
        metadata = {
            "source_file": "cloudformation",
            "format": file_extension,
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

    def _extract_parameters(self, parameters: Dict[str, Any]) -> None:
        """
        Extract parameter default values for reference resolution.

        Args:
            parameters: Parameters section of CloudFormation template
        """
        for param_name, param_def in parameters.items():
            if isinstance(param_def, dict) and "Default" in param_def:
                self.parameters[param_name] = param_def["Default"]
                logger.debug(f"Extracted parameter: {param_name} = {param_def['Default']}")

    def _extract_resource(self, logical_name: str, resource_def: Dict[str, Any]) -> None:
        """
        Extract a resource definition.

        Args:
            logical_name: Logical resource name
            resource_def: Resource definition dict
        """
        if not isinstance(resource_def, dict) or "Type" not in resource_def:
            logger.warning(f"Invalid resource definition for {logical_name}")
            return

        resource_type = resource_def["Type"]
        properties = resource_def.get("Properties", {})

        self.resources[logical_name] = {
            "type": resource_type,
            "name": logical_name,
            "properties": properties,
        }
        logger.debug(f"Extracted resource: {logical_name} ({resource_type})")

    def _build_asset(self, logical_name: str, resource_data: Dict) -> Optional[Asset]:
        """
        Build an Asset from a CloudFormation resource.

        Args:
            logical_name: Logical resource name
            resource_data: Resource data dict

        Returns:
            Asset object or None if resource type is not mappable
        """
        resource_type = resource_data["type"]
        properties = resource_data["properties"]

        # Map resource type to normalized type
        normalized_type, service = cfn_type_mapper(resource_type)

        # Extract security-relevant properties
        extracted_props = self._extract_properties(resource_type, properties)

        # Infer data sensitivity
        data_sensitivity = self._infer_sensitivity(normalized_type, resource_type)

        # Infer trust boundary
        trust_boundary = self._infer_trust_boundary(extracted_props, normalized_type)

        asset = Asset(
            id=f"cfn-{logical_name}",
            name=logical_name,
            type=normalized_type,
            cloud="aws",
            service=service,
            properties=extracted_props,
            data_sensitivity=data_sensitivity,
            trust_boundary=trust_boundary,
        )

        return asset

    def _extract_properties(self, resource_type: str, properties: Dict) -> Dict:
        """
        Extract security-relevant properties from CloudFormation resource.

        Args:
            resource_type: CloudFormation resource type
            properties: Resource properties dict

        Returns:
            Dict of security-relevant properties
        """
        extracted = {}

        # Internet facing detection (CloudFormation uses PascalCase)
        if "AssociatePublicIpAddress" in properties:
            extracted["internet_facing"] = bool(
                self._resolve_value(properties["AssociatePublicIpAddress"])
            )

        # Port extraction from SecurityGroupIngress
        if "SecurityGroupIngress" in properties:
            ports = []
            ingress_rules = properties["SecurityGroupIngress"]
            if isinstance(ingress_rules, list):
                for rule in ingress_rules:
                    if isinstance(rule, dict) and "FromPort" in rule:
                        ports.append(rule["FromPort"])
            extracted["ports"] = ports

        # IAM role extraction
        for iam_field in ["IamInstanceProfile", "ExecutionRoleArn", "Role", "RoleArn"]:
            if iam_field in properties:
                extracted["iam_role"] = self._extract_reference(properties[iam_field])

        # VPC/Subnet extraction
        if "VpcId" in properties:
            extracted["vpc"] = self._extract_reference(properties["VpcId"])

        if "SubnetId" in properties:
            extracted["subnet"] = self._extract_reference(properties["SubnetId"])
        elif "SubnetIds" in properties:
            subnets = properties["SubnetIds"]
            if isinstance(subnets, list) and subnets:
                extracted["subnet"] = self._extract_reference(subnets[0])
        elif "Subnets" in properties:
            subnets = properties["Subnets"]
            if isinstance(subnets, list) and subnets:
                extracted["subnet"] = self._extract_reference(subnets[0])

        # Encryption detection
        if "Encrypted" in properties:
            extracted["encryption_at_rest"] = bool(
                self._resolve_value(properties["Encrypted"])
            )

        if "KmsKeyId" in properties or "KmsKeyArn" in properties:
            extracted["encryption_at_rest"] = True

        if "BucketEncryption" in properties:
            extracted["encryption_at_rest"] = True

        # S3 public access detection
        if resource_type == "AWS::S3::Bucket":
            # Check for ACL
            if "AccessControl" in properties:
                acl = properties["AccessControl"]
                extracted["public"] = acl in ["PublicRead", "PublicReadWrite"]
            # Check for PublicAccessBlockConfiguration
            elif "PublicAccessBlockConfiguration" in properties:
                pac = properties["PublicAccessBlockConfiguration"]
                if isinstance(pac, dict):
                    # If all blocks are true, it's not public
                    all_blocked = all(
                        pac.get(key, False)
                        for key in [
                            "BlockPublicAcls",
                            "BlockPublicPolicy",
                            "IgnorePublicAcls",
                            "RestrictPublicBuckets",
                        ]
                    )
                    extracted["public"] = not all_blocked
            else:
                extracted["public"] = False

        # Load balancer scheme
        if resource_type in [
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "AWS::ElasticLoadBalancing::LoadBalancer",
        ]:
            scheme = properties.get("Scheme", "internal")
            extracted["internet_facing"] = scheme == "internet-facing"

        # Security groups
        if "SecurityGroups" in properties:
            sgs = properties["SecurityGroups"]
            if isinstance(sgs, list):
                extracted["security_groups"] = [
                    self._extract_reference(sg) for sg in sgs
                ]

        if "VpcSecurityGroupIds" in properties:
            sgs = properties["VpcSecurityGroupIds"]
            if isinstance(sgs, list):
                extracted["security_groups"] = [
                    self._extract_reference(sg) for sg in sgs
                ]

        if "SecurityGroupIds" in properties:
            sgs = properties["SecurityGroupIds"]
            if isinstance(sgs, list):
                extracted["security_groups"] = [
                    self._extract_reference(sg) for sg in sgs
                ]

        # Copy other relevant fields
        for field in [
            "InstanceType",
            "Engine",
            "AllocatedStorage",
            "PubliclyAccessible",
        ]:
            if field in properties:
                extracted[field] = self._resolve_value(properties[field])

        return extracted

    def _resolve_value(self, value: Any) -> Any:
        """
        Resolve a CloudFormation value (may contain Ref or other functions).

        Args:
            value: Value to resolve

        Returns:
            Resolved value (reference string, parameter value, or original)
        """
        if isinstance(value, dict):
            # Handle Ref
            if "Ref" in value:
                ref_name = value["Ref"]
                # Check if it's a parameter
                if ref_name in self.parameters:
                    return self.parameters[ref_name]
                # Return as reference
                return ref_name

            # Handle Fn::GetAtt
            if "Fn::GetAtt" in value:
                get_att = value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    return get_att[0]  # Return resource name

            # Handle Fn::Sub (basic - just return the template string)
            if "Fn::Sub" in value:
                sub_value = value["Fn::Sub"]
                if isinstance(sub_value, str):
                    return sub_value
                elif isinstance(sub_value, list) and len(sub_value) > 0:
                    return sub_value[0]

        return value

    def _extract_reference(self, value: Any) -> str:
        """
        Extract resource reference from a CloudFormation value.

        Args:
            value: Value that may contain a reference

        Returns:
            Extracted reference string or original value as string
        """
        if isinstance(value, dict):
            # Handle Ref
            if "Ref" in value:
                return value["Ref"]

            # Handle Fn::GetAtt
            if "Fn::GetAtt" in value:
                get_att = value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    return get_att[0]

        if isinstance(value, str):
            return value

        return str(value)

    def _infer_sensitivity(self, normalized_type: str, resource_type: str) -> str:
        """
        Infer data sensitivity based on resource type.

        Args:
            normalized_type: Normalized type
            resource_type: CloudFormation resource type

        Returns:
            Sensitivity level: "high", "medium", or "low"
        """
        # High sensitivity for data storage
        if "storage" in normalized_type or "DB" in resource_type or "Table" in resource_type:
            return "high"

        # Medium sensitivity for compute
        if "compute" in normalized_type or "Lambda" in resource_type:
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

        # Publicly accessible databases
        if properties.get("PubliclyAccessible") is True:
            return "internet"

        # Resources with explicit subnet are vpc-internal
        if properties.get("subnet"):
            return "vpc-internal"

        # Default to private
        return "private"

    def _build_relationships(self) -> None:
        """
        Build relationships between assets by analyzing references.

        Identifies dependencies, network access, IAM bindings, and data flows
        from Ref and Fn::GetAtt intrinsic functions.
        """
        for asset in self.assets:
            # Get the logical name from the asset ID (remove "cfn-" prefix)
            logical_name = asset.id.replace("cfn-", "")
            resource_data = self.resources.get(logical_name)

            if not resource_data:
                continue

            properties = resource_data["properties"]

            # Scan for references in properties
            self._find_references(asset, properties)

    def _find_references(
        self, source_asset: Asset, properties: Any, path: str = ""
    ) -> None:
        """
        Recursively find references to other resources in properties.

        Args:
            source_asset: Source asset making references
            properties: Properties to scan
            path: Current path in properties (for nested structures)
        """
        if isinstance(properties, dict):
            # Check for Ref
            if "Ref" in properties:
                target_ref = properties["Ref"]
                if self._is_valid_resource_ref(target_ref):
                    self._add_relationship_by_context(
                        source_asset, target_ref, path
                    )

            # Check for Fn::GetAtt
            elif "Fn::GetAtt" in properties:
                get_att = properties["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    target_ref = get_att[0]
                    if self._is_valid_resource_ref(target_ref):
                        self._add_relationship_by_context(
                            source_asset, target_ref, path
                        )

            # Recurse into nested structures
            else:
                for key, value in properties.items():
                    self._find_references(source_asset, value, f"{path}.{key}")

        elif isinstance(properties, list):
            for item in properties:
                self._find_references(source_asset, item, path)

    def _add_relationship_by_context(
        self, source_asset: Asset, target_ref: str, context_path: str
    ) -> None:
        """
        Add a relationship based on the context of the reference.

        Args:
            source_asset: Source asset
            target_ref: Target resource logical name
            context_path: Path context for determining relationship type
        """
        # Determine relationship type based on context
        rel_type = "depends_on"
        rel_props = {}

        context_lower = context_path.lower()

        # IAM role references
        if any(
            keyword in context_lower
            for keyword in ["role", "executionrole", "iaminstanceprofile"]
        ):
            rel_type = "iam_binding"
            rel_props = {"context": "iam_role"}

        # Security group references
        elif "securitygroup" in context_lower:
            rel_type = "network_access"
            rel_props = {"type": "security_group"}

        # S3 bucket or database references (data flows)
        elif any(keyword in context_lower for keyword in ["bucket", "table", "database"]):
            rel_type = "data_flow"
            rel_props = {"direction": "outbound"}

        # VPC/subnet dependencies
        elif any(keyword in context_lower for keyword in ["vpc", "subnet"]):
            rel_props = {"dependency_type": "network"}

        self._add_relationship(
            source_asset.id,
            f"cfn-{target_ref}",
            rel_type,
            rel_props,
        )

    def _is_valid_resource_ref(self, ref: str) -> bool:
        """
        Check if a reference points to a valid resource in the template.

        Args:
            ref: Resource reference (logical name)

        Returns:
            True if reference is valid, False otherwise
        """
        if not ref or not isinstance(ref, str):
            return False

        # Exclude AWS pseudo parameters
        if ref in [
            "AWS::AccountId",
            "AWS::Region",
            "AWS::StackName",
            "AWS::StackId",
            "AWS::NotificationARNs",
            "AWS::Partition",
            "AWS::URLSuffix",
        ]:
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
