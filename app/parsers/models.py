"""Normalized asset graph models for threat modeling.

These models represent cloud infrastructure as a directed graph where nodes are
assets (compute, storage, network resources) and edges are relationships
(network access, IAM bindings, data flows, dependencies).
"""

from datetime import datetime
from typing import Literal, Dict, List, Tuple
from pydantic import BaseModel, Field


class Asset(BaseModel):
    """
    Represents a cloud infrastructure asset.

    Assets are normalized across different IaC formats (Terraform, CloudFormation)
    into consistent types for threat modeling.
    """

    id: str = Field(..., description="Unique identifier for the asset")
    name: str = Field(..., description="Human-readable name")
    type: str = Field(
        ...,
        description=(
            "Normalized asset type (e.g., 'compute.container', 'storage.object', "
            "'network.lb', 'identity.iam_role')"
        ),
    )
    cloud: str = Field(default="aws", description="Cloud provider")
    service: str = Field(
        ...,
        description="Cloud service name (e.g., 'EC2', 'S3', 'Lambda')",
    )
    properties: Dict = Field(
        default_factory=dict,
        description=(
            "Asset-specific properties: internet_facing, ports, iam_role, vpc, subnet, "
            "encryption_at_rest, encryption_in_transit, public, etc."
        ),
    )
    data_sensitivity: Literal["high", "medium", "low"] = Field(
        default="medium",
        description="Sensitivity level of data handled by this asset",
    )
    trust_boundary: str = Field(
        default="private",
        description="Trust boundary this asset belongs to",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "aws_instance.web_server",
                "name": "web-server-prod",
                "type": "compute.vm",
                "cloud": "aws",
                "service": "EC2",
                "properties": {
                    "internet_facing": True,
                    "ports": [80, 443],
                    "vpc": "vpc-12345",
                    "subnet": "subnet-67890",
                    "iam_role": "ec2-web-role",
                    "encryption_at_rest": True,
                },
                "data_sensitivity": "medium",
                "trust_boundary": "dmz",
            }
        }


class Relationship(BaseModel):
    """
    Represents a relationship between two assets.

    Relationships model how assets interact: network connectivity, IAM permissions,
    data flows, and service dependencies.
    """

    source: str = Field(..., description="Source asset ID")
    target: str = Field(..., description="Target asset ID")
    type: Literal["network_access", "iam_binding", "data_flow", "depends_on"] = Field(
        ...,
        description="Type of relationship",
    )
    properties: Dict = Field(
        default_factory=dict,
        description=(
            "Relationship-specific properties: protocol, port, security_group, "
            "encrypted, direction, etc."
        ),
    )

    class Config:
        json_schema_extra = {
            "example": {
                "source": "aws_lb.public_alb",
                "target": "aws_instance.web_server",
                "type": "network_access",
                "properties": {
                    "protocol": "https",
                    "port": 443,
                    "security_group": "sg-web",
                    "encrypted": True,
                },
            }
        }


class TrustBoundary(BaseModel):
    """
    Represents a trust boundary grouping related assets.

    Trust boundaries help identify security perimeters and potential attack paths
    across different security zones.
    """

    id: str = Field(..., description="Unique identifier for the boundary")
    name: str = Field(..., description="Human-readable name")
    assets: List[str] = Field(
        default_factory=list,
        description="List of asset IDs in this boundary",
    )
    exposure: Literal["internet", "vpc-internal", "private", "management"] = Field(
        ...,
        description="Exposure level of this boundary",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "boundary_dmz",
                "name": "DMZ - Internet Facing",
                "assets": ["aws_lb.public_alb", "aws_cloudfront.cdn"],
                "exposure": "internet",
            }
        }


class AssetGraph(BaseModel):
    """
    Container for a complete infrastructure asset graph.

    Represents the entire infrastructure topology with assets, their relationships,
    and trust boundaries for threat modeling analysis.
    """

    assets: List[Asset] = Field(
        default_factory=list,
        description="List of all assets in the infrastructure",
    )
    relationships: List[Relationship] = Field(
        default_factory=list,
        description="List of all relationships between assets",
    )
    trust_boundaries: List[TrustBoundary] = Field(
        default_factory=list,
        description="List of trust boundaries grouping assets",
    )
    metadata: Dict = Field(
        default_factory=dict,
        description=(
            "Metadata about the graph: source_file, format, parsed_at, "
            "resource_count, etc."
        ),
    )

    class Config:
        json_schema_extra = {
            "example": {
                "assets": [
                    {
                        "id": "aws_instance.web",
                        "name": "web-server",
                        "type": "compute.vm",
                        "cloud": "aws",
                        "service": "EC2",
                        "properties": {"internet_facing": True},
                        "data_sensitivity": "medium",
                        "trust_boundary": "dmz",
                    }
                ],
                "relationships": [
                    {
                        "source": "aws_lb.alb",
                        "target": "aws_instance.web",
                        "type": "network_access",
                        "properties": {"port": 443, "encrypted": True},
                    }
                ],
                "trust_boundaries": [
                    {
                        "id": "dmz",
                        "name": "DMZ",
                        "assets": ["aws_lb.alb", "aws_instance.web"],
                        "exposure": "internet",
                    }
                ],
                "metadata": {
                    "source_file": "main.tf",
                    "format": "terraform",
                    "parsed_at": "2026-04-09T12:00:00Z",
                    "resource_count": 15,
                },
            }
        }


# Type mapping helpers

# Terraform resource type to (normalized_type, service_name) mapping
TERRAFORM_TYPE_MAP = {
    # Compute
    "aws_instance": ("compute.vm", "EC2"),
    "aws_ecs_service": ("compute.container", "ECS"),
    "aws_ecs_task_definition": ("compute.container", "ECS"),
    "aws_lambda_function": ("compute.serverless", "Lambda"),
    "aws_transfer_server": ("compute.transfer", "Transfer Family"),
    # Storage
    "aws_s3_bucket": ("storage.object", "S3"),
    "aws_rds_instance": ("storage.database", "RDS"),
    "aws_rds_cluster": ("storage.database", "RDS"),
    "aws_dynamodb_table": ("storage.database", "DynamoDB"),
    "aws_efs_file_system": ("storage.filesystem", "EFS"),
    "aws_fsx_windows_file_system": ("storage.filesystem", "FSx"),
    "aws_fsx_lustre_file_system": ("storage.filesystem", "FSx"),
    # Network
    "aws_vpc": ("network.vpc", "VPC"),
    "aws_subnet": ("network.subnet", "VPC"),
    "aws_security_group": ("network.security_group", "VPC"),
    "aws_network_acl": ("network.acl", "VPC"),
    "aws_route_table": ("network.route_table", "VPC"),
    "aws_internet_gateway": ("network.gateway", "VPC"),
    "aws_nat_gateway": ("network.gateway", "VPC"),
    "aws_lb": ("network.lb", "ALB"),
    "aws_alb": ("network.lb", "ALB"),
    "aws_elb": ("network.lb", "ELB"),
    "aws_cloudfront_distribution": ("network.cdn", "CloudFront"),
    "aws_api_gateway_rest_api": ("network.gateway", "API-Gateway"),
    "aws_api_gateway_v2_api": ("network.gateway", "API-Gateway"),
    # Identity & Access
    "aws_iam_role": ("identity.iam_role", "IAM"),
    "aws_iam_policy": ("identity.iam_policy", "IAM"),
    "aws_iam_user": ("identity.iam_user", "IAM"),
    "aws_iam_group": ("identity.iam_group", "IAM"),
    # Security
    "aws_kms_key": ("security.kms_key", "KMS"),
    "aws_kms_alias": ("security.kms_alias", "KMS"),
    "aws_secrets_manager_secret": ("security.secret", "Secrets Manager"),
    "aws_ssm_parameter": ("security.parameter", "SSM"),
    # Messaging
    "aws_sqs_queue": ("messaging.queue", "SQS"),
    "aws_sns_topic": ("messaging.topic", "SNS"),
    "aws_kinesis_stream": ("messaging.stream", "Kinesis"),
    # Monitoring
    "aws_cloudwatch_log_group": ("monitoring.logs", "CloudWatch"),
    "aws_cloudwatch_metric_alarm": ("monitoring.alarm", "CloudWatch"),
}

# CloudFormation resource type to (normalized_type, service_name) mapping
CLOUDFORMATION_TYPE_MAP = {
    # Compute
    "AWS::EC2::Instance": ("compute.vm", "EC2"),
    "AWS::ECS::Service": ("compute.container", "ECS"),
    "AWS::ECS::TaskDefinition": ("compute.container", "ECS"),
    "AWS::Lambda::Function": ("compute.serverless", "Lambda"),
    "AWS::Transfer::Server": ("compute.transfer", "Transfer Family"),
    # Storage
    "AWS::S3::Bucket": ("storage.object", "S3"),
    "AWS::RDS::DBInstance": ("storage.database", "RDS"),
    "AWS::RDS::DBCluster": ("storage.database", "RDS"),
    "AWS::DynamoDB::Table": ("storage.database", "DynamoDB"),
    "AWS::EFS::FileSystem": ("storage.filesystem", "EFS"),
    "AWS::FSx::FileSystem": ("storage.filesystem", "FSx"),
    # Network
    "AWS::EC2::VPC": ("network.vpc", "VPC"),
    "AWS::EC2::Subnet": ("network.subnet", "VPC"),
    "AWS::EC2::SecurityGroup": ("network.security_group", "VPC"),
    "AWS::EC2::NetworkAcl": ("network.acl", "VPC"),
    "AWS::EC2::RouteTable": ("network.route_table", "VPC"),
    "AWS::EC2::InternetGateway": ("network.gateway", "VPC"),
    "AWS::EC2::NatGateway": ("network.gateway", "VPC"),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": ("network.lb", "ALB"),
    "AWS::ElasticLoadBalancing::LoadBalancer": ("network.lb", "ELB"),
    "AWS::CloudFront::Distribution": ("network.cdn", "CloudFront"),
    "AWS::ApiGateway::RestApi": ("network.gateway", "API-Gateway"),
    "AWS::ApiGatewayV2::Api": ("network.gateway", "API-Gateway"),
    # Identity & Access
    "AWS::IAM::Role": ("identity.iam_role", "IAM"),
    "AWS::IAM::Policy": ("identity.iam_policy", "IAM"),
    "AWS::IAM::User": ("identity.iam_user", "IAM"),
    "AWS::IAM::Group": ("identity.iam_group", "IAM"),
    # Security
    "AWS::KMS::Key": ("security.kms_key", "KMS"),
    "AWS::KMS::Alias": ("security.kms_alias", "KMS"),
    "AWS::SecretsManager::Secret": ("security.secret", "Secrets Manager"),
    "AWS::SSM::Parameter": ("security.parameter", "SSM"),
    # Messaging
    "AWS::SQS::Queue": ("messaging.queue", "SQS"),
    "AWS::SNS::Topic": ("messaging.topic", "SNS"),
    "AWS::Kinesis::Stream": ("messaging.stream", "Kinesis"),
    # Monitoring
    "AWS::Logs::LogGroup": ("monitoring.logs", "CloudWatch"),
    "AWS::CloudWatch::Alarm": ("monitoring.alarm", "CloudWatch"),
}


def aws_type_mapper(resource_type: str) -> Tuple[str, str]:
    """
    Map Terraform AWS resource type to normalized (type, service) tuple.

    Args:
        resource_type: Terraform resource type (e.g., "aws_instance")

    Returns:
        Tuple of (normalized_type, service_name)
        Examples: ("compute.vm", "EC2"), ("storage.object", "S3")

    Examples:
        >>> aws_type_mapper("aws_instance")
        ("compute.vm", "EC2")
        >>> aws_type_mapper("aws_s3_bucket")
        ("storage.object", "S3")
        >>> aws_type_mapper("aws_unknown_resource")
        ("other.unknown", "aws_unknown_resource")
    """
    return TERRAFORM_TYPE_MAP.get(
        resource_type,
        ("other.unknown", resource_type),
    )


def cfn_type_mapper(resource_type: str) -> Tuple[str, str]:
    """
    Map CloudFormation AWS resource type to normalized (type, service) tuple.

    Args:
        resource_type: CloudFormation resource type (e.g., "AWS::EC2::Instance")

    Returns:
        Tuple of (normalized_type, service_name)
        Examples: ("compute.vm", "EC2"), ("storage.object", "S3")

    Examples:
        >>> cfn_type_mapper("AWS::EC2::Instance")
        ("compute.vm", "EC2")
        >>> cfn_type_mapper("AWS::S3::Bucket")
        ("storage.object", "S3")
        >>> cfn_type_mapper("AWS::Unknown::Resource")
        ("other.unknown", "AWS::Unknown::Resource")
    """
    return CLOUDFORMATION_TYPE_MAP.get(
        resource_type,
        ("other.unknown", resource_type),
    )
