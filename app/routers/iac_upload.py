"""IaC file upload and parsing endpoints."""

import json
import logging
from typing import List

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from app.parsers import TerraformParser, CloudFormationParser, AssetGraph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/iac", tags=["IaC Parsing"])


class ValidationResult(BaseModel):
    """Result of IaC file validation."""

    valid: bool
    format: str  # "terraform" or "cloudformation"
    resource_count: int
    asset_types: List[str]


class SupportedFormat(BaseModel):
    """Supported IaC format."""

    name: str
    extensions: List[str]


class SupportedFormatsResponse(BaseModel):
    """List of supported formats."""

    formats: List[SupportedFormat]


@router.post("/upload", response_model=AssetGraph)
async def upload_iac_file(file: UploadFile = File(...)) -> AssetGraph:
    """
    Upload and parse an Infrastructure-as-Code file.

    Supports:
    - Terraform (.tf files)
    - CloudFormation (.yaml, .yml, .json files)

    Returns the parsed AssetGraph with assets, relationships, and trust boundaries.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Get file extension
    filename_lower = file.filename.lower()

    try:
        # Read file content
        content = await file.read()
        content_str = content.decode("utf-8")

        # Detect file type and parse
        if filename_lower.endswith(".tf"):
            # Terraform file
            logger.info(f"Parsing Terraform file: {file.filename}")
            parser = TerraformParser()
            asset_graph = parser.parse(content_str)

        elif filename_lower.endswith((".yaml", ".yml", ".json")):
            # Could be CloudFormation
            extension = "yaml" if filename_lower.endswith((".yaml", ".yml")) else "json"

            # For JSON files, check if it's CloudFormation
            if extension == "json":
                try:
                    parsed_json = json.loads(content_str)
                    if not isinstance(parsed_json, dict) or "Resources" not in parsed_json:
                        raise HTTPException(
                            status_code=422,
                            detail="JSON file does not appear to be a CloudFormation template (missing 'Resources' key)",
                        )
                except json.JSONDecodeError as e:
                    raise HTTPException(status_code=422, detail=f"Invalid JSON: {str(e)}")

            logger.info(f"Parsing CloudFormation {extension.upper()} file: {file.filename}")
            parser = CloudFormationParser()
            asset_graph = parser.parse(content_str, file_extension=extension)

        else:
            raise HTTPException(
                status_code=422,
                detail="Unsupported file format. Supported extensions: .tf, .yaml, .yml, .json",
            )

        logger.info(
            f"Successfully parsed {file.filename}: "
            f"{len(asset_graph.assets)} assets, "
            f"{len(asset_graph.relationships)} relationships"
        )

        return asset_graph

    except HTTPException:
        raise
    except ValueError as e:
        # Parser validation errors
        logger.error(f"Parse error for {file.filename}: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error parsing {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse file: {str(e)}")


@router.post("/validate", response_model=ValidationResult)
async def validate_iac_file(file: UploadFile = File(...)) -> ValidationResult:
    """
    Validate an Infrastructure-as-Code file without returning the full graph.

    Returns validation status and metadata about the parsed file.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    filename_lower = file.filename.lower()

    try:
        # Read file content
        content = await file.read()
        content_str = content.decode("utf-8")

        # Detect file type and parse
        if filename_lower.endswith(".tf"):
            # Terraform file
            parser = TerraformParser()
            asset_graph = parser.parse(content_str)
            format_name = "terraform"

        elif filename_lower.endswith((".yaml", ".yml", ".json")):
            # CloudFormation
            extension = "yaml" if filename_lower.endswith((".yaml", ".yml")) else "json"

            # For JSON files, check if it's CloudFormation
            if extension == "json":
                try:
                    parsed_json = json.loads(content_str)
                    if not isinstance(parsed_json, dict) or "Resources" not in parsed_json:
                        raise HTTPException(
                            status_code=422,
                            detail="JSON file does not appear to be a CloudFormation template",
                        )
                except json.JSONDecodeError as e:
                    raise HTTPException(status_code=422, detail=f"Invalid JSON: {str(e)}")

            parser = CloudFormationParser()
            asset_graph = parser.parse(content_str, file_extension=extension)
            format_name = "cloudformation"

        else:
            raise HTTPException(
                status_code=422,
                detail="Unsupported file format. Supported extensions: .tf, .yaml, .yml, .json",
            )

        # Extract unique asset types
        asset_types = sorted(list(set(asset.type for asset in asset_graph.assets)))

        logger.info(
            f"Validated {file.filename}: {format_name}, "
            f"{asset_graph.metadata.get('resource_count', len(asset_graph.assets))} resources"
        )

        return ValidationResult(
            valid=True,
            format=format_name,
            resource_count=asset_graph.metadata.get("resource_count", len(asset_graph.assets)),
            asset_types=asset_types,
        )

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error for {file.filename}: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error validating {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/supported", response_model=SupportedFormatsResponse)
async def get_supported_formats() -> SupportedFormatsResponse:
    """
    Get list of supported Infrastructure-as-Code formats.
    """
    return SupportedFormatsResponse(
        formats=[
            SupportedFormat(name="Terraform", extensions=[".tf"]),
            SupportedFormat(name="AWS CloudFormation", extensions=[".yaml", ".yml", ".json"]),
        ]
    )
