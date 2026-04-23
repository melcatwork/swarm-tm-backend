"""LLM model management endpoints.

This module provides REST API endpoints for:
- Listing available LLM models
- Checking model availability
- Getting current LLM configuration
"""

import logging
import requests
from typing import Dict, List, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/llm", tags=["LLM"])


def _get_commented_ollama_models() -> set:
    """
    Parse .env file to identify commented Ollama models.

    Returns:
        Set of model names that are commented (prefixed with #) in .env
    """
    import re
    from pathlib import Path

    commented_models = set()

    # Find .env file (go up from backend/app/routers to project root)
    env_path = Path(__file__).parent.parent.parent.parent / ".env"

    if not env_path.exists():
        logger.warning(f".env file not found at {env_path}")
        return commented_models

    try:
        with open(env_path, "r") as f:
            content = f.read()

        # Find commented Ollama models: lines starting with # that have OLLAMA_MODEL=
        commented_pattern = r'^\s*#\s*OLLAMA_MODEL\s*=\s*([^\s#]+)'
        for match in re.finditer(commented_pattern, content, re.MULTILINE):
            model_name = match.group(1).strip().strip('"').strip("'")
            commented_models.add(model_name)
            logger.debug(f"Found commented model in .env: {model_name}")

    except Exception as e:
        logger.error(f"Error parsing .env for commented models: {e}")

    return commented_models


class ModelInfo(BaseModel):
    """Information about an available model."""

    name: str
    provider: str
    available: bool
    is_default: bool
    is_wip: bool  # True if model is commented in .env (Work In Progress)
    display_name: str
    description: str | None = None


class AvailableModelsResponse(BaseModel):
    """Response with available models."""

    current_provider: str
    current_model: str
    models: List[ModelInfo]


@router.get("/models", response_model=AvailableModelsResponse)
async def get_available_models():
    """
    Get all available LLM models dynamically from local Ollama installation.

    For Ollama provider: queries local Ollama via API to get ALL available models,
    and marks models as WIP (Work In Progress) if they are commented in .env.
    Only uncommented models can be used for threat modeling.

    For Bedrock/Anthropic: uses .env configuration as before.

    Returns:
        AvailableModelsResponse with list of available models
    """
    settings = get_settings()

    # Get models from .env file (for defaults and non-Ollama providers)
    models_by_provider = settings.get_available_models()

    # Parse .env to identify commented Ollama models
    commented_ollama_models = _get_commented_ollama_models()
    logger.info(f"Commented (WIP) models from .env: {commented_ollama_models}")

    # Flatten to list with display names
    all_models = []

    # Process Ollama models - DYNAMICALLY from local Ollama installation
    if settings.LLM_PROVIDER == "ollama":
        # Fetch ALL models from local Ollama (not just .env models)
        available_ollama_models = []
        try:
            response = requests.get(
                f"{settings.OLLAMA_BASE_URL}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                ollama_data = response.json()
                # Extract model names and details
                for model_entry in ollama_data.get("models", []):
                    model_name = model_entry.get("name", "")
                    if model_name:
                        available_ollama_models.append({
                            "name": model_name,
                            "size": model_entry.get("size", 0),
                            "modified_at": model_entry.get("modified_at", "")
                        })
                logger.info(f"Found {len(available_ollama_models)} Ollama models via API")
        except Exception as e:
            logger.warning(f"Could not fetch Ollama models from {settings.OLLAMA_BASE_URL}: {e}")

        # Build model list from actual Ollama installation
        if available_ollama_models:
            # Use ALL models from Ollama, marking commented ones as WIP
            for model_entry in available_ollama_models:
                model_name = model_entry["name"]
                is_default = (model_name == settings.OLLAMA_MODEL)
                is_wip = model_name in commented_ollama_models  # Mark as WIP if commented in .env

                # Format model size
                size_bytes = model_entry["size"]
                if size_bytes == 0:
                    size_str = "size unknown"
                elif size_bytes >= 1024**3:  # >= 1GB
                    size_str = f"{size_bytes / (1024**3):.1f}GB"
                elif size_bytes >= 1024**2:  # >= 1MB
                    size_str = f"{size_bytes / (1024**2):.0f}MB"
                else:  # < 1MB
                    size_str = f"{size_bytes / 1024:.0f}KB"

                # Add WIP suffix to display name if commented in .env
                display_suffix = " - Work In Progress" if is_wip else ""

                all_models.append(ModelInfo(
                    name=model_name,
                    provider="ollama",
                    available=True,
                    is_default=is_default,
                    is_wip=is_wip,
                    display_name=f"{model_name} ({size_str}){display_suffix}",
                    description=f"Local Ollama model - {size_str}" if not is_wip else f"Local Ollama model - {size_str} (WIP - not yet enabled)"
                ))
        else:
            # Fallback to .env models if Ollama API unreachable
            logger.warning("Falling back to .env models (Ollama API unreachable)")
            for model in models_by_provider.get("ollama", []):
                # Check if model is commented in .env (WIP)
                is_wip = model["name"] in commented_ollama_models
                display_suffix = " - Work In Progress" if is_wip else ""

                all_models.append(ModelInfo(
                    name=model["name"],
                    provider="ollama",
                    available=False,
                    is_default=model["is_default"],
                    is_wip=is_wip,
                    display_name=f"{model['name']} (Ollama){display_suffix}",
                    description="Ollama not reachable - check if 'ollama serve' is running" if not is_wip else "Ollama not reachable - model marked as WIP"
                ))

    # Process Bedrock models - Add Anthropic models on Bedrock
    if settings.is_llm_configured() if settings.LLM_PROVIDER == "bedrock" else False:
        # If Bedrock is configured, show all available Anthropic models
        bedrock_models = settings.get_bedrock_anthropic_models()
        for bedrock_model in bedrock_models:
            is_default = (bedrock_model["id"] == settings.BEDROCK_MODEL)
            all_models.append(ModelInfo(
                name=bedrock_model["id"],
                provider="bedrock",
                available=True,
                is_default=is_default,
                is_wip=False,
                display_name=f"{bedrock_model['name']} (AWS Bedrock)",
                description=bedrock_model["description"]
            ))
    else:
        # Fallback to .env models if Bedrock not configured or not the current provider
        for model in models_by_provider.get("bedrock", []):
            all_models.append(ModelInfo(
                name=model["name"],
                provider="bedrock",
                available=False,
                is_default=model["is_default"],
                is_wip=False,
                display_name=f"{model['name']} (AWS Bedrock)",
                description="AWS credentials not configured"
            ))

    # Process Anthropic models - Add Claude 4.5/4.6 models
    if settings.is_llm_configured() if settings.LLM_PROVIDER == "anthropic" else False:
        # If Anthropic API is configured, show all available Claude 4.5/4.6 models
        anthropic_models = settings.get_anthropic_api_models()
        for anthropic_model in anthropic_models:
            is_default = (anthropic_model["id"] == settings.ANTHROPIC_MODEL)
            all_models.append(ModelInfo(
                name=anthropic_model["id"],
                provider="anthropic",
                available=True,
                is_default=is_default,
                is_wip=False,
                display_name=f"{anthropic_model['name']} (Anthropic API)",
                description=anthropic_model["description"]
            ))
    else:
        # Fallback to .env models if Anthropic not configured or not the current provider
        for model in models_by_provider.get("anthropic", []):
            all_models.append(ModelInfo(
                name=model["name"],
                provider="anthropic",
                available=False,
                is_default=model["is_default"],
                is_wip=False,
                display_name=f"{model['name']} (Anthropic API)",
                description="API key not configured"
            ))

    # Sort: available first, then by provider, then by name
    all_models.sort(key=lambda m: (not m.available, m.provider, m.name))

    return AvailableModelsResponse(
        current_provider=settings.LLM_PROVIDER,
        current_model=settings.OLLAMA_MODEL if settings.LLM_PROVIDER == "ollama"
                      else settings.BEDROCK_MODEL if settings.LLM_PROVIDER == "bedrock"
                      else settings.ANTHROPIC_MODEL,
        models=all_models
    )


@router.get("/status")
async def get_llm_status():
    """
    Get current LLM configuration and status.

    Returns:
        Current LLM provider, model, and availability status
    """
    settings = get_settings()

    status = {
        "provider": settings.LLM_PROVIDER,
        "configured": settings.is_llm_configured(),
        "temperature": settings.LLM_TEMPERATURE,
        "max_tokens": settings.LLM_MAX_TOKENS,
    }

    if settings.LLM_PROVIDER == "ollama":
        status["model"] = settings.OLLAMA_MODEL
        status["base_url"] = settings.OLLAMA_BASE_URL

        # Check Ollama availability
        try:
            response = requests.get(
                f"{settings.OLLAMA_BASE_URL}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                ollama_data = response.json()
                available_models = [model.get("name") for model in ollama_data.get("models", [])]
                status["ollama_reachable"] = True
                status["model_available"] = settings.OLLAMA_MODEL in available_models
                status["available_models_count"] = len(available_models)
            else:
                status["ollama_reachable"] = False
                status["model_available"] = False
        except Exception as e:
            status["ollama_reachable"] = False
            status["model_available"] = False
            status["error"] = str(e)

    elif settings.LLM_PROVIDER == "bedrock":
        status["model"] = settings.BEDROCK_MODEL
        status["region"] = settings.AWS_REGION
        status["has_bearer_token"] = bool(settings.AWS_BEARER_TOKEN_BEDROCK)

    elif settings.LLM_PROVIDER == "anthropic":
        status["model"] = settings.ANTHROPIC_MODEL

    return status


class BedrockConfigRequest(BaseModel):
    """Request body for updating Bedrock configuration."""
    aws_bearer_token: str
    aws_region: str = "us-east-1"


@router.post("/bedrock/configure")
async def configure_bedrock(config: BedrockConfigRequest):
    """
    Configure AWS Bedrock bearer token.

    Note: This updates the runtime configuration and persists to .env file.

    Args:
        config: AWS bearer token and region

    Returns:
        Success status and available models
    """
    import os
    from pathlib import Path

    # Update environment variables (runtime only)
    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = config.aws_bearer_token
    os.environ["AWS_REGION"] = config.aws_region
    os.environ["AWS_REGION_NAME"] = config.aws_region  # For compatibility
    os.environ["AWS_DEFAULT_REGION"] = config.aws_region  # For boto3

    # Update .env file for persistence
    env_path = Path(__file__).parent.parent.parent.parent / ".env"

    if env_path.exists():
        try:
            with open(env_path, "r") as f:
                lines = f.readlines()

            # Update or add bearer token and region
            updated_lines = []
            found_keys = set()

            for line in lines:
                if line.strip().startswith("AWS_BEARER_TOKEN_BEDROCK=") or line.strip().startswith("#AWS_BEARER_TOKEN_BEDROCK="):
                    updated_lines.append(f"AWS_BEARER_TOKEN_BEDROCK={config.aws_bearer_token}\n")
                    found_keys.add("AWS_BEARER_TOKEN_BEDROCK")
                elif line.strip().startswith("AWS_REGION=") or line.strip().startswith("#AWS_REGION="):
                    updated_lines.append(f"AWS_REGION={config.aws_region}\n")
                    found_keys.add("AWS_REGION")
                else:
                    updated_lines.append(line)

            # Add missing keys
            if "AWS_BEARER_TOKEN_BEDROCK" not in found_keys:
                updated_lines.append(f"AWS_BEARER_TOKEN_BEDROCK={config.aws_bearer_token}\n")
            if "AWS_REGION" not in found_keys:
                updated_lines.append(f"AWS_REGION={config.aws_region}\n")

            with open(env_path, "w") as f:
                f.writelines(updated_lines)

            logger.info("AWS Bedrock bearer token saved to .env file")

        except Exception as e:
            logger.error(f"Failed to update .env file: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save credentials: {str(e)}")

    # Get updated settings
    settings = get_settings()

    return {
        "status": "success",
        "message": "AWS Bedrock configured successfully",
        "region": config.aws_region,
        "available_models": settings.get_bedrock_anthropic_models()
    }
