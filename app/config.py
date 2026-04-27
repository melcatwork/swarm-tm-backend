"""Application configuration using Pydantic Settings."""

from typing import Optional, Dict
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # LLM Provider Configuration
    LLM_PROVIDER: str = "bedrock"

    # AWS Bedrock (bearer token authentication for Anthropic models)
    AWS_BEARER_TOKEN_BEDROCK: Optional[str] = None
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

    # Direct Anthropic API (alternative)
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20240620"

    # Ollama (local LLM, no API key needed)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen3:14b"

    # OpenAI API (alternative - not recommended for threat modeling)
    OPENAI_API_KEY: Optional[str] = None

    # LLM Performance Configuration (model-agnostic)
    LLM_TEMPERATURE: float = 0.5          # Lower = more consistent, higher = more creative (0.0-1.0)
    LLM_MAX_TOKENS: int = 64000           # Maximum tokens per response (extended for Claude 4 models)
    LLM_CONTEXT_WINDOW: int = 32000       # Maximum context window size
    LLM_TIMEOUT_SECONDS: int = 600        # Timeout for LLM operations (10 minutes)
    LLM_RETRY_ATTEMPTS: int = 3           # Number of retry attempts on failure

    # Database
    DATABASE_URL: str = "sqlite:///data/swarm_tm.db"

    # CORS Configuration
    CORS_ORIGINS: Optional[str] = None  # Comma-separated list of allowed origins

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def get_llm_config(self) -> Dict[str, str]:
        """
        Get LLM configuration based on the selected provider.

        Returns:
            Dictionary with 'model', 'provider', and optionally 'base_url' keys
        """
        if self.LLM_PROVIDER == "bedrock":
            return {
                "model": self.BEDROCK_MODEL,
                "provider": "bedrock",
            }
        elif self.LLM_PROVIDER == "ollama":
            return {
                "model": f"ollama/{self.OLLAMA_MODEL}",
                "provider": "ollama",
                "base_url": self.OLLAMA_BASE_URL,
            }
        else:
            return {
                "model": self.ANTHROPIC_MODEL,
                "provider": "anthropic",
            }

    def is_llm_configured(self) -> bool:
        """
        Check if LLM is properly configured.

        Returns:
            True if LLM provider has required credentials set
        """
        if self.LLM_PROVIDER == "bedrock":
            return bool(self.AWS_BEARER_TOKEN_BEDROCK)
        elif self.LLM_PROVIDER == "anthropic":
            return bool(self.ANTHROPIC_API_KEY)
        elif self.LLM_PROVIDER == "ollama":
            # Ollama doesn't need API keys, just check base_url is set
            return bool(self.OLLAMA_BASE_URL)
        return False

    def get_available_models(self) -> Dict[str, list]:
        """
        Get all available models by reading .env file.

        Parses .env file to find all configured models (including commented ones)
        for each provider.

        Returns:
            Dictionary with provider keys and list of model objects
        """
        import os
        import re
        from pathlib import Path

        models_by_provider = {
            "ollama": [],
            "bedrock": [],
            "anthropic": []
        }

        # Find .env file
        env_path = Path(__file__).parent.parent.parent / ".env"

        if not env_path.exists():
            # Fallback to current config values
            if self.LLM_PROVIDER == "ollama":
                models_by_provider["ollama"].append({
                    "name": self.OLLAMA_MODEL,
                    "provider": "ollama",
                    "available": True,
                    "is_default": True
                })
            elif self.LLM_PROVIDER == "bedrock":
                models_by_provider["bedrock"].append({
                    "name": self.BEDROCK_MODEL,
                    "provider": "bedrock",
                    "available": self.is_llm_configured(),
                    "is_default": True
                })
            elif self.LLM_PROVIDER == "anthropic":
                models_by_provider["anthropic"].append({
                    "name": self.ANTHROPIC_MODEL,
                    "provider": "anthropic",
                    "available": self.is_llm_configured(),
                    "is_default": True
                })
            return models_by_provider

        # Parse .env file
        with open(env_path, "r") as f:
            content = f.read()

        # Find Ollama models (including commented)
        ollama_pattern = r'^\s*#?\s*OLLAMA_MODEL\s*=\s*([^\s#]+)'
        for match in re.finditer(ollama_pattern, content, re.MULTILINE):
            model_name = match.group(1).strip().strip('"').strip("'")
            is_active = not match.group(0).strip().startswith("#")

            models_by_provider["ollama"].append({
                "name": model_name,
                "provider": "ollama",
                "available": True if is_active else None,  # None = needs verification
                "is_default": is_active and model_name == self.OLLAMA_MODEL
            })

        # Find Bedrock models
        bedrock_pattern = r'^\s*#?\s*BEDROCK_MODEL\s*=\s*([^\s#]+)'
        for match in re.finditer(bedrock_pattern, content, re.MULTILINE):
            model_name = match.group(1).strip().strip('"').strip("'")
            is_active = not match.group(0).strip().startswith("#")

            models_by_provider["bedrock"].append({
                "name": model_name,
                "provider": "bedrock",
                "available": self.is_llm_configured() if is_active else False,
                "is_default": is_active and model_name == self.BEDROCK_MODEL
            })

        # Find Anthropic models
        anthropic_pattern = r'^\s*#?\s*ANTHROPIC_MODEL\s*=\s*([^\s#]+)'
        for match in re.finditer(anthropic_pattern, content, re.MULTILINE):
            model_name = match.group(1).strip().strip('"').strip("'")
            is_active = not match.group(0).strip().startswith("#")

            models_by_provider["anthropic"].append({
                "name": model_name,
                "provider": "anthropic",
                "available": self.is_llm_configured() if is_active else False,
                "is_default": is_active and model_name == self.ANTHROPIC_MODEL
            })

        # Remove duplicates
        for provider in models_by_provider:
            seen = set()
            unique_models = []
            for model in models_by_provider[provider]:
                if model["name"] not in seen:
                    seen.add(model["name"])
                    unique_models.append(model)
            models_by_provider[provider] = unique_models

        return models_by_provider

    def get_bedrock_anthropic_models(self) -> list:
        """
        Get list of available Anthropic models on AWS Bedrock.

        Returns:
            List of Bedrock Anthropic model configurations (ACTIVE models only)
        """
        return [
            {
                "id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                "name": "Claude Sonnet 4.5 (Cross-Region)",
                "provider": "bedrock",
                "description": "Latest Claude Sonnet 4.5 via inference profile (recommended)",
                "context_window": 200000,
                "max_tokens": 64000
            },
            {
                "id": "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
                "name": "Claude 3.5 Sonnet (Cross-Region)",
                "provider": "bedrock",
                "description": "Claude 3.5 Sonnet via inference profile",
                "context_window": 200000,
                "max_tokens": 8192
            },
            {
                "id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                "name": "Claude 3.5 Sonnet",
                "provider": "bedrock",
                "description": "Claude 3.5 model with improved structured output",
                "context_window": 200000,
                "max_tokens": 8192
            },
            {
                "id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "name": "Claude 3 Sonnet",
                "provider": "bedrock",
                "description": "Balanced Claude 3 model",
                "context_window": 200000,
                "max_tokens": 4096
            },
            {
                "id": "anthropic.claude-3-haiku-20240307-v1:0",
                "name": "Claude 3 Haiku",
                "provider": "bedrock",
                "description": "Fastest Claude 3 model",
                "context_window": 200000,
                "max_tokens": 4096
            }
        ]

    def get_anthropic_api_models(self) -> list:
        """
        Get list of available Anthropic API models (Claude 4.5/4.6).

        Returns:
            List of Anthropic API model configurations
        """
        return [
            {
                "id": "claude-opus-4-6",
                "name": "Claude Opus 4.6",
                "provider": "anthropic",
                "description": "Most powerful Claude model (2025)",
                "context_window": 200000,
                "max_tokens": 64000
            },
            {
                "id": "claude-sonnet-4-6",
                "name": "Claude Sonnet 4.6",
                "provider": "anthropic",
                "description": "Balanced Claude 4 model (2025)",
                "context_window": 200000,
                "max_tokens": 64000
            },
            {
                "id": "claude-haiku-4-5-20251001",
                "name": "Claude Haiku 4.5",
                "provider": "anthropic",
                "description": "Fastest Claude 4 model (2025)",
                "context_window": 200000,
                "max_tokens": 64000
            }
        ]


# Singleton instance
settings = Settings()


def get_settings() -> Settings:
    """
    Get the singleton settings instance.

    Returns:
        Settings instance
    """
    return settings
