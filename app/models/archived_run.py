"""
Models for archived threat modeling runs.

This module provides data structures for storing and retrieving
complete threat modeling run results including metadata, attack paths,
mitigations, and analysis results.
"""

from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class ArchivedRunMetadata(BaseModel):
    """Metadata for an archived threat modeling run."""

    run_id: str = Field(..., description="Unique identifier for the run")
    name: str = Field(..., description="User-editable name for the run")
    created_at: str = Field(..., description="ISO timestamp of creation")
    updated_at: Optional[str] = Field(None, description="ISO timestamp of last update")
    file_name: str = Field(..., description="Original IaC file name")
    file_type: str = Field(..., description="File type (.tf, .yaml, .json)")
    mode: str = Field(..., description="Run mode: full, quick, or single")
    agent_name: Optional[str] = Field(None, description="Agent name if single mode")
    execution_time_seconds: float = Field(..., description="Total execution time")
    paths_count: int = Field(..., description="Number of attack paths found")
    model_used: Optional[str] = Field(None, description="LLM model used")


class ArchivedRun(BaseModel):
    """Complete archived threat modeling run with all data."""

    metadata: ArchivedRunMetadata = Field(..., description="Run metadata")
    result: Dict[str, Any] = Field(..., description="Complete pipeline result")

    class Config:
        json_schema_extra = {
            "example": {
                "metadata": {
                    "run_id": "run_20260412_140530",
                    "name": "TM Swarm Run - ecommerce-platform",
                    "created_at": "2026-04-12T14:05:30Z",
                    "file_name": "ecommerce-platform.tf",
                    "file_type": ".tf",
                    "mode": "quick",
                    "execution_time_seconds": 893.6,
                    "paths_count": 4,
                    "model_used": "qwen3:14b"
                },
                "result": {
                    "status": "ok",
                    "asset_graph": {},
                    "final_paths": [],
                    # ... rest of pipeline result
                }
            }
        }


class ArchivedRunList(BaseModel):
    """List of archived runs with metadata only."""

    runs: List[ArchivedRunMetadata] = Field(default_factory=list)
    total: int = Field(..., description="Total number of archived runs")


class UpdateRunNameRequest(BaseModel):
    """Request to update archived run name."""

    run_id: str = Field(..., description="Run ID to update")
    new_name: str = Field(..., description="New name for the run")


class DeleteRunRequest(BaseModel):
    """Request to delete an archived run."""

    run_id: str = Field(..., description="Run ID to delete")
