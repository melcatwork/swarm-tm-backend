"""
API endpoints for archived threat modeling runs.

Provides REST API for saving, retrieving, updating, and deleting
archived threat modeling results.
"""

import logging
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.models.archived_run import (
    ArchivedRun,
    ArchivedRunMetadata,
    ArchivedRunList,
    UpdateRunNameRequest,
    DeleteRunRequest,
)
from app.services.archive_service import get_archive_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/archive", tags=["Archive"])


class SaveRunRequest(BaseModel):
    """Request to save an archived run."""

    pipeline_result: Dict[str, Any] = Field(..., description="Complete pipeline result")
    file_name: str = Field(..., description="Original IaC file name")
    mode: str = Field(..., description="Run mode: full, quick, single, or stigmergic")
    agent_name: str | None = Field(None, description="Agent name if single mode")
    custom_name: str | None = Field(None, description="Custom name for the run")


class SaveRunResponse(BaseModel):
    """Response after saving a run."""

    status: str = Field(..., description="Status: ok or error")
    metadata: ArchivedRunMetadata | None = Field(None, description="Run metadata")
    error: str | None = Field(None, description="Error message if failed")


class UpdateRunNameResponse(BaseModel):
    """Response after updating run name."""

    status: str = Field(..., description="Status: ok or error")
    run_id: str | None = Field(None, description="Updated run ID")
    new_name: str | None = Field(None, description="New name")
    error: str | None = Field(None, description="Error message if failed")


class DeleteRunResponse(BaseModel):
    """Response after deleting a run."""

    status: str = Field(..., description="Status: ok or error")
    run_id: str | None = Field(None, description="Deleted run ID")
    error: str | None = Field(None, description="Error message if failed")


@router.post("/save", response_model=SaveRunResponse)
async def save_archived_run(request: SaveRunRequest):
    """
    Save a completed threat modeling run to the archive.

    This endpoint is typically called automatically after a pipeline completes,
    but can also be called manually to archive existing results.

    Args:
        request: Save run request with pipeline result and metadata

    Returns:
        Metadata for the saved run

    Raises:
        HTTPException: 500 if save fails
    """
    try:
        archive_service = get_archive_service()

        metadata = archive_service.save_run(
            pipeline_result=request.pipeline_result,
            file_name=request.file_name,
            mode=request.mode,
            agent_name=request.agent_name,
            custom_name=request.custom_name,
        )

        logger.info(f"Archived run saved: {metadata.run_id}")

        return SaveRunResponse(
            status="ok",
            metadata=metadata,
        )

    except Exception as e:
        logger.error(f"Failed to save archived run: {e}", exc_info=True)
        return SaveRunResponse(
            status="error",
            error=str(e),
        )


@router.get("/runs", response_model=ArchivedRunList)
async def get_archived_runs():
    """
    Get list of all archived runs (metadata only).

    Returns list sorted by created_at descending (newest first).

    Returns:
        List of archived run metadata
    """
    try:
        archive_service = get_archive_service()
        return archive_service.get_all_runs()

    except Exception as e:
        logger.error(f"Failed to get archived runs: {e}")
        return ArchivedRunList(runs=[], total=0)


@router.get("/runs/{run_id}", response_model=ArchivedRun)
async def get_archived_run(run_id: str):
    """
    Get complete data for a specific archived run.

    Args:
        run_id: Run ID to retrieve

    Returns:
        Complete archived run with all data

    Raises:
        HTTPException: 404 if run not found
    """
    try:
        archive_service = get_archive_service()
        archived_run = archive_service.get_run(run_id)

        if not archived_run:
            raise HTTPException(
                status_code=404,
                detail=f"Archived run not found: {run_id}"
            )

        return archived_run

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get archived run {run_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve archived run: {str(e)}"
        )


@router.put("/runs/name", response_model=UpdateRunNameResponse)
async def update_run_name(request: UpdateRunNameRequest):
    """
    Update the name of an archived run.

    Args:
        request: Update request with run_id and new_name

    Returns:
        Updated run metadata

    Raises:
        HTTPException: 404 if run not found, 500 if update fails
    """
    try:
        archive_service = get_archive_service()

        success = archive_service.update_run_name(
            run_id=request.run_id,
            new_name=request.new_name,
        )

        if not success:
            return UpdateRunNameResponse(
                status="error",
                error=f"Run not found or update failed: {request.run_id}",
            )

        return UpdateRunNameResponse(
            status="ok",
            run_id=request.run_id,
            new_name=request.new_name,
        )

    except Exception as e:
        logger.error(f"Failed to update run name: {e}")
        return UpdateRunNameResponse(
            status="error",
            error=str(e),
        )


@router.delete("/runs/{run_id}", response_model=DeleteRunResponse)
async def delete_archived_run(run_id: str):
    """
    Delete an archived run.

    Args:
        run_id: Run ID to delete

    Returns:
        Deletion confirmation

    Raises:
        HTTPException: 404 if run not found, 500 if deletion fails
    """
    try:
        archive_service = get_archive_service()

        success = archive_service.delete_run(run_id)

        if not success:
            return DeleteRunResponse(
                status="error",
                run_id=run_id,
                error="Run not found or deletion failed",
            )

        return DeleteRunResponse(
            status="ok",
            run_id=run_id,
        )

    except Exception as e:
        logger.error(f"Failed to delete run {run_id}: {e}")
        return DeleteRunResponse(
            status="error",
            run_id=run_id,
            error=str(e),
        )


@router.get("/stats")
async def get_archive_stats():
    """
    Get statistics about archived runs.

    Returns:
        Dictionary with archive statistics
    """
    try:
        archive_service = get_archive_service()
        return archive_service.get_stats()

    except Exception as e:
        logger.error(f"Failed to get archive stats: {e}")
        return {
            "total_runs": 0,
            "total_paths": 0,
            "modes": {},
            "file_types": {},
        }
