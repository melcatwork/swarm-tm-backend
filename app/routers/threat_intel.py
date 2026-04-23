"""Threat intelligence API endpoints."""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..threat_intel.core import (
    FeedManager,
    CitationScorer,
    ThreatIntelItem,
    SourceConfig,
    FeedStatus,
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])

# Module-level singleton instances
feed_manager = FeedManager()
scorer = CitationScorer()


class PullResponse(BaseModel):
    """Response model for pull operations."""

    status: str
    items_fetched: int


class UpdateTTPResponse(BaseModel):
    """Response model for TTP update operations."""

    status: str
    techniques_updated: int


class AddSourceResponse(BaseModel):
    """Response model for adding a source."""

    status: str
    source: str


class ToggleSourceRequest(BaseModel):
    """Request model for toggling a source."""

    enabled: bool


@router.get("/items", response_model=List[ThreatIntelItem])
async def get_threat_intel_items(
    category: Optional[str] = Query(None, description="Filter by category (cve, incident, ttp, news)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of items to return"),
) -> List[ThreatIntelItem]:
    """
    Get threat intelligence items from all sources.

    Fetches data from all enabled sources, scores by relevance, and returns
    the top N items filtered by optional category and severity parameters.

    Args:
        category: Optional category filter (cve, incident, ttp, news)
        severity: Optional severity filter (critical, high, medium, low, info)
        limit: Maximum number of items to return (default 50)

    Returns:
        List of ThreatIntelItem objects sorted by citation score
    """
    try:
        logger.info(
            f"Fetching threat intel items (category={category}, severity={severity}, limit={limit})"
        )

        # Fetch from all sources
        items = feed_manager.fetch_all()

        if not items:
            logger.warning("No items fetched from any source")
            return []

        # Score items
        scored_items = scorer.score_items(items)

        # Filter by category if provided
        if category:
            scored_items = [
                item for item in scored_items
                if item.category == category.lower()
            ]
            logger.info(f"Filtered to {len(scored_items)} items with category={category}")

        # Filter by severity if provided
        if severity:
            scored_items = [
                item for item in scored_items
                if item.severity == severity.lower()
            ]
            logger.info(f"Filtered to {len(scored_items)} items with severity={severity}")

        # Limit results
        result = scored_items[:limit]

        logger.info(f"Returning {len(result)} threat intel items")
        return result

    except Exception as e:
        logger.error(f"Error fetching threat intel items: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat intel: {str(e)}")


@router.post("/pull", response_model=PullResponse)
async def pull_threat_intel() -> PullResponse:
    """
    Manually trigger a pull from all threat intelligence sources.

    Forces an immediate fetch from all enabled sources, bypassing any
    scheduled refresh intervals.

    Returns:
        Status and count of items fetched
    """
    try:
        logger.info("Manual pull triggered for all sources")

        items = feed_manager.fetch_all()

        logger.info(f"Manual pull completed: {len(items)} items fetched")
        return PullResponse(
            status="ok",
            items_fetched=len(items)
        )

    except Exception as e:
        logger.error(f"Error during manual pull: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pull failed: {str(e)}")


@router.post("/update-ttp", response_model=UpdateTTPResponse)
async def update_ttp() -> UpdateTTPResponse:
    """
    Force update of MITRE ATT&CK techniques, bypassing cache.

    Triggers a fresh download of the ATT&CK STIX data, ignoring the
    24-hour cache. Useful for getting the latest technique updates.

    Returns:
        Status and count of techniques updated
    """
    try:
        logger.info("Forcing ATT&CK TTP update (bypassing cache)")

        # Delete cache to force fresh download
        from pathlib import Path
        cache_file = Path("data/attack_enterprise.json")
        if cache_file.exists():
            cache_file.unlink()
            logger.info("Deleted ATT&CK cache file")

        # Fetch from ATT&CK source
        items = feed_manager.fetch_source("MITRE ATT&CK")

        logger.info(f"ATT&CK TTP update completed: {len(items)} techniques")
        return UpdateTTPResponse(
            status="ok",
            techniques_updated=len(items)
        )

    except ValueError as e:
        logger.error(f"ATT&CK source not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating TTPs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"TTP update failed: {str(e)}")


@router.get("/sources", response_model=List[FeedStatus])
async def get_sources() -> List[FeedStatus]:
    """
    Get status of all configured threat intelligence sources.

    Returns health status, last fetch time, and item counts for each
    configured source.

    Returns:
        List of FeedStatus objects
    """
    try:
        logger.info("Getting source status")

        statuses = feed_manager.get_status()

        logger.info(f"Returning status for {len(statuses)} sources")
        return statuses

    except Exception as e:
        logger.error(f"Error getting source status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get sources: {str(e)}")


@router.post("/sources", response_model=AddSourceResponse)
async def add_source(source_config: SourceConfig) -> AddSourceResponse:
    """
    Add a new threat intelligence source.

    Adds a source configuration to the system and loads the corresponding
    adapter if enabled.

    Args:
        source_config: Source configuration to add

    Returns:
        Status and name of added source
    """
    try:
        logger.info(f"Adding new source: {source_config.name}")

        feed_manager.add_source(source_config)

        logger.info(f"Successfully added source: {source_config.name}")
        return AddSourceResponse(
            status="ok",
            source=source_config.name
        )

    except ValueError as e:
        logger.warning(f"Source already exists: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding source: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to add source: {str(e)}")


@router.put("/sources/{name}/toggle")
async def toggle_source(name: str, request: ToggleSourceRequest) -> dict:
    """
    Enable or disable a threat intelligence source.

    Toggles the enabled state of a source, loading or unloading the
    corresponding adapter as needed.

    Args:
        name: Name of the source to toggle
        request: Toggle request with enabled flag

    Returns:
        Status message
    """
    try:
        logger.info(f"Toggling source '{name}' to enabled={request.enabled}")

        feed_manager.toggle_source(name, request.enabled)

        logger.info(f"Successfully toggled source: {name}")
        return {
            "status": "ok",
            "source": name,
            "enabled": request.enabled
        }

    except ValueError as e:
        logger.warning(f"Source not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error toggling source: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to toggle source: {str(e)}")


@router.delete("/sources/{name}")
async def remove_source(name: str) -> dict:
    """
    Remove a threat intelligence source.

    Deletes a source from the configuration and unloads its adapter.

    Args:
        name: Name of the source to remove

    Returns:
        Status message
    """
    try:
        logger.info(f"Removing source: {name}")

        feed_manager.remove_source(name)

        logger.info(f"Successfully removed source: {name}")
        return {
            "status": "ok",
            "source": name,
            "removed": True
        }

    except ValueError as e:
        logger.warning(f"Source not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error removing source: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to remove source: {str(e)}")
