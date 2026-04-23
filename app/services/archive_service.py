"""
Archive service for storing and retrieving threat modeling runs.

This service provides persistence for completed threat modeling runs,
allowing users to save, retrieve, update, and delete archived results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from uuid import uuid4

from app.models.archived_run import ArchivedRun, ArchivedRunMetadata, ArchivedRunList
from app.utils.timezone import now_gmt8, now_gmt8_iso

logger = logging.getLogger(__name__)

# Archive storage directory
ARCHIVE_DIR = Path("data/archived_runs")
ARCHIVE_INDEX_FILE = ARCHIVE_DIR / "index.json"


class ArchiveService:
    """Service for managing archived threat modeling runs."""

    def __init__(self):
        """Initialize archive service and ensure storage directory exists."""
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        if not ARCHIVE_INDEX_FILE.exists():
            self._save_index([])
            logger.info("Created new archive index")

    def _load_index(self) -> List[Dict[str, Any]]:
        """Load archive index from disk."""
        try:
            with open(ARCHIVE_INDEX_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load archive index: {e}")
            return []

    def _save_index(self, index: List[Dict[str, Any]]) -> None:
        """Save archive index to disk."""
        try:
            with open(ARCHIVE_INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save archive index: {e}")
            raise

    def _get_run_file_path(self, run_id: str) -> Path:
        """Get file path for a specific run."""
        return ARCHIVE_DIR / f"{run_id}.json"

    def generate_run_id(self) -> str:
        """Generate unique run ID with timestamp (GMT+8)."""
        timestamp = now_gmt8().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid4())[:8]
        return f"run_{timestamp}_{unique_id}"

    def generate_default_name(self, file_name: str, mode: str) -> str:
        """Generate default name for archived run (GMT+8)."""
        timestamp = now_gmt8().strftime("%Y-%m-%d %H:%M")
        file_base = Path(file_name).stem
        return f"TM Swarm Run - {file_base} - {timestamp}"

    def save_run(
        self,
        pipeline_result: Dict[str, Any],
        file_name: str,
        mode: str,
        agent_name: Optional[str] = None,
        custom_name: Optional[str] = None,
        model_used: Optional[str] = None,
    ) -> ArchivedRunMetadata:
        """
        Save a completed threat modeling run.

        Args:
            pipeline_result: Complete pipeline result dictionary
            file_name: Original IaC file name
            mode: Run mode (full, quick, single)
            agent_name: Agent name if single mode
            custom_name: Custom name for the run (optional)
            model_used: LLM model name used for the run (optional)

        Returns:
            Metadata for the saved run
        """
        try:
            # Generate run ID and metadata
            run_id = self.generate_run_id()
            created_at = now_gmt8_iso()

            # Extract file type
            file_type = Path(file_name).suffix

            # Get execution time and paths count from result
            execution_time = pipeline_result.get("execution_time_seconds", 0)
            # Handle both standard pipelines (final_paths) and stigmergic (attack_paths)
            paths_count = len(pipeline_result.get("final_paths", pipeline_result.get("attack_paths", [])))

            # Generate name
            name = custom_name or self.generate_default_name(file_name, mode)

            # Create metadata
            metadata = ArchivedRunMetadata(
                run_id=run_id,
                name=name,
                created_at=created_at,
                updated_at=None,
                file_name=file_name,
                file_type=file_type,
                mode=mode,
                agent_name=agent_name,
                execution_time_seconds=execution_time,
                paths_count=paths_count,
                model_used=model_used,
            )

            # Create archived run
            archived_run = ArchivedRun(
                metadata=metadata,
                result=pipeline_result
            )

            # Save run to file
            run_file_path = self._get_run_file_path(run_id)
            with open(run_file_path, "w", encoding="utf-8") as f:
                json.dump(archived_run.model_dump(), f, indent=2)

            # Update index
            index = self._load_index()
            index.append(metadata.model_dump())
            # Sort by created_at descending (newest first)
            index.sort(key=lambda x: x["created_at"], reverse=True)
            self._save_index(index)

            logger.info(f"Saved archived run: {run_id} - {name}")
            return metadata

        except Exception as e:
            logger.error(f"Failed to save archived run: {e}", exc_info=True)
            raise

    def get_all_runs(self) -> ArchivedRunList:
        """
        Get list of all archived runs (metadata only).

        Returns:
            List of archived run metadata
        """
        try:
            index = self._load_index()
            runs = [ArchivedRunMetadata(**run_data) for run_data in index]
            return ArchivedRunList(runs=runs, total=len(runs))
        except Exception as e:
            logger.error(f"Failed to get archived runs: {e}")
            return ArchivedRunList(runs=[], total=0)

    def get_run(self, run_id: str) -> Optional[ArchivedRun]:
        """
        Get complete data for a specific archived run.

        Args:
            run_id: Run ID to retrieve

        Returns:
            Complete archived run or None if not found
        """
        try:
            run_file_path = self._get_run_file_path(run_id)
            if not run_file_path.exists():
                logger.warning(f"Archived run not found: {run_id}")
                return None

            with open(run_file_path, "r", encoding="utf-8") as f:
                run_data = json.load(f)

            return ArchivedRun(**run_data)

        except Exception as e:
            logger.error(f"Failed to get archived run {run_id}: {e}")
            return None

    def update_run_name(self, run_id: str, new_name: str) -> bool:
        """
        Update the name of an archived run.

        Args:
            run_id: Run ID to update
            new_name: New name for the run

        Returns:
            True if successful, False otherwise
        """
        try:
            # Load the run
            archived_run = self.get_run(run_id)
            if not archived_run:
                return False

            # Update metadata
            archived_run.metadata.name = new_name
            archived_run.metadata.updated_at = now_gmt8_iso()

            # Save updated run
            run_file_path = self._get_run_file_path(run_id)
            with open(run_file_path, "w", encoding="utf-8") as f:
                json.dump(archived_run.model_dump(), f, indent=2)

            # Update index
            index = self._load_index()
            for run_data in index:
                if run_data["run_id"] == run_id:
                    run_data["name"] = new_name
                    run_data["updated_at"] = archived_run.metadata.updated_at
                    break
            self._save_index(index)

            logger.info(f"Updated run name: {run_id} -> {new_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to update run name {run_id}: {e}")
            return False

    def delete_run(self, run_id: str) -> bool:
        """
        Delete an archived run.

        Args:
            run_id: Run ID to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete run file
            run_file_path = self._get_run_file_path(run_id)
            if run_file_path.exists():
                run_file_path.unlink()

            # Update index
            index = self._load_index()
            index = [run for run in index if run["run_id"] != run_id]
            self._save_index(index)

            logger.info(f"Deleted archived run: {run_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete archived run {run_id}: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about archived runs.

        Returns:
            Dictionary with archive statistics
        """
        try:
            index = self._load_index()

            total_runs = len(index)
            if total_runs == 0:
                return {
                    "total_runs": 0,
                    "total_paths": 0,
                    "modes": {},
                    "file_types": {},
                }

            total_paths = sum(run.get("paths_count", 0) for run in index)

            modes = {}
            file_types = {}

            for run in index:
                mode = run.get("mode", "unknown")
                modes[mode] = modes.get(mode, 0) + 1

                file_type = run.get("file_type", "unknown")
                file_types[file_type] = file_types.get(file_type, 0) + 1

            return {
                "total_runs": total_runs,
                "total_paths": total_paths,
                "modes": modes,
                "file_types": file_types,
                "latest_run": index[0] if index else None,
            }

        except Exception as e:
            logger.error(f"Failed to get archive stats: {e}")
            return {"total_runs": 0, "total_paths": 0, "modes": {}, "file_types": {}}


# Singleton instance
_archive_service = None


def get_archive_service() -> ArchiveService:
    """Get singleton archive service instance."""
    global _archive_service
    if _archive_service is None:
        _archive_service = ArchiveService()
    return _archive_service
