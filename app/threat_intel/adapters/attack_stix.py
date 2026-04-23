"""MITRE ATT&CK STIX adapter for fetching TTPs and threat actor profiles."""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any

import requests

from app.utils.timezone import now_gmt8
from ..core.models import ThreatIntelItem, SourceConfig
from .base_adapter import BaseAdapter

logger = logging.getLogger(__name__)


class AttackStixAdapter(BaseAdapter):
    """
    Adapter for fetching MITRE ATT&CK Enterprise techniques and threat actors from STIX data.

    Downloads and caches the ATT&CK Enterprise STIX bundle, extracts attack patterns
    (techniques/TTPs) as ThreatIntelItems, and builds threat actor profiles with
    associated techniques for use by the swarm agents.
    """

    STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    CACHE_FILE = Path("data/attack_enterprise.json")
    THREAT_ACTORS_FILE = Path("data/threat_actors.json")
    CACHE_MAX_AGE_HOURS = 24
    REQUEST_TIMEOUT = 60

    def __init__(self, source_config: SourceConfig) -> None:
        """
        Initialize the ATT&CK STIX adapter.

        Args:
            source_config: Configuration for this ATT&CK source
        """
        super().__init__(source_config)
        # Ensure data directory exists
        self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    def fetch(self) -> List[ThreatIntelItem]:
        """
        Fetch ATT&CK techniques and extract threat actor profiles.

        Downloads the ATT&CK Enterprise STIX bundle (or loads from cache),
        extracts techniques as ThreatIntelItems, and processes threat actor
        groups with their associated techniques.

        Returns:
            List of ThreatIntelItem objects representing ATT&CK techniques

        Raises:
            Exception: Logs errors but returns empty list on failure
        """
        try:
            # Load STIX data (from cache or download)
            stix_data = self._load_stix_data()

            if not stix_data:
                logger.error("Failed to load STIX data")
                return []

            objects = stix_data.get("objects", [])
            logger.info(f"Loaded {len(objects)} STIX objects for {self.get_name()}")

            # Extract techniques (attack-patterns)
            techniques = self._extract_techniques(objects)
            logger.info(f"Extracted {len(techniques)} ATT&CK techniques")

            # Extract threat actors and their relationships
            self._extract_threat_actors(objects)

            return techniques

        except Exception as e:
            logger.error(f"Failed to fetch ATT&CK data: {e}", exc_info=True)
            return []

    def _load_stix_data(self) -> Dict[str, Any] | None:
        """
        Load STIX data from cache or download if needed.

        Checks if cached file exists and is recent enough. If not, downloads
        fresh data from MITRE's GitHub repository.

        Returns:
            STIX data dictionary or None on failure
        """
        # Check if cache is valid
        if self._is_cache_valid():
            logger.info(f"Loading ATT&CK STIX data from cache: {self.CACHE_FILE}")
            try:
                with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache, will download: {e}")

        # Download fresh data
        return self._download_stix_data()

    def _is_cache_valid(self) -> bool:
        """
        Check if the cached STIX file exists and is recent enough.

        Returns:
            True if cache is valid, False otherwise
        """
        if not self.CACHE_FILE.exists():
            return False

        # Check file age
        file_mtime = datetime.fromtimestamp(
            self.CACHE_FILE.stat().st_mtime,
            tz=timezone.utc
        )
        age = now_gmt8() - file_mtime
        max_age = timedelta(hours=self.CACHE_MAX_AGE_HOURS)

        is_valid = age < max_age
        if is_valid:
            logger.info(f"Cache is valid (age: {age.total_seconds() / 3600:.1f} hours)")
        else:
            logger.info(f"Cache is stale (age: {age.total_seconds() / 3600:.1f} hours)")

        return is_valid

    def _download_stix_data(self) -> Dict[str, Any] | None:
        """
        Download fresh STIX data from MITRE's GitHub repository.

        Returns:
            STIX data dictionary or None on failure
        """
        try:
            logger.info(f"Downloading ATT&CK STIX data from {self.STIX_URL}")

            response = requests.get(self.STIX_URL, timeout=self.REQUEST_TIMEOUT)
            response.raise_for_status()

            stix_data = response.json()

            # Save to cache
            with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(stix_data, f, indent=2)

            logger.info(f"Downloaded and cached STIX data to {self.CACHE_FILE}")
            return stix_data

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download STIX data: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing STIX download: {e}", exc_info=True)
            return None

    def _extract_techniques(self, objects: List[Dict[str, Any]]) -> List[ThreatIntelItem]:
        """
        Extract ATT&CK techniques from STIX objects.

        Args:
            objects: List of STIX objects

        Returns:
            List of ThreatIntelItem objects for techniques
        """
        techniques = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            try:
                item = self._parse_technique(obj)
                if item:
                    techniques.append(item)
            except Exception as e:
                logger.error(f"Error parsing technique: {e}", exc_info=True)
                continue

        return techniques

    def _parse_technique(self, obj: Dict[str, Any]) -> ThreatIntelItem | None:
        """
        Parse a STIX attack-pattern object into a ThreatIntelItem.

        Args:
            obj: STIX attack-pattern object

        Returns:
            ThreatIntelItem or None if parsing fails
        """
        try:
            # Extract technique ID from external references
            external_refs = obj.get("external_references", [])
            if not external_refs:
                logger.warning("Attack pattern missing external references")
                return None

            # First reference should be the MITRE ATT&CK reference
            mitre_ref = external_refs[0]
            technique_id = mitre_ref.get("external_id", "")
            url = mitre_ref.get("url", "")

            if not technique_id:
                logger.warning("Attack pattern missing technique ID")
                return None

            # Extract basic fields
            name = obj.get("name", "Unnamed Technique")
            description = obj.get("description", "")
            summary = description[:500]  # Truncate to 500 chars

            # Parse modified date
            modified_str = obj.get("modified", obj.get("created", ""))
            try:
                published = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published = now_gmt8()

            # Extract tactics from kill chain phases
            tags = []
            kill_chain_phases = obj.get("kill_chain_phases", [])
            for phase in kill_chain_phases:
                phase_name = phase.get("phase_name", "")
                if phase_name:
                    tags.append(phase_name)

            # Create ThreatIntelItem
            item = ThreatIntelItem(
                id=technique_id,
                title=name,
                summary=summary,
                source="MITRE ATT&CK",
                url=url,
                published=published,
                category="ttp",
                severity="info",
                tags=tags,
                cves=[],
                ttps=[technique_id],
                raw_data=obj,
            )

            return item

        except Exception as e:
            logger.error(f"Error parsing technique object: {e}", exc_info=True)
            return None

    def _extract_threat_actors(self, objects: List[Dict[str, Any]]) -> None:
        """
        Extract threat actor groups and their associated techniques.

        Processes intrusion-set objects (threat actors) and builds profiles
        with associated techniques by analyzing STIX relationships. Saves
        the threat actor profiles to a JSON file for use by swarm agents.

        Args:
            objects: List of STIX objects
        """
        try:
            # Extract intrusion-sets (threat actor groups)
            intrusion_sets = {}
            for obj in objects:
                if obj.get("type") == "intrusion-set":
                    group_id = obj.get("id")
                    intrusion_sets[group_id] = {
                        "id": group_id,
                        "name": obj.get("name", "Unknown Group"),
                        "description": obj.get("description", ""),
                        "aliases": obj.get("aliases", []),
                        "created": obj.get("created", ""),
                        "modified": obj.get("modified", ""),
                        "techniques": [],
                        "external_references": obj.get("external_references", []),
                    }

            logger.info(f"Found {len(intrusion_sets)} threat actor groups")

            # Extract relationships (threat actors using techniques)
            relationships = {}
            for obj in objects:
                if obj.get("type") == "relationship":
                    rel_type = obj.get("relationship_type")
                    if rel_type == "uses":
                        source_ref = obj.get("source_ref", "")
                        target_ref = obj.get("target_ref", "")

                        # Check if source is a threat actor group
                        if source_ref in intrusion_sets:
                            if source_ref not in relationships:
                                relationships[source_ref] = []
                            relationships[source_ref].append(target_ref)

            # Map techniques to threat actors
            # First, build a map of attack-pattern IDs to technique IDs
            technique_id_map = {}
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    stix_id = obj.get("id")
                    external_refs = obj.get("external_references", [])
                    if external_refs:
                        technique_id = external_refs[0].get("external_id", "")
                        if technique_id:
                            technique_id_map[stix_id] = technique_id

            # Associate techniques with threat actors
            for group_id, target_refs in relationships.items():
                if group_id in intrusion_sets:
                    for target_ref in target_refs:
                        # Check if target is an attack-pattern
                        if target_ref in technique_id_map:
                            technique_id = technique_id_map[target_ref]
                            intrusion_sets[group_id]["techniques"].append(technique_id)

            # Convert to list and add statistics
            threat_actors_list = []
            for group_data in intrusion_sets.values():
                # Deduplicate techniques
                group_data["techniques"] = list(set(group_data["techniques"]))
                group_data["technique_count"] = len(group_data["techniques"])
                threat_actors_list.append(group_data)

            # Sort by technique count (most prolific groups first)
            threat_actors_list.sort(key=lambda x: x["technique_count"], reverse=True)

            # Save to file
            with open(self.THREAT_ACTORS_FILE, "w", encoding="utf-8") as f:
                json.dump(threat_actors_list, f, indent=2)

            logger.info(
                f"Saved {len(threat_actors_list)} threat actor profiles to "
                f"{self.THREAT_ACTORS_FILE}"
            )

            # Log top 5 most prolific groups
            for i, group in enumerate(threat_actors_list[:5], 1):
                logger.info(
                    f"  {i}. {group['name']}: {group['technique_count']} techniques"
                )

        except Exception as e:
            logger.error(f"Error extracting threat actors: {e}", exc_info=True)

    def health_check(self) -> bool:
        """
        Check if ATT&CK data is accessible.

        Returns True if the cache file exists OR the STIX URL is reachable.

        Returns:
            True if the source is healthy, False otherwise
        """
        # Check if cache exists
        if self.CACHE_FILE.exists():
            logger.info(f"Health check passed for {self.get_name()}: cache exists")
            return True

        # Check if URL is reachable
        try:
            response = requests.head(self.STIX_URL, timeout=10)
            is_healthy = response.status_code < 400

            if is_healthy:
                logger.info(
                    f"Health check passed for {self.get_name()}: URL is reachable"
                )
            else:
                logger.warning(
                    f"Health check failed for {self.get_name()}: "
                    f"status {response.status_code}"
                )

            return is_healthy

        except requests.exceptions.RequestException as e:
            logger.error(f"Health check failed for {self.get_name()}: {e}")
            return False
