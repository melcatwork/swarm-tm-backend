"""Core data models for threat intelligence items and configurations."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class ThreatIntelItem(BaseModel):
    """
    Represents a single threat intelligence item from any source.

    This model normalizes data from various threat intelligence feeds into
    a consistent structure for processing and storage.
    """

    id: str = Field(..., description="Unique identifier for the threat intel item")
    title: str = Field(..., description="Title or headline of the threat intel")
    summary: str = Field(..., description="Brief summary or description")
    source: str = Field(..., description="Source name (e.g., 'CISA', 'NVD')")
    url: str = Field(..., description="URL to the original threat intel item")
    published: datetime = Field(..., description="Publication date and time")
    category: Literal["cve", "incident", "ttp", "news"] = Field(
        ..., description="Category of threat intelligence"
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        ..., description="Severity level of the threat"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="List of tags or keywords associated with the item"
    )
    cves: list[str] = Field(
        default_factory=list,
        description="List of CVE identifiers mentioned in the item"
    )
    ttps: list[str] = Field(
        default_factory=list,
        description="List of MITRE ATT&CK TTPs (Tactics, Techniques, Procedures)"
    )
    citation_score: float = Field(
        default=0.0,
        ge=0.0,
        description="Score indicating how often this item is cited or referenced"
    )
    raw_data: dict = Field(
        default_factory=dict,
        description="Original raw data from the source for reference"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "cve-2024-1234",
                "title": "Critical RCE in Popular Framework",
                "summary": "A critical remote code execution vulnerability was discovered...",
                "source": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "published": "2024-03-15T10:30:00Z",
                "category": "cve",
                "severity": "critical",
                "tags": ["rce", "framework", "authentication"],
                "cves": ["CVE-2024-1234"],
                "ttps": ["T1190"],
                "citation_score": 8.5,
                "raw_data": {}
            }
        }


class SourceConfig(BaseModel):
    """
    Configuration for a threat intelligence source.

    Defines how to connect to and fetch data from a specific threat
    intelligence feed or API.
    """

    name: str = Field(..., description="Unique name for this source")
    adapter: str = Field(
        ...,
        description="Adapter class name to use for fetching (e.g., 'RSSAdapter', 'CISAAdapter')"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this source is currently enabled"
    )
    refresh_minutes: int = Field(
        default=60,
        gt=0,
        description="How often to refresh data from this source (in minutes)"
    )
    config: dict = Field(
        default_factory=dict,
        description="Adapter-specific configuration parameters"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "cisa-alerts",
                "adapter": "RSSAdapter",
                "enabled": True,
                "refresh_minutes": 30,
                "config": {
                    "url": "https://www.cisa.gov/cybersecurity-advisories/rss.xml",
                    "category": "incident"
                }
            }
        }


class FeedStatus(BaseModel):
    """
    Status information for a threat intelligence feed.

    Tracks the current health and metrics of a configured threat
    intelligence source.
    """

    source_name: str = Field(..., description="Name of the source")
    last_fetch: datetime | None = Field(
        None,
        description="Timestamp of the last successful fetch"
    )
    item_count: int = Field(
        ...,
        ge=0,
        description="Number of items fetched in the last refresh"
    )
    healthy: bool = Field(
        ...,
        description="Whether the source is currently healthy and functioning"
    )
    error: str | None = Field(
        default=None,
        description="Error message if the last fetch failed"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "source_name": "cisa-alerts",
                "last_fetch": "2024-03-15T12:00:00Z",
                "item_count": 15,
                "healthy": True,
                "error": None
            }
        }
