"""
Timezone utilities for consistent GMT+8 timezone handling across the application.

All timestamps in the system use GMT+8 (Asia/Singapore timezone).
"""
from datetime import datetime, timezone, timedelta
from typing import Optional

# GMT+8 timezone
GMT8 = timezone(timedelta(hours=8))


def now_gmt8() -> datetime:
    """
    Get current datetime in GMT+8 timezone.

    Returns:
        Current datetime with GMT+8 timezone info
    """
    return datetime.now(GMT8)


def now_gmt8_iso() -> str:
    """
    Get current datetime in GMT+8 as ISO 8601 string.

    Returns:
        ISO 8601 formatted string with +08:00 timezone suffix

    Example:
        "2026-04-14T15:30:45+08:00"
    """
    return now_gmt8().isoformat()


def to_gmt8(dt: datetime) -> datetime:
    """
    Convert any datetime to GMT+8 timezone.

    Args:
        dt: Datetime to convert (can be timezone-aware or naive)

    Returns:
        Datetime converted to GMT+8 timezone
    """
    if dt.tzinfo is None:
        # Assume naive datetime is UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(GMT8)


def parse_iso_to_gmt8(iso_string: str) -> Optional[datetime]:
    """
    Parse ISO 8601 string and convert to GMT+8.

    Args:
        iso_string: ISO 8601 formatted datetime string

    Returns:
        Datetime in GMT+8 timezone, or None if parsing fails
    """
    try:
        # Remove 'Z' suffix if present and add UTC timezone
        if iso_string.endswith('Z'):
            iso_string = iso_string[:-1] + '+00:00'
        dt = datetime.fromisoformat(iso_string)
        return to_gmt8(dt)
    except (ValueError, AttributeError):
        return None


def format_gmt8(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format datetime in GMT+8 timezone.

    Args:
        dt: Datetime to format
        format_str: strftime format string

    Returns:
        Formatted datetime string in GMT+8
    """
    gmt8_dt = to_gmt8(dt)
    return gmt8_dt.strftime(format_str)
