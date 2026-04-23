"""Knowledge base loader for cloud TTP reference material.

Provides selective injection of MITRE ATT&CK technique context
into agent prompts based on what was actually found in security
analysis, rather than injecting the entire knowledge base.
"""

import logging
from pathlib import Path
from typing import List, Optional, Set
import yaml

logger = logging.getLogger(__name__)

# Path to technique knowledge base
KB_PATH = Path(__file__).parent / "cloud_ttp_kb.yaml"


def load_technique_kb() -> dict:
    """Load the complete technique knowledge base from YAML.

    Returns:
        Dictionary mapping technique IDs to technique details
    """
    try:
        with open(KB_PATH, 'r') as f:
            kb_data = yaml.safe_load(f)
            return kb_data.get('techniques', {})
    except FileNotFoundError:
        logger.warning(f"Technique KB not found at {KB_PATH}")
        return {}
    except Exception as e:
        logger.error(f"Failed to load technique KB: {e}")
        return {}


def get_technique_context(technique_id: str) -> Optional[str]:
    """Get formatted context for a single technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1552.005")

    Returns:
        Formatted string with technique details, or None if not found
    """
    kb = load_technique_kb()

    if technique_id not in kb:
        return None

    tech = kb[technique_id]

    # Format technique context
    lines = [
        f"=== {technique_id}: {tech.get('name', 'Unknown')} ===",
        f"Description: {tech.get('description', 'No description available')}",
        "",
    ]

    # AWS implementation details
    if 'aws_implementation' in tech:
        impl = tech['aws_implementation']
        lines.append("AWS Implementation:")
        lines.append(f"  {impl}")
        lines.append("")

    # Exploitation commands
    if 'commands' in tech and tech['commands']:
        lines.append("Exploitation Commands:")
        for cmd in tech['commands']:
            lines.append(f"  {cmd}")
        lines.append("")

    # Detection gap
    if 'detection_gap' in tech:
        lines.append(f"Detection Gap: {tech['detection_gap']}")
        lines.append("")

    return '\n'.join(lines)


def get_techniques_for_findings(findings: List) -> str:
    """Returns technique KB context only for techniques referenced in findings.

    This is the key function for selective injection. Instead of dumping
    the entire KB into every agent prompt, this extracts only the techniques
    that were actually found during security analysis.

    Args:
        findings: List of SecurityFinding objects with technique_id attributes

    Returns:
        Formatted string containing technique context for all referenced techniques.
        Returns empty string if no techniques found or KB unavailable.
    """
    if not findings:
        return ''

    # Collect unique technique IDs from findings
    technique_ids: Set[str] = set()

    for finding in findings:
        # Primary technique ID
        if hasattr(finding, 'technique_id') and finding.technique_id:
            technique_ids.add(finding.technique_id)

        # Also check description for embedded technique references (T1234.567 format)
        if hasattr(finding, 'description') and finding.description:
            import re
            matches = re.findall(r'T\d{4}(?:\.\d{3})?', finding.description)
            technique_ids.update(matches)

    if not technique_ids:
        logger.info("No technique IDs found in security findings")
        return ''

    logger.info(f"Extracting KB context for {len(technique_ids)} techniques: {sorted(technique_ids)}")

    # Retrieve context for each technique
    result = []
    for tid in sorted(technique_ids):
        ctx = get_technique_context(tid)
        if ctx:
            result.append(ctx)
        else:
            logger.warning(f"No KB entry found for technique {tid}")

    if not result:
        return ''

    # Build final context section
    header = [
        "=" * 80,
        "TECHNIQUE REFERENCE (relevant to findings above)",
        "=" * 80,
        "",
        f"The following {len(result)} techniques were identified in the security analysis.",
        "Reference material is provided below to guide your attack path construction.",
        "",
    ]

    return '\n'.join(header + result)


def get_all_technique_ids() -> List[str]:
    """Get list of all technique IDs in the knowledge base.

    Returns:
        Sorted list of technique ID strings
    """
    kb = load_technique_kb()
    return sorted(kb.keys())
