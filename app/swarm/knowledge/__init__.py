"""Cloud TTP Knowledge Base Package

Provides selective technique reference injection for agent prompts.
Instead of injecting the entire MITRE ATT&CK knowledge base into every
prompt, this module extracts only the techniques that were actually found
during security analysis.
"""

from .kb_loader import (
    get_technique_context,
    get_techniques_for_findings,
    get_all_technique_ids,
    load_technique_kb,
)

__all__ = [
    'get_technique_context',
    'get_techniques_for_findings',
    'get_all_technique_ids',
    'load_technique_kb',
]
