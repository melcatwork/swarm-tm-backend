from typing import Optional
from .intel_db import IntelDatabase, AbusePattern

class AbuseKBLoader:
    def __init__(self):
        self.db = IntelDatabase()

    def get_all(self) -> list[AbusePattern]:
        # Return all abuse patterns from DB
        with self.db._conn() as conn:
            rows = conn.execute(
                'SELECT * FROM abuse_patterns '
                'ORDER BY cvss_equivalent DESC'
            ).fetchall()
        return [self.db._row_to_abuse(r) for r in rows]

    def get_abuse_by_id(
        self, abuse_id: str
    ) -> Optional[dict]:
        with self.db._conn() as conn:
            row = conn.execute(
                'SELECT * FROM abuse_patterns WHERE abuse_id=?',
                (abuse_id,)
            ).fetchone()
        if not row:
            return None
        return dict(self.db._row_to_abuse(row).__dict__)

    def get_abuses_for_resource_type(
        self, resource_type: str
    ) -> list[dict]:
        results = self.db.get_abuse_patterns_for_resource(
            resource_type
        )
        return [r.__dict__ for r in results]

    def get_abuses_for_signal(
        self, signal_id: str
    ) -> list[dict]:
        # Signal-to-abuse mapping — kept here not in DB
        # so it can be updated without a sync
        SIGNAL_ABUSE_MAP = {
            'IMDS_V1_ENABLED': ['ATTCK-T1552-005'],
            'IAM_S3_WILDCARD': ['ATTCK-T1530', 'ATTCK-T1537'],
            'IAM_PRIVILEGE_ESCALATION_ACTIONS': [
                'ATTCK-T1548', 'ATTCK-T1098', 'ATTCK-T1136-003'
            ],
            'CLOUDTRAIL_NO_S3_DATA_EVENTS': [
                'ATTCK-T1562-008'
            ],
            'S3_NO_RESOURCE_POLICY': ['ATTCK-T1530'],
        }
        abuse_ids = SIGNAL_ABUSE_MAP.get(signal_id, [])
        results = []
        for aid in abuse_ids:
            entry = self.get_abuse_by_id(aid)
            if entry:
                results.append(entry)
        return results

    def format_for_prompt(self, abuses: list) -> str:
        if not abuses:
            return ''
        lines = [
            'CLOUD ABUSE PATTERNS APPLICABLE TO THIS INFRASTRUCTURE:',
            '',
        ]
        for abuse in abuses:
            if isinstance(abuse, dict):
                name = abuse.get('name', '')
                abuse_id = abuse.get('abuse_id', '')
                phase = abuse.get('kill_chain_phase', '')
                tech = abuse.get('technique_id', '')
                desc = abuse.get('description', '')
                cmds = abuse.get('exploitation_commands', [])
                gap = abuse.get('detection_gap', '')
                refs = abuse.get('references', [])
            else:
                name = getattr(abuse, 'name', '')
                abuse_id = getattr(abuse, 'abuse_id', '')
                phase = getattr(abuse, 'kill_chain_phase', '')
                tech = getattr(abuse, 'technique_id', '')
                desc = getattr(abuse, 'description', '')
                cmds = getattr(
                    abuse, 'exploitation_commands', []
                )
                gap = getattr(abuse, 'detection_gap', '')
                refs = getattr(abuse, 'references', [])
            lines.append(f'[{abuse_id}] {name}')
            lines.append(
                f'  Phase: {phase} | ATT&CK: {tech}'
            )
            lines.append(f'  {desc[:200]}')
            if cmds:
                lines.append('  Commands:')
                for cmd in cmds[:3]:
                    lines.append(f'    {cmd}')
            if gap:
                lines.append(f'  Detection gap: {gap}')
            if refs:
                lines.append(f'  Reference: {refs[0]}')
            lines.append('')
        return '\n'.join(lines)
