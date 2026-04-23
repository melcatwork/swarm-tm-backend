import sqlite3
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / 'intel.db'

@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v3_severity: str
    epss_score: float
    epss_percentile: float
    in_kev: bool
    kev_date_added: Optional[str]
    affected_products: list[str]
    affected_versions: str
    cpe_matches: list[str]
    technique_ids: list[str]
    kill_chain_phase: str
    poc_in_github: bool
    nuclei_template_exists: bool
    metasploit_module_exists: bool
    references: list[str]
    published_date: str
    last_modified: str
    source: str            # NVD / OSV / GHSA
    remediation: str = ''  # Added for compatibility

    @property
    def risk_score(self) -> float:
        base = self.cvss_v3_score if self.cvss_v3_score else 5.0
        epss_bonus = self.epss_score * 3.0
        kev_bonus = 2.0 if self.in_kev else 0.0
        poc_bonus = 1.0 if (
            self.poc_in_github
            or self.nuclei_template_exists
            or self.metasploit_module_exists
        ) else 0.0
        return min(10.0, (base + epss_bonus + kev_bonus
                          + poc_bonus) / 3.0)

@dataclass
class AbusePattern:
    abuse_id: str
    name: str
    source: str             # ATTCK / CLOUDSPLOIT / PROWLER / MANUAL
    category: str
    cloud_providers: list[str]
    affected_terraform_resources: list[str]
    description: str
    kill_chain_phase: str
    technique_id: str
    technique_name: str
    exploitation_difficulty: str
    exploitation_commands: list[str]
    detection_gap: str
    cloudtrail_logged: bool
    guardduty_finding: Optional[str]
    remediation: str
    references: list[str]
    cvss_equivalent: float

class IntelDatabase:

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript('''
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_score REAL DEFAULT 0.0,
    cvss_v3_severity TEXT DEFAULT 'UNKNOWN',
    epss_score REAL DEFAULT 0.0,
    epss_percentile REAL DEFAULT 0.0,
    in_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    affected_products_json TEXT DEFAULT '[]',
    affected_versions TEXT DEFAULT 'unknown',
    cpe_matches_json TEXT DEFAULT '[]',
    technique_ids_json TEXT DEFAULT '[]',
    kill_chain_phase TEXT DEFAULT 'initial_access',
    poc_in_github INTEGER DEFAULT 0,
    nuclei_template_exists INTEGER DEFAULT 0,
    metasploit_module_exists INTEGER DEFAULT 0,
    references_json TEXT DEFAULT '[]',
    published_date TEXT,
    last_modified TEXT,
    source TEXT DEFAULT 'NVD',
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS abuse_patterns (
    abuse_id TEXT PRIMARY KEY,
    name TEXT,
    source TEXT,
    category TEXT,
    cloud_providers_json TEXT DEFAULT '[]',
    affected_terraform_resources_json TEXT DEFAULT '[]',
    description TEXT,
    kill_chain_phase TEXT,
    technique_id TEXT,
    technique_name TEXT,
    exploitation_difficulty TEXT DEFAULT 'MEDIUM',
    exploitation_commands_json TEXT DEFAULT '[]',
    detection_gap TEXT,
    cloudtrail_logged INTEGER DEFAULT 1,
    guardduty_finding TEXT,
    remediation TEXT,
    references_json TEXT DEFAULT '[]',
    cvss_equivalent REAL DEFAULT 7.0,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS resource_type_cve_index (
    resource_type TEXT,
    cve_id TEXT,
    software_keyword TEXT,
    PRIMARY KEY (resource_type, cve_id)
);

CREATE TABLE IF NOT EXISTS sync_state (
    source TEXT PRIMARY KEY,
    last_sync TEXT,
    record_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cve_severity
    ON cves(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_cve_kev
    ON cves(in_kev);
CREATE INDEX IF NOT EXISTS idx_cve_epss
    ON cves(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_abuse_resource
    ON abuse_patterns(category);
''')

    def upsert_cve(self, entry: dict):
        with self._conn() as conn:
            conn.execute('''
INSERT INTO cves (
    cve_id, description, cvss_v3_score, cvss_v3_severity,
    epss_score, epss_percentile, in_kev, kev_date_added,
    affected_products_json, affected_versions,
    cpe_matches_json, technique_ids_json, kill_chain_phase,
    poc_in_github, nuclei_template_exists,
    metasploit_module_exists, references_json,
    published_date, last_modified, source
) VALUES (
    :cve_id, :description, :cvss_v3_score, :cvss_v3_severity,
    :epss_score, :epss_percentile, :in_kev, :kev_date_added,
    :affected_products_json, :affected_versions,
    :cpe_matches_json, :technique_ids_json, :kill_chain_phase,
    :poc_in_github, :nuclei_template_exists,
    :metasploit_module_exists, :references_json,
    :published_date, :last_modified, :source
)
ON CONFLICT(cve_id) DO UPDATE SET
    cvss_v3_score=excluded.cvss_v3_score,
    cvss_v3_severity=excluded.cvss_v3_severity,
    epss_score=excluded.epss_score,
    epss_percentile=excluded.epss_percentile,
    in_kev=excluded.in_kev,
    kev_date_added=excluded.kev_date_added,
    poc_in_github=excluded.poc_in_github,
    nuclei_template_exists=excluded.nuclei_template_exists,
    last_modified=excluded.last_modified,
    updated_at=datetime('now')
''', entry)

    def upsert_abuse(self, entry: dict):
        with self._conn() as conn:
            conn.execute('''
INSERT INTO abuse_patterns (
    abuse_id, name, source, category,
    cloud_providers_json,
    affected_terraform_resources_json,
    description, kill_chain_phase,
    technique_id, technique_name,
    exploitation_difficulty,
    exploitation_commands_json,
    detection_gap, cloudtrail_logged,
    guardduty_finding, remediation,
    references_json, cvss_equivalent
) VALUES (
    :abuse_id, :name, :source, :category,
    :cloud_providers_json,
    :affected_terraform_resources_json,
    :description, :kill_chain_phase,
    :technique_id, :technique_name,
    :exploitation_difficulty,
    :exploitation_commands_json,
    :detection_gap, :cloudtrail_logged,
    :guardduty_finding, :remediation,
    :references_json, :cvss_equivalent
)
ON CONFLICT(abuse_id) DO UPDATE SET
    description=excluded.description,
    exploitation_commands_json=excluded.exploitation_commands_json,
    updated_at=datetime('now')
''', entry)

    def index_cve_for_resource(
        self,
        resource_type: str,
        cve_id: str,
        software_keyword: str,
    ):
        with self._conn() as conn:
            conn.execute('''
INSERT OR IGNORE INTO resource_type_cve_index
    (resource_type, cve_id, software_keyword)
VALUES (?, ?, ?)
''', (resource_type, cve_id, software_keyword))

    def get_cves_for_resource(
        self,
        resource_type: str,
        software: str = '',
        version: str = '',
        min_cvss: float = 6.0,
        limit: int = 20,
    ) -> list[CVEEntry]:
        with self._conn() as conn:
            if software:
                rows = conn.execute('''
SELECT c.* FROM cves c
JOIN resource_type_cve_index i ON c.cve_id = i.cve_id
WHERE i.resource_type = ?
  AND (i.software_keyword = '' OR i.software_keyword LIKE ?)
  AND c.cvss_v3_score >= ?
ORDER BY c.in_kev DESC, c.epss_score DESC,
         c.cvss_v3_score DESC
LIMIT ?
''', (resource_type, f'%{software.lower()}%',
      min_cvss, limit)).fetchall()
            else:
                rows = conn.execute('''
SELECT c.* FROM cves c
JOIN resource_type_cve_index i ON c.cve_id = i.cve_id
WHERE i.resource_type = ?
  AND c.cvss_v3_score >= ?
ORDER BY c.in_kev DESC, c.epss_score DESC,
         c.cvss_v3_score DESC
LIMIT ?
''', (resource_type, min_cvss, limit)).fetchall()
        return [self._row_to_cve(r) for r in rows]

    def get_abuse_patterns_for_resource(
        self, resource_type: str
    ) -> list[AbusePattern]:
        with self._conn() as conn:
            rows = conn.execute('''
SELECT * FROM abuse_patterns
WHERE affected_terraform_resources_json LIKE ?
ORDER BY cvss_equivalent DESC
''', (f'%{resource_type}%',)).fetchall()
        return [self._row_to_abuse(r) for r in rows]

    def get_kev_entries(self) -> list[CVEEntry]:
        with self._conn() as conn:
            rows = conn.execute('''
SELECT * FROM cves WHERE in_kev = 1
ORDER BY epss_score DESC
''').fetchall()
        return [self._row_to_cve(r) for r in rows]

    def get_sync_state(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute(
                'SELECT * FROM sync_state'
            ).fetchall()
        return {r['source']: dict(r) for r in rows}

    def update_sync_state(
        self,
        source: str,
        record_count: int,
    ):
        with self._conn() as conn:
            conn.execute('''
INSERT INTO sync_state (source, last_sync, record_count)
VALUES (?, datetime('now'), ?)
ON CONFLICT(source) DO UPDATE SET
    last_sync=datetime('now'),
    record_count=?
''', (source, record_count, record_count))

    def _row_to_cve(self, row) -> CVEEntry:
        return CVEEntry(
            cve_id=row['cve_id'],
            description=row['description'] or '',
            cvss_v3_score=row['cvss_v3_score'] or 0.0,
            cvss_v3_severity=row['cvss_v3_severity'] or 'UNKNOWN',
            epss_score=row['epss_score'] or 0.0,
            epss_percentile=row['epss_percentile'] or 0.0,
            in_kev=bool(row['in_kev']),
            kev_date_added=row['kev_date_added'],
            affected_products=json.loads(
                row['affected_products_json'] or '[]'
            ),
            affected_versions=row['affected_versions'] or '',
            cpe_matches=json.loads(
                row['cpe_matches_json'] or '[]'
            ),
            technique_ids=json.loads(
                row['technique_ids_json'] or '[]'
            ),
            kill_chain_phase=row['kill_chain_phase'] or '',
            poc_in_github=bool(row['poc_in_github']),
            nuclei_template_exists=bool(
                row['nuclei_template_exists']
            ),
            metasploit_module_exists=bool(
                row['metasploit_module_exists']
            ),
            references=json.loads(
                row['references_json'] or '[]'
            ),
            published_date=row['published_date'] or '',
            last_modified=row['last_modified'] or '',
            source=row['source'] or 'NVD',
        )

    def _row_to_abuse(self, row) -> AbusePattern:
        return AbusePattern(
            abuse_id=row['abuse_id'],
            name=row['name'] or '',
            source=row['source'] or '',
            category=row['category'] or '',
            cloud_providers=json.loads(
                row['cloud_providers_json'] or '[]'
            ),
            affected_terraform_resources=json.loads(
                row['affected_terraform_resources_json'] or '[]'
            ),
            description=row['description'] or '',
            kill_chain_phase=row['kill_chain_phase'] or '',
            technique_id=row['technique_id'] or '',
            technique_name=row['technique_name'] or '',
            exploitation_difficulty=row[
                'exploitation_difficulty'
            ] or 'MEDIUM',
            exploitation_commands=json.loads(
                row['exploitation_commands_json'] or '[]'
            ),
            detection_gap=row['detection_gap'] or '',
            cloudtrail_logged=bool(row['cloudtrail_logged']),
            guardduty_finding=row['guardduty_finding'],
            remediation=row['remediation'] or '',
            references=json.loads(
                row['references_json'] or '[]'
            ),
            cvss_equivalent=row['cvss_equivalent'] or 7.0,
        )
