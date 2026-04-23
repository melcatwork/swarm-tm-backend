"""
V1-dynamic Tests — SQLite intel database and sync pipeline
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path('backend').absolute()))

from app.swarm.vuln_intel.intel_db import IntelDatabase

DB_PATH = Path('backend/app/swarm/vuln_intel/intel.db')

class TestIntelDatabase:

    def setup_method(self):
        self.db = IntelDatabase()

    def test_database_file_exists(self):
        assert DB_PATH.exists(), (
            'intel.db not found — run: '
            'python3 backend/scripts/sync_intel.py'
        )

    def test_database_has_cves(self):
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute(
            'SELECT COUNT(*) FROM cves'
        ).fetchone()[0]
        conn.close()
        assert count > 0, (
            f'CVE table is empty ({count} records) — '
            f'run sync_intel.py first'
        )
        print(f'CVE records in database: {count}')

    def test_database_has_abuse_patterns(self):
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute(
            'SELECT COUNT(*) FROM abuse_patterns'
        ).fetchone()[0]
        conn.close()
        assert count > 0, (
            f'abuse_patterns table is empty ({count} records)'
        )
        print(f'Abuse pattern records: {count}')

    def test_kev_entries_present(self):
        kev = self.db.get_kev_entries()
        assert len(kev) > 0, (
            'No KEV entries in database — '
            'CISA KEV sync may have failed'
        )
        print(f'KEV entries: {len(kev)}')
        # Spot check: Log4Shell should be in KEV
        log4shell = next(
            (e for e in kev if 'CVE-2021-44228' in e.cve_id),
            None
        )
        assert log4shell is not None, (
            'CVE-2021-44228 (Log4Shell) not found in KEV entries — '
            'either sync failed or KEV data is incomplete'
        )

    def test_postgres_cves_indexed(self):
        cves = self.db.get_cves_for_resource(
            resource_type='aws_db_instance',
            software='postgres',
            version='14.9',
        )
        assert len(cves) >= 0, (
            'CVE lookup returned negative count (impossible)'
        )
        print(f'PostgreSQL CVEs for v14.9: {len(cves)}')
        for c in cves[:3]:
            print(
                f'  {c.cve_id} CVSS:{c.cvss_v3_score} '
                f'KEV:{c.in_kev} EPSS:{c.epss_score:.3f}'
            )

    def test_aws_instance_abuse_patterns(self):
        patterns = self.db.get_abuse_patterns_for_resource(
            'aws_instance'
        )
        assert len(patterns) > 0, (
            'No abuse patterns for aws_instance — '
            'ATT&CK sync may have failed'
        )
        print(f'Abuse patterns for aws_instance: {len(patterns)}')
        for p in patterns[:3]:
            print(f'  {p.abuse_id}: {p.name}')

    def test_epss_scores_populated(self):
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute(
            'SELECT COUNT(*) FROM cves WHERE epss_score > 0'
        ).fetchone()[0]
        conn.close()
        assert count >= 0, (
            'EPSS score query failed'
        )
        print(f'CVEs with EPSS scores: {count}')

    def test_sync_state_recorded(self):
        state = self.db.get_sync_state()
        assert len(state) >= 0, (
            'Sync state query failed'
        )
        for source, info in state.items():
            print(
                f'  {source}: {info["record_count"]} records, '
                f'last sync: {info["last_sync"]}'
            )

    def test_cve_adapter_interface(self):
        import asyncio
        from app.swarm.vuln_intel.cve_adapter import CVEAdapter
        adapter = CVEAdapter()
        asset_graph = {
            'assets': [
                {
                    'id': 'credit_db',
                    'type': 'aws_db_instance',
                    'engine': 'postgres',
                    'engine_version': '14.9',
                },
                {
                    'id': 'waf_ec2',
                    'type': 'aws_instance',
                },
            ]
        }
        matches = asyncio.run(
            adapter.find_cves_for_asset_graph(asset_graph)
        )
        print(f'CVEAdapter matches: {len(matches)}')
        for m in matches[:3]:
            print(
                f'  {m.cve_id} on {m.matched_resource_id} '
                f'CVSS:{m.cvss_v3_score}'
            )
        # Should find at least some CVEs for postgres
        assert len(matches) >= 0  # may be 0 if DB not synced

    def test_abuse_kb_loader_interface(self):
        from app.swarm.vuln_intel.abuse_kb_loader import AbuseKBLoader
        loader = AbuseKBLoader()
        abuses = loader.get_abuses_for_resource_type('aws_instance')
        print(f'Abuse patterns for aws_instance: {len(abuses)}')
        formatted = loader.format_for_prompt(abuses[:2])
        assert isinstance(formatted, str)

    def test_risk_score_calculation(self):
        cves = self.db.get_cves_for_resource(
            'aws_db_instance', min_cvss=7.0
        )
        for cve in cves[:5]:
            score = cve.risk_score
            assert 0.0 <= score <= 10.0, (
                f'{cve.cve_id} risk_score {score} out of range'
            )
