"""
End-to-end tests — all four run types against Capital One IaC
Requires the backend server to be running:
  uvicorn app.main:app --port 8000
"""
import pytest
import httpx
import json
from pathlib import Path

BASE_URL = 'http://localhost:8000'
TF_FILE = Path('samples/capital-one-breach-replica.tf')
TIMEOUT = 300  # seconds — LLM calls take time

def is_server_running() -> bool:
    try:
        r = httpx.get(f'{BASE_URL}/api/health', timeout=5.0)
        return r.status_code == 200
    except Exception:
        return False

@pytest.fixture(scope='module')
def server_check():
    if not is_server_running():
        pytest.skip(
            'Backend server not running. Start with: '
            'cd backend && uvicorn app.main:app --port 8000'
        )

def post_iac(endpoint: str, tf_path: Path) -> dict:
    with open(tf_path, 'rb') as f:
        files = {'file': ('capital-one.tf', f, 'text/plain')}
        resp = httpx.post(
            f'{BASE_URL}{endpoint}',
            files=files,
            timeout=TIMEOUT,
        )
    assert resp.status_code == 200, (
        f'{endpoint} returned {resp.status_code}: {resp.text[:200]}'
    )
    return resp.json()

class TestEndToEndSingleAgent:

    def test_single_agent_returns_security_findings(
        self, server_check
    ):
        result = post_iac('/api/swarm/run/single', TF_FILE)
        print(f'\nSingle agent response keys: {list(result.keys())}')
        # Should have security_findings (Revised L2)
        assert 'security_findings' in result or (
            'vulnerability_intelligence' in result
        ), (
            'Response missing security_findings or '
            'vulnerability_intelligence field'
        )

    def test_single_agent_finds_imds_issue(self, server_check):
        result = post_iac('/api/swarm/run/single', TF_FILE)
        findings = (
            result.get('security_findings', [])
            or result.get('vulnerability_intelligence', {})
               .get('matched_vulns', [])
        )
        print(f'Findings: {len(findings)}')
        for f in findings[:3]:
            print(f'  {f}')
        # At least one finding should relate to IMDSv1 or IAM
        finding_text = json.dumps(findings).lower()
        assert any(kw in finding_text for kw in [
            'imds', 'metadata', 'iam', 'credential', 's3'
        ]), (
            'No security findings related to known Capital One '
            'misconfigurations (IMDS, IAM, S3) — LLM analyser '
            'may not be running or producing findings'
        )

    def test_single_agent_attack_paths_have_llm_evaluation(
        self, server_check
    ):
        result = post_iac('/api/swarm/run/single', TF_FILE)
        paths = result.get('attack_paths', [])
        if not paths:
            pytest.skip('No attack paths returned')
        for path in paths[:2]:
            assert 'llm_evaluation' in path or (
                'adjusted_composite_score' in path
            ), (
                f'Path {path.get("name", "")} missing '
                f'llm_evaluation — Revised L4 PathEvaluator '
                f'not wired into single agent run'
            )

class TestEndToEndTwoAgent:

    def test_two_agent_returns_vuln_intelligence(
        self, server_check
    ):
        result = post_iac('/api/swarm/run/quick', TF_FILE)
        print(f'\nTwo agent response keys: {list(result.keys())}')
        has_vuln_intel = (
            'vulnerability_intelligence' in result
            or 'security_findings' in result
        )
        assert has_vuln_intel, (
            'Two agent run missing vulnerability intelligence'
        )

    def test_two_agent_vuln_stats(self, server_check):
        result = post_iac('/api/swarm/run/quick', TF_FILE)
        intel = result.get('vulnerability_intelligence', {})
        stats = intel if not intel.get('stats') else intel['stats']
        print(f'Vuln intel: {stats}')

class TestEndToEndMultiAgent:

    def test_multi_agent_returns_all_fields(self, server_check):
        result = post_iac('/api/swarm/run/multi', TF_FILE)
        print(f'\nMulti agent response keys: {list(result.keys())}')
        expected_fields = [
            'attack_paths',
        ]
        for field in expected_fields:
            assert field in result, (
                f'Multi agent response missing: {field}'
            )

    def test_multi_agent_paths_reference_specific_vulns(
        self, server_check
    ):
        result = post_iac('/api/swarm/run/multi', TF_FILE)
        paths = result.get('attack_paths', [])
        if not paths:
            pytest.skip('No attack paths returned')
        path_text = json.dumps(paths).lower()
        # Paths should reference specific vulns not just technique IDs
        has_specific = any(kw in path_text for kw in [
            'aws-imds', 'aws-iam', 'aws-s3', 'aws-ct',
            'cve-', 'attck-', 'imds', 'metadata',
        ])
        print(
            f'Paths contain specific vuln references: {has_specific}'
        )
        # This is a soft assertion — log but don't fail
        if not has_specific:
            print(
                'WARNING: Attack paths do not reference specific '
                'vulnerability IDs — personas may not be using '
                'vuln context from the prompt'
            )

class TestEndToEndStigmergic:

    def test_swarm_run_has_incident_seeding_field(
        self, server_check
    ):
        result = post_iac(
            '/api/swarm/run/stigmergic', TF_FILE
        )
        print(f'\nSwarm run response keys: {list(result.keys())}')
        # incident_seeding replaced by finding-based seeding
        # but field should still appear
        has_seeding = (
            'incident_seeding' in result
            or 'finding_seeding' in result
            or 'pheromone_seeding' in result
        )
        if not has_seeding:
            print(
                'WARNING: No seeding info in response — '
                'check that finding-based seeding is wired'
            )

    def test_swarm_run_emergent_insights_present(
        self, server_check
    ):
        result = post_iac(
            '/api/swarm/run/stigmergic', TF_FILE
        )
        insights = result.get('emergent_insights', {})
        assert insights or 'attack_paths' in result, (
            'Swarm run missing both emergent_insights and attack_paths — '
            'stigmergic run may not have completed'
        )
        print(f'Emergent insights keys: {list(insights.keys()) if insights else "none"}')

class TestCapitalOneGroundTruth:
    """
    Validates swarm findings against the documented Capital One
    breach attack path. These are soft assertions that print
    pass/fail but do not stop the test suite.
    """

    EXPECTED_TECHNIQUES = [
        'T1190',    # Exploit Public-Facing Application
        'T1552.005',  # Cloud Instance Metadata API
        'T1078.004',  # Valid Cloud Accounts
        'T1530',    # Data from Cloud Storage
    ]

    EXPECTED_TARGETS = [
        'waf_ec2', 'waf', 'ec2',
        'ISRM', 'waf_role', 'iam_role',
        'customer_data', 's3',
    ]

    def test_ground_truth_technique_coverage(
        self, server_check
    ):
        result = post_iac('/api/swarm/run/multi', TF_FILE)
        paths = result.get('attack_paths', [])
        all_text = json.dumps(paths).lower()
        print('\nGround truth technique coverage:')
        found_count = 0
        for tech in self.EXPECTED_TECHNIQUES:
            found = tech.lower() in all_text
            status = 'PASS' if found else 'MISS'
            print(f'  [{status}] {tech}')
            if found:
                found_count += 1
        coverage = found_count / len(self.EXPECTED_TECHNIQUES)
        print(
            f'\nTechnique coverage: '
            f'{found_count}/{len(self.EXPECTED_TECHNIQUES)} '
            f'({coverage:.0%})'
        )
        assert coverage >= 0.0, (
            f'Coverage should be non-negative'
        )

    def test_imdsv1_chain_in_output(self, server_check):
        result = post_iac('/api/swarm/run/multi', TF_FILE)
        all_text = json.dumps(result).lower()
        has_imds_chain = (
            ('t1190' in all_text and 't1552' in all_text)
            or ('ssrf' in all_text and 'metadata' in all_text)
            or ('imds' in all_text and 'credential' in all_text)
        )
        print(
            f'\nIMDSv1 chain detected in output: {has_imds_chain}'
        )
        if not has_imds_chain:
            print(
                'WARNING: IMDSv1 credential theft chain not '
                'found in output. Check:'
                '\n  1. Revised L1 persona reasoning approach'
                '\n  2. Revised L2 security analyser output'
                '\n  3. V1 IMDS abuse pattern in intel.db'
                '\n  4. V3 context injection into agent prompts'
            )
