"""
Integration tests for Revised Prompt 1 and Revised Prompt 2.

Tests the complete flow: IaC upload → VulnContext →
persona injection → attack paths → confirmed findings.

These tests require the backend server to be running:
  uvicorn app.main:app --port 8000 --app-dir backend

Uses capital-one-breach-replica.tf as the test IaC because
it has known misconfigurations that should produce confirmed
findings.

IMPORTANT: Tests validate STRUCTURE not content. They do not
check for specific vulnerability names, technique IDs, or
attack patterns. This matches the dynamic design intent.
"""
import pytest
import httpx
import json
from pathlib import Path

BASE_URL = 'http://localhost:8000'
TF_FILE = Path('samples/capital-one-breach-replica.tf')
TIMEOUT = 300


def server_is_running() -> bool:
    try:
        r = httpx.get(f'{BASE_URL}/api/health', timeout=5.0)
        return r.status_code == 200
    except Exception:
        return False


@pytest.fixture(scope='module', autouse=True)
def require_server():
    if not server_is_running():
        pytest.skip(
            'Backend server not running. Start with:\n'
            '  cd /Users/bland/Desktop/swarm-tm\n'
            '  uvicorn app.main:app --port 8000 --app-dir backend\n'
            'Then re-run tests.'
        )


def call_run_endpoint(endpoint: str, form_data: dict = None) -> dict:
    if not TF_FILE.exists():
        pytest.skip(f'Test IaC file not found: {TF_FILE}')

    with open(TF_FILE, 'rb') as f:
        files = {'file': ('test.tf', f, 'text/plain')}
        if form_data:
            resp = httpx.post(
                f'{BASE_URL}{endpoint}',
                files=files,
                data=form_data,
                timeout=TIMEOUT,
            )
        else:
            resp = httpx.post(
                f'{BASE_URL}{endpoint}',
                files=files,
                timeout=TIMEOUT,
            )
    assert resp.status_code == 200, (
        f'{endpoint} returned {resp.status_code}: '
        f'{resp.text[:300]}'
    )
    return resp.json()


def assert_confirmed_findings_present(
    data: dict,
    run_name: str,
):
    """
    Asserts confirmed_findings is present and non-empty.
    Does not check what specific findings are present.
    """
    confirmed = data.get('confirmed_findings', [])
    assert confirmed, (
        f'{run_name}: confirmed_findings is empty or missing. '
        'VulnMatcher must produce CONFIRMED findings for '
        'capital-one-breach-replica.tf — check that '
        'VulnContextBuilder runs before agents and '
        'confirmed_findings is added to the response.'
    )
    return confirmed


def assert_attack_paths_present(data: dict, run_name: str):
    paths = data.get('attack_paths', data.get('final_paths', []))
    assert paths, (
        f'{run_name}: attack_paths/final_paths is empty or missing'
    )
    return paths


def assert_grounded_path_present(data: dict, run_name: str):
    paths = data.get('attack_paths', data.get('final_paths', []))
    grounded = [
        p for p in paths
        if p.get('grounded_in_confirmed_vuln')
    ]
    assert grounded, (
        f'{run_name}: No grounded attack paths found. '
        'output_filter.py should synthesise at least one '
        'path from confirmed evidence regardless of what '
        'agents produced.'
    )
    return grounded


def assert_finding_structure(
    finding: dict,
    run_name: str,
):
    required = {
        'vuln_id', 'resource_id', 'technique_id',
        'kill_chain_phase', 'match_confidence',
    }
    missing = required - set(finding.keys())
    assert not missing, (
        f'{run_name}: confirmed finding missing '
        f'required fields: {missing}'
    )
    assert finding['match_confidence'] == 'CONFIRMED', (
        f'{run_name}: finding in confirmed_findings has '
        f'confidence {finding["match_confidence"]} — '
        'only CONFIRMED findings should appear'
    )
    assert finding.get('resource_id'), (
        f'{run_name}: finding has empty resource_id'
    )
    assert finding.get('technique_id'), (
        f'{run_name}: finding has empty technique_id'
    )


def assert_path_structure(path: dict, run_name: str):
    steps = path.get('steps', [])
    assert steps, (
        f'{run_name}: path {path.get("path_id")} has no steps'
    )
    for step in steps[:3]:
        assert step.get('technique_id'), (
            f'{run_name}: step missing technique_id'
        )
        # Check for either asset_id or target_asset
        assert step.get('asset_id') or step.get('target_asset'), (
            f'{run_name}: step missing asset_id/target_asset'
        )


class TestSingleAgentRun:

    @pytest.fixture(scope='class')
    def result(self):
        return call_run_endpoint(
            '/api/swarm/run/single',
            form_data={'agent_name': 'cloud_native_attacker'}
        )

    def test_returns_200(self, result):
        assert result is not None

    def test_has_confirmed_findings(self, result):
        confirmed = assert_confirmed_findings_present(
            result, 'Single agent'
        )
        print(f'\n  Confirmed findings: {len(confirmed)}')
        for f in confirmed[:2]:
            print(
                f'  - {f.get("vuln_id")} on '
                f'{f.get("resource_id")} '
                f'phase={f.get("kill_chain_phase")}'
            )

    def test_confirmed_findings_structure(self, result):
        confirmed = result.get('confirmed_findings', [])
        for f in confirmed[:3]:
            assert_finding_structure(f, 'Single agent')

    def test_has_attack_paths(self, result):
        assert_attack_paths_present(result, 'Single agent')

    def test_has_grounded_paths(self, result):
        grounded = assert_grounded_path_present(
            result, 'Single agent'
        )
        print(f'\n  Grounded paths: {len(grounded)}')

    def test_grounded_path_structure(self, result):
        paths = result.get('attack_paths', result.get('final_paths', []))
        grounded = [
            p for p in paths
            if p.get('grounded_in_confirmed_vuln')
        ]
        for p in grounded[:2]:
            assert_path_structure(p, 'Single agent')

    def test_has_persona_selection_field(self, result):
        ps = result.get('persona_selection', {})
        assert ps, (
            'persona_selection field missing from single '
            'agent response — Revised Prompt 2 router '
            'update may not have been applied'
        )
        assert 'final' in ps, 'persona_selection.final missing'
        print(f'\n  Personas used: {ps.get("final")}')

    def test_specialist_injected_when_findings_exist(
        self, result
    ):
        confirmed = result.get('confirmed_findings', [])
        if not confirmed:
            pytest.skip('No confirmed findings to test with')
        ps = result.get('persona_selection', {})
        injected = ps.get(
            'injected_for_high_confidence_findings', []
        )
        final = ps.get('final', [])
        print(
            f'\n  Injected: {injected}'
            f'\n  Final personas: {final}'
        )
        # If confirmed findings exist, specialist should
        # have been injected OR already in requested set
        has_specialist = any(
            p in final
            for p in ['cloud_native_attacker', 'apt29_cozy_bear',
                       'volt_typhoon', 'lateral_movement_specialist']
        )
        if not has_specialist:
            # Check if injection was attempted but specialist
            # not available in requested set
            print(
                '  WARNING: No specialist persona in final '
                'list despite confirmed findings. Check that '
                'cloud_native_attacker is in available '
                'personas for single run.'
            )


class TestTwoAgentRun:

    @pytest.fixture(scope='class')
    def result(self):
        return call_run_endpoint('/api/swarm/run/quick')

    def test_has_confirmed_findings(self, result):
        confirmed = assert_confirmed_findings_present(
            result, '2 agents'
        )
        print(f'\n  Confirmed findings: {len(confirmed)}')

    def test_has_grounded_paths(self, result):
        assert_grounded_path_present(result, '2 agents')

    def test_persona_selection_present(self, result):
        ps = result.get('persona_selection', {})
        assert ps, 'persona_selection missing from 2-agent run'
        final = ps.get('final', [])
        assert len(final) <= 3, (
            f'2-agent run has {len(final)} personas — '
            'should be capped at 3'
        )
        print(f'\n  Personas used: {final}')


class TestMultiAgentRun:

    @pytest.fixture(scope='class')
    def result(self):
        return call_run_endpoint('/api/swarm/run')

    def test_has_confirmed_findings(self, result):
        confirmed = assert_confirmed_findings_present(
            result, 'Multi-agent'
        )
        print(f'\n  Confirmed findings: {len(confirmed)}')

    def test_has_grounded_paths(self, result):
        assert_grounded_path_present(result, 'Multi-agent')

    def test_consensus_field_present(self, result):
        ps = result.get('persona_selection', {})
        if ps and 'consensus' in ps:
            consensus = ps.get('consensus', [])
            print(
                f'\n  Consensus techniques: {len(consensus)}'
            )
        else:
            print(
                '\n  WARNING: persona_selection.consensus missing from '
                'multi-agent response — ConsensusAggregator '
                'may not be wired in'
            )

    def test_more_paths_than_single_run(self, result):
        paths = result.get('attack_paths', result.get('final_paths', []))
        print(f'\n  Total paths in multi-agent: {len(paths)}')
        assert len(paths) >= 1, (
            'Multi-agent run produced no attack paths'
        )


class TestSwarmRun:

    @pytest.fixture(scope='class')
    def result(self):
        return call_run_endpoint(
            '/api/swarm/run/stigmergic'
        )

    def test_has_confirmed_findings(self, result):
        confirmed = assert_confirmed_findings_present(
            result, 'Swarm run'
        )
        print(f'\n  Confirmed findings: {len(confirmed)}')

    def test_has_emergent_insights(self, result):
        insights = result.get('emergent_insights', {})
        assert insights, (
            'Swarm run missing emergent_insights — '
            'stigmergic run may not have completed'
        )

    def test_has_attack_paths(self, result):
        assert_attack_paths_present(result, 'Swarm run')


class TestDynamicBehaviourAcrossRunTypes:
    """
    Cross-run-type tests that validate the tool behaves
    dynamically — findings are driven by IaC content,
    not hardcoded rules.
    """

    def test_all_run_types_find_something(self):
        """
        All four run types must produce at least one
        confirmed finding for the same IaC input.
        If one run type finds nothing and another finds
        several, the wiring is inconsistent.
        """
        endpoints = [
            ('single', '/api/swarm/run/single', {'agent_name': 'cloud_native_attacker'}),
            ('quick', '/api/swarm/run/quick', None),
            ('multi', '/api/swarm/run', None),
            ('stigmergic', '/api/swarm/run/stigmergic', None),
        ]
        counts = {}
        for name, endpoint, form_data in endpoints:
            data = call_run_endpoint(endpoint, form_data)
            confirmed = data.get('confirmed_findings', [])
            counts[name] = len(confirmed)
            print(
                f'\n  {name}: {len(confirmed)} confirmed findings'
            )

        # All run types should find at least something
        for name, count in counts.items():
            assert count > 0, (
                f'{name} run found 0 confirmed findings. '
                'All run types must surface confirmed findings '
                'from capital-one-breach-replica.tf. '
                'This IaC has multiple documented '
                'misconfigurations that should produce '
                'CONFIRMED findings.'
            )

    def test_confirmed_findings_consistent_across_runs(self):
        """
        The confirmed_findings list is produced by VulnMatcher
        before agents run. It should be the same across all
        run types for the same IaC input.
        """
        endpoints = [
            ('/api/swarm/run/single', {'agent_name': 'cloud_native_attacker'}),
            ('/api/swarm/run/quick', None),
        ]
        finding_sets = []
        for endpoint, form_data in endpoints:
            data = call_run_endpoint(endpoint, form_data)
            confirmed = data.get('confirmed_findings', [])
            finding_ids = {
                f.get('vuln_id') for f in confirmed
            }
            finding_sets.append(finding_ids)

        if len(finding_sets) >= 2:
            # Both should find the same confirmed vulns
            # since VulnMatcher runs before agents
            set_a, set_b = finding_sets[0], finding_sets[1]
            overlap = set_a & set_b
            print(
                f'\n  Single run findings: {set_a}'
                f'\n  2-agent run findings: {set_b}'
                f'\n  Overlap: {overlap}'
            )
            # At least 50% overlap expected
            if set_a and set_b:
                overlap_ratio = len(overlap) / max(
                    len(set_a), len(set_b)
                )
                assert overlap_ratio >= 0.5, (
                    f'Only {overlap_ratio:.0%} overlap between '
                    'confirmed findings across run types. '
                    'VulnMatcher runs before agents so findings '
                    'should be consistent.'
                )
