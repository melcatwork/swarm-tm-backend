"""
Integration tests verifying all four run type API responses
return attack paths with up to 10 steps without truncation.

Requires server running on localhost:8000.
Uses capital-one-breach-replica.tf and
scarleteel-breach-replica.tf as test inputs.
"""
import pytest
import httpx
import json
from pathlib import Path

BASE_URL = 'http://localhost:8000'
TIMEOUT = 300
TF_FILES = {
    'capital_one': Path(__file__).parent.parent / 'samples' / 'capital-one-breach-replica.tf',
    'scarleteel': Path(__file__).parent.parent / 'samples' / 'scarleteel-breach-replica.tf',
}


def server_is_running() -> bool:
    try:
        return httpx.get(
            f'{BASE_URL}/api/health', timeout=5.0
        ).status_code == 200
    except Exception:
        return False


@pytest.fixture(scope='module', autouse=True)
def require_server():
    if not server_is_running():
        pytest.skip(
            'Start server: uvicorn app.main:app --port 8000'
        )


def post_iac(endpoint: str, tf_path: Path) -> dict:
    with open(tf_path, 'rb') as f:
        resp = httpx.post(
            f'{BASE_URL}{endpoint}',
            files={'file': (tf_path.name, f, 'text/plain')},
            timeout=TIMEOUT,
        )
    assert resp.status_code == 200
    return resp.json()


def get_longest_path(data: dict) -> dict | None:
    # Check multiple possible keys for attack paths
    paths = (
        data.get('attack_paths', []) or
        data.get('final_paths', []) or
        []
    )
    if not paths:
        return None
    return max(paths, key=lambda p: len(p.get('steps', [])))


def assert_path_steps_valid(
    path: dict,
    run_name: str,
    tf_name: str,
):
    steps = path.get('steps', [])
    assert steps, f'{run_name}/{tf_name}: path has no steps'
    for i, step in enumerate(steps, 1):
        assert step.get('technique_id'), (
            f'{run_name}/{tf_name}: step {i} missing technique_id'
        )
        assert step.get('asset_id') or step.get('target_asset') or step.get('resource_id'), (
            f'{run_name}/{tf_name}: step {i} missing asset_id'
        )
        assert step.get('kill_chain_phase'), (
            f'{run_name}/{tf_name}: step {i} missing phase'
        )
        assert step.get('step_number') == i, (
            f'{run_name}/{tf_name}: step {i} has wrong number '
            f'{step.get("step_number")}'
        )


@pytest.mark.parametrize(
    'tf_key', ['capital_one', 'scarleteel']
)
@pytest.mark.parametrize(
    'endpoint,run_name',
    [
        ('/api/swarm/run/single', 'single'),
        ('/api/swarm/run/quick', 'quick'),
        ('/api/swarm/run', 'full'),
        ('/api/swarm/run/stigmergic', 'swarm'),
    ],
)
class TestLongPathsInAllRunTypes:

    def test_paths_returned(
        self, endpoint, run_name, tf_key
    ):
        tf_path = TF_FILES[tf_key]
        if not tf_path.exists():
            pytest.skip(f'{tf_path} not found')
        data = post_iac(endpoint, tf_path)
        paths = data.get('attack_paths', []) or data.get('final_paths', [])
        assert paths, (
            f'{run_name}/{tf_key}: no attack_paths in response'
        )
        print(f'\n  {run_name}/{tf_key}: {len(paths)} paths')

    def test_longest_path_has_valid_structure(
        self, endpoint, run_name, tf_key
    ):
        tf_path = TF_FILES[tf_key]
        if not tf_path.exists():
            pytest.skip(f'{tf_path} not found')
        data = post_iac(endpoint, tf_path)
        longest = get_longest_path(data)
        if not longest:
            pytest.skip('No paths returned')
        step_count = len(longest.get('steps', []))
        print(
            f'\n  {run_name}/{tf_key}: '
            f'longest path = {step_count} steps'
        )
        assert_path_steps_valid(longest, run_name, tf_key)

    def test_no_path_exceeds_10_steps(
        self, endpoint, run_name, tf_key
    ):
        tf_path = TF_FILES[tf_key]
        if not tf_path.exists():
            pytest.skip(f'{tf_path} not found')
        data = post_iac(endpoint, tf_path)
        paths = data.get('attack_paths', []) or data.get('final_paths', [])
        for path in paths:
            steps = path.get('steps', [])
            assert len(steps) <= 10, (
                f'{run_name}/{tf_key}: path '
                f'{path.get("path_id", path.get("id"))} has {len(steps)} steps'
                ' — exceeds 10 step maximum'
            )

    def test_multi_step_path_phases_are_ordered(
        self, endpoint, run_name, tf_key
    ):
        """
        Steps in a path must be in kill chain phase order.
        A 6-step path must not jump backward in the kill chain.
        """
        PHASE_ORDER = [
            'reconnaissance', 'resource_development',
            'initial_access', 'execution', 'persistence',
            'privilege_escalation', 'defense_evasion',
            'credential_access', 'discovery',
            'lateral_movement', 'collection',
            'exfiltration', 'impact',
        ]

        def phase_index(phase: str) -> int:
            phase_lower = phase.lower()
            try:
                return PHASE_ORDER.index(phase_lower)
            except ValueError:
                # Handle multi-phase steps like "Execution & Persistence"
                for i, p in enumerate(PHASE_ORDER):
                    if p in phase_lower:
                        return i
                return 99

        tf_path = TF_FILES[tf_key]
        if not tf_path.exists():
            pytest.skip(f'{tf_path} not found')
        data = post_iac(endpoint, tf_path)
        paths = data.get('attack_paths', []) or data.get('final_paths', [])
        for path in paths:
            steps = path.get('steps', [])
            if len(steps) < 3:
                continue
            phases = [
                s.get('kill_chain_phase', '') for s in steps
            ]
            indices = [phase_index(p) for p in phases]
            for j in range(1, len(indices)):
                assert indices[j] >= indices[j - 1], (
                    f'{run_name}/{tf_key}: path '
                    f'{path.get("path_id", path.get("id"))} has steps out of '
                    f'kill chain order at position {j}: '
                    f'{phases[j-1]} → {phases[j]}'
                )
