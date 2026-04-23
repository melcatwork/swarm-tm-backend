"""
Tests for Revised Prompt 1 — cloud_native_attacker persona.

Validates:
- Persona exists and is structured correctly
- Required fields are present and non-trivial
- security_reasoning_approach covers all five reasoning domains
- Prompt builder injects reasoning approach
"""
import pytest
import yaml
import os
from pathlib import Path

PERSONAS_PATH = Path('backend/app/swarm/agents/personas.yaml')


def load_personas() -> dict:
    with open(PERSONAS_PATH) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def get_cloud_native_attacker() -> dict:
    personas = load_personas()
    return personas.get('cloud_native_attacker')


class TestPersonaExists:

    def test_personas_file_exists(self):
        assert PERSONAS_PATH.exists(), (
            'personas.yaml not found at '
            f'{PERSONAS_PATH}'
        )

    def test_cloud_native_attacker_exists(self):
        cna = get_cloud_native_attacker()
        assert cna is not None, (
            'cloud_native_attacker persona not found '
            'in personas.yaml — Revised Prompt 1 may '
            'not have run'
        )

    def test_cloud_native_attacker_at_top(self):
        """First persona in YAML should be cloud_native_attacker for priority"""
        personas = load_personas()
        assert personas, 'personas.yaml is empty'
        first_key = next(iter(personas.keys()))
        assert first_key == 'cloud_native_attacker', (
            f'First persona is {first_key} — '
            'cloud_native_attacker should be first for priority ordering'
        )


class TestPersonaRequiredFields:

    def test_has_display_name(self):
        cna = get_cloud_native_attacker()
        assert cna.get('display_name'), 'display_name field is missing or empty'

    def test_has_category(self):
        cna = get_cloud_native_attacker()
        assert cna.get('category') == 'archetype', (
            'category should be "archetype"'
        )

    def test_has_role(self):
        cna = get_cloud_native_attacker()
        role = cna.get('role', '')
        assert len(role) > 20, (
            f'role too short ({len(role)} chars) — '
            'should describe the persona role meaningfully'
        )

    def test_has_goal(self):
        cna = get_cloud_native_attacker()
        goal = cna.get('goal', '')
        assert len(goal) > 50, (
            f'goal too short ({len(goal)} chars) — '
            'should describe objectives clearly'
        )

    def test_has_backstory(self):
        cna = get_cloud_native_attacker()
        backstory = cna.get('backstory', '')
        assert len(backstory) > 100, (
            f'backstory too short ({len(backstory)} chars) — '
            'should provide detailed context'
        )

    def test_has_ttp_focus(self):
        cna = get_cloud_native_attacker()
        ttps = cna.get('ttp_focus', [])
        assert len(ttps) >= 10, (
            f'ttp_focus list has only {len(ttps)} entries — '
            'cloud_native_attacker should have broad '
            'ATT&CK coverage (>=10 techniques)'
        )

    def test_ttps_are_valid_attck_format(self):
        import re
        cna = get_cloud_native_attacker()
        pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
        for ttp in cna.get('ttp_focus', []):
            assert pattern.match(ttp), (
                f'TTP {ttp!r} is not a valid ATT&CK '
                'technique ID format (T####.###)'
            )

    def test_has_security_reasoning_approach(self):
        cna = get_cloud_native_attacker()
        approach = cna.get('security_reasoning_approach', '')
        assert len(approach) > 300, (
            f'security_reasoning_approach is only '
            f'{len(approach)} chars — must be substantive '
            'reasoning guidance'
        )

    def test_has_operational_style(self):
        cna = get_cloud_native_attacker()
        style = cna.get('operational_style', '')
        assert len(style) > 100, (
            'operational_style is too short — '
            'should describe attacker decision philosophy'
        )

    def test_is_protected_and_enabled(self):
        cna = get_cloud_native_attacker()
        assert cna.get('protected') is True, (
            'protected should be true for default personas'
        )
        assert cna.get('enabled') is True, (
            'enabled should be true so persona runs by default'
        )


class TestReasoningApproachQuality:

    def test_approach_mentions_identity_or_iam(self):
        cna = get_cloud_native_attacker()
        approach = cna.get(
            'security_reasoning_approach', ''
        ).lower()
        assert any(kw in approach for kw in [
            'identity', 'iam', 'permission', 'role',
            'credential', 'access'
        ]), (
            'reasoning approach does not mention identity '
            'or permission concepts'
        )

    def test_approach_mentions_storage(self):
        cna = get_cloud_native_attacker()
        approach = cna.get(
            'security_reasoning_approach', ''
        ).lower()
        assert any(kw in approach for kw in [
            'storage', 'bucket', 'data', 'object'
        ]), (
            'reasoning approach does not mention '
            'storage security concepts'
        )

    def test_approach_mentions_logging_or_detection(self):
        cna = get_cloud_native_attacker()
        approach = cna.get(
            'security_reasoning_approach', ''
        ).lower()
        assert any(kw in approach for kw in [
            'log', 'audit', 'monitor', 'detect', 'trail',
            'invisible', 'undetect'
        ]), (
            'reasoning approach does not mention logging '
            'or detection gap concepts'
        )

    def test_approach_mentions_relationships_or_chains(self):
        cna = get_cloud_native_attacker()
        approach = cna.get(
            'security_reasoning_approach', ''
        ).lower()
        assert any(kw in approach for kw in [
            'chain', 'combination', 'relationship',
            'together', 'path', 'lateral', 'pivot'
        ]), (
            'reasoning approach does not reason about '
            'cross-resource attack chains'
        )

    def test_approach_is_generalisable(self):
        cna = get_cloud_native_attacker()
        approach = cna.get('security_reasoning_approach', '')
        # Approach should describe reasoning patterns,
        # not just AWS-specific checks
        # Must contain question words indicating open reasoning
        question_indicators = [
            'what', 'how', 'which', 'whether',
            'does', 'can', 'would', 'ask'
        ]
        approach_lower = approach.lower()
        found = [
            q for q in question_indicators
            if q in approach_lower
        ]
        assert len(found) >= 3, (
            'reasoning approach contains fewer than 3 '
            'question-oriented words — it may be a checklist '
            'rather than a reasoning framework'
        )


class TestPersonaIntegration:

    def test_cloud_native_attacker_in_selector(self):
        """persona_selector should reference cloud_native_attacker"""
        selector_path = Path(
            'backend/app/swarm/persona_selector.py'
        )
        assert selector_path.exists(), (
            'persona_selector.py not found — '
            'Revised Prompt 2 may not have run'
        )
        content = selector_path.read_text()
        assert 'cloud_native_attacker' in content, (
            'persona_selector.py does not reference '
            'cloud_native_attacker — injection will not work'
        )

    def test_prompt_builder_injects_reasoning_approach(self):
        """Prompt builder must inject security_reasoning_approach"""
        import glob
        py_files = glob.glob(
            'backend/app/swarm/**/*.py', recursive=True
        )
        found = False
        for filepath in py_files:
            if 'test_' in filepath or '__pycache__' in filepath:
                continue
            try:
                content = open(filepath).read()
                if ('security_reasoning_approach' in content
                        and ('prompt' in content.lower()
                             or 'backstory' in content.lower())):
                    found = True
                    break
            except Exception:
                continue
        assert found, (
            'No file found that injects '
            'security_reasoning_approach into a prompt. '
            'Revised Prompt 1 Task 4 (prompt builder update) '
            'may not have been applied.'
        )
