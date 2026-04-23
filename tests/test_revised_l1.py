"""
Revised L1 Tests — Persona reasoning instructions
Verifies that personas have open-ended security_reasoning_approach
fields and that the prompt builder injects them correctly.
"""
import pytest
import yaml
from pathlib import Path

PERSONAS_PATH = Path('backend/app/swarm/agents/personas.yaml')

def load_personas():
    with open(PERSONAS_PATH) as f:
        data = yaml.safe_load(f)
    return data.get('personas', data) if isinstance(
        data, dict
    ) else data

class TestRevisedL1PersonaStructure:

    def test_personas_file_exists(self):
        assert PERSONAS_PATH.exists(), (
            'personas.yaml not found'
        )

    def test_all_personas_have_reasoning_approach(self):
        personas = load_personas()
        missing = []
        for p_id, p in personas.items():
            if not p.get('security_reasoning_approach'):
                missing.append(p_id)
        assert not missing, (
            f'Personas missing security_reasoning_approach: '
            f'{missing}'
        )

    def test_reasoning_approach_not_empty(self):
        personas = load_personas()
        for p_id, p in personas.items():
            approach = p.get('security_reasoning_approach', '')
            assert len(approach) > 100, (
                f'Persona {p_id} has trivially short '
                f'security_reasoning_approach: {len(approach)} chars'
            )

    def test_no_hard_coded_signal_lists_in_personas(self):
        personas = load_personas()
        for p_id, p in personas.items():
            # Old field should be gone
            assert 'iac_signal_to_attack_chain' not in p, (
                f'Persona {p_id} still has old '
                f'iac_signal_to_attack_chain field — '
                f'Revised L1 did not remove it'
            )

    def test_cloud_native_attacker_has_iam_reasoning(self):
        personas = load_personas()
        cloud_native = personas.get('cloud_native_attacker')
        assert cloud_native is not None, (
            'cloud_native_attacker persona not found'
        )
        approach = cloud_native.get(
            'security_reasoning_approach', ''
        ).lower()
        assert 'iam' in approach, (
            'cloud_native_attacker reasoning approach '
            'does not mention IAM'
        )

    def test_prompt_builder_uses_reasoning_approach(self):
        # Find the prompt builder function and verify it
        # reads security_reasoning_approach not a signal list
        import os
        prompt_builder_files = []
        for root, dirs, files in os.walk('backend/app/swarm'):
            for f in files:
                if f.endswith('.py'):
                    prompt_builder_files.append(
                        os.path.join(root, f)
                    )
        found_injection = False
        for filepath in prompt_builder_files:
            try:
                content = open(filepath).read()
                if ('security_reasoning_approach' in content
                        and 'prompt' in content.lower()):
                    found_injection = True
                    break
            except Exception:
                continue
        assert found_injection, (
            'No file found that injects security_reasoning_approach '
            'into a prompt — Revised L1 prompt builder update '
            'may not have been applied'
        )

    def test_no_hard_coded_signal_injection_in_prompt_builder(self):
        import os
        for root, dirs, files in os.walk('backend/app/swarm'):
            for f in files:
                if not f.endswith('.py'):
                    continue
                filepath = os.path.join(root, f)
                if 'test_' in f:
                    continue
                content = open(filepath).read()
                # Old pattern: injecting a list of named signals
                # as pre-determined findings into agent prompts
                bad_patterns = [
                    'IMDS_V1_ENABLED\\n',
                    'IAM_S3_WILDCARD\\n',
                    'signal_list =',
                    'hardcoded_signals',
                ]
                for pattern in bad_patterns:
                    assert pattern not in content, (
                        f'{filepath} still contains hard-coded '
                        f'signal pattern: {pattern!r}'
                    )
