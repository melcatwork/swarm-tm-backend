"""Security Analyser using LLM-based dynamic vulnerability detection.

Uses an LLM to dynamically identify misconfigurations and vulnerabilities in
serialised IaC. Finds anything the LLM knows about—not limited to pre-coded conditions.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """
    A security finding discovered by LLM analysis of the IaC.
    Not produced by hard-coded rules—produced by LLM reasoning.
    """
    finding_id: str
    resource_id: str
    resource_type: str
    category: str
    title: str
    description: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    technique_id: str
    technique_name: str
    kill_chain_phase: str
    exploitation_detail: str
    exploitation_commands: List[str]
    detection_gap: str
    affected_relationships: List[str]
    remediation: str
    confidence: str         # HIGH / MEDIUM / LOW
    reasoning: str          # LLM's explanation of why this is an issue


class SecurityAnalyser:
    """
    Uses an LLM to dynamically identify misconfigurations and vulnerabilities
    in serialised IaC. Finds anything the LLM knows about—not limited to
    pre-coded conditions.
    """

    ANALYSIS_SYSTEM_PROMPT = """
You are a senior cloud security architect and penetration tester with deep expertise in AWS, Azure, and GCP security. You have comprehensive knowledge of:

- Cloud service misconfigurations and their exploitation
- IAM privilege escalation techniques
- Instance metadata service abuse patterns
- Storage service access control failures
- Network security group misconfigurations
- Logging and monitoring gaps
- Container and serverless security issues
- Supply chain and CI/CD security risks
- Known CVEs affecting cloud-deployed software
- MITRE ATT&CK for Cloud techniques
- Real-world cloud breach patterns

When given Infrastructure as Code, you identify EVERY security issue present—not just common ones. You reason about:

1. Individual resource misconfigurations
2. Dangerous combinations of resources that are each acceptable alone but dangerous together
3. Missing controls that should be present
4. Version-specific vulnerabilities in deployed software
5. Trust relationships that could be abused
6. Logging gaps that would allow undetected exploitation

You respond ONLY with a JSON array of findings. Each finding follows this exact schema:

{
  "finding_id": "F001",
  "resource_id": "exact resource ID from the IaC",
  "resource_type": "terraform resource type",
  "category": "one of: IAM / NETWORK / STORAGE / COMPUTE / LOGGING / ENCRYPTION / RUNTIME / CONFIGURATION / TRUST / VERSIONING",
  "title": "short descriptive title",
  "description": "what is misconfigured or vulnerable and why it is dangerous",
  "severity": "CRITICAL or HIGH or MEDIUM or LOW",
  "technique_id": "primary ATT&CK technique ID e.g. T1552.005",
  "technique_name": "technique name",
  "kill_chain_phase": "ATT&CK kill chain phase",
  "exploitation_detail": "how an attacker would exploit this in this specific cloud environment",
  "exploitation_commands": ["specific commands if applicable"],
  "detection_gap": "what monitoring would miss this",
  "affected_relationships": ["other resource IDs that compound this risk"],
  "remediation": "specific fix for this configuration",
  "confidence": "HIGH or MEDIUM or LOW",
  "reasoning": "why you identified this as a security issue"
}

Find everything. Do not filter to only well-known issues. A Cognito identity pool with unauthenticated access is as important as an IMDSv1-enabled EC2 instance. An over-permissioned Lambda execution role matters as much as a wildcard S3 policy. Reason about the complete picture.
"""

    def __init__(self, llm_client):
        """
        Initialize the SecurityAnalyser with an LLM client.

        Args:
            llm_client: LLM client instance (same one used by swarm agents)
        """
        self.llm = llm_client

    async def analyse(
        self,
        serialised_iac: str,
        max_findings: int = 30,
    ) -> List[SecurityFinding]:
        """
        Analyse serialised IaC for security issues using LLM reasoning.

        Args:
            serialised_iac: IaC serialised as text by IaCSerialiser
            max_findings: Maximum number of findings to return

        Returns:
            List of SecurityFinding objects discovered by the LLM
        """
        user_prompt = f"""
Analyse the following Infrastructure as Code for all security misconfigurations, vulnerabilities, and attack-enabling conditions.

{serialised_iac}

Respond with a JSON array of findings following the schema in your system prompt. Find at minimum every HIGH and CRITICAL severity issue. Include MEDIUM severity issues where they compound with other findings. Do not limit yourself to well-known checks—use your full security knowledge.

Return ONLY the JSON array with no other text.
"""

        try:
            # Call LLM with system and user prompts
            response = await self._llm_complete(
                system=self.ANALYSIS_SYSTEM_PROMPT,
                user=user_prompt,
                max_tokens=4000,
                temperature=0.2,  # Low temperature for consistency
            )

            return self._parse_findings(response, max_findings)

        except Exception as e:
            logger.error(f"LLM security analysis failed: {e}", exc_info=True)
            return []

    async def _llm_complete(
        self,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """
        Call the LLM with system and user prompts.

        Args:
            system: System prompt
            user: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Returns:
            LLM response text
        """
        # Use the LLM client's call method (CrewAI LLM interface)
        try:
            # CrewAI LLM instances have a call() method
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
            response = self.llm.call(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            raise

    def _parse_findings(
        self,
        response: str,
        max_findings: int,
    ) -> List[SecurityFinding]:
        """
        Parse LLM response into SecurityFinding objects.

        Args:
            response: Raw LLM response text
            max_findings: Maximum findings to return

        Returns:
            List of parsed SecurityFinding objects
        """
        # Extract JSON from response
        text = response.strip()

        # Handle markdown code blocks if present
        if '```' in text:
            match = re.search(
                r'```(?:json)?\s*([\s\S]*?)```', text
            )
            if match:
                text = match.group(1).strip()

        try:
            raw_findings = json.loads(text)
            if not isinstance(raw_findings, list):
                raw_findings = [raw_findings]
        except json.JSONDecodeError:
            # Try to extract array from partial response
            match = re.search(r'\[[\s\S]*\]', text)
            if match:
                try:
                    raw_findings = json.loads(match.group(0))
                except Exception:
                    logger.warning("Failed to parse LLM findings JSON")
                    return []
            else:
                logger.warning("No JSON array found in LLM response")
                return []

        findings = []
        for i, raw in enumerate(raw_findings[:max_findings]):
            try:
                findings.append(SecurityFinding(
                    finding_id=raw.get('finding_id', f'F{i+1:03d}'),
                    resource_id=raw.get('resource_id', ''),
                    resource_type=raw.get('resource_type', ''),
                    category=raw.get('category', 'CONFIGURATION'),
                    title=raw.get('title', ''),
                    description=raw.get('description', ''),
                    severity=raw.get('severity', 'MEDIUM'),
                    technique_id=raw.get('technique_id', ''),
                    technique_name=raw.get('technique_name', ''),
                    kill_chain_phase=raw.get('kill_chain_phase', ''),
                    exploitation_detail=raw.get('exploitation_detail', ''),
                    exploitation_commands=raw.get('exploitation_commands', []),
                    detection_gap=raw.get('detection_gap', ''),
                    affected_relationships=raw.get('affected_relationships', []),
                    remediation=raw.get('remediation', ''),
                    confidence=raw.get('confidence', 'MEDIUM'),
                    reasoning=raw.get('reasoning', ''),
                ))
            except Exception as e:
                logger.warning(f"Failed to parse finding {i}: {e}")
                continue

        logger.info(f"Parsed {len(findings)} security findings from LLM analysis")
        return findings

    def format_for_prompt(
        self,
        findings: List[SecurityFinding],
    ) -> str:
        """
        Format findings as context for agent prompts.

        Args:
            findings: List of SecurityFinding objects

        Returns:
            Formatted text suitable for injection into agent prompts
        """
        if not findings:
            return (
                'SECURITY ANALYSIS: No findings from LLM analysis.'
            )

        critical = [f for f in findings if f.severity == 'CRITICAL']
        high = [f for f in findings if f.severity == 'HIGH']
        medium = [f for f in findings if f.severity == 'MEDIUM']

        lines = [
            f'SECURITY FINDINGS FROM IaC ANALYSIS ({len(findings)} total):',
            '',
        ]

        for group, label in [
            (critical, 'CRITICAL'),
            (high, 'HIGH'),
            (medium, 'MEDIUM'),
        ]:
            if not group:
                continue

            lines.append(f'{label} SEVERITY ({len(group)} findings):')

            for f in group:
                lines.append(f'  [{f.finding_id}] {f.title}')
                lines.append(
                    f'  Resource: {f.resource_id} ({f.resource_type})'
                )
                lines.append(
                    f'  ATT&CK: {f.technique_id} | '
                    f'Phase: {f.kill_chain_phase} | '
                    f'Confidence: {f.confidence}'
                )
                lines.append(f'  Issue: {f.description}')

                if f.exploitation_commands:
                    lines.append('  Commands:')
                    for cmd in f.exploitation_commands[:3]:
                        lines.append(f'    {cmd}')

                if f.detection_gap:
                    lines.append(f'  Detection gap: {f.detection_gap}')

                if f.affected_relationships:
                    lines.append(
                        f'  Compounds with: '
                        f'{", ".join(f.affected_relationships)}'
                    )

                lines.append('')

        return '\n'.join(lines)
