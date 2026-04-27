"""LLM-based Path Evaluator for Attack Path Scoring.

Replaces hard-coded pattern matching with LLM reasoning to evaluate attack paths
against confirmed security findings from SecurityAnalyser. Can score any attack
path regardless of technique sequence.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class PathEvaluationResult:
    """Result of LLM-based path evaluation."""
    path_id: str
    evidence_score: float       # 0-10: how well grounded in findings
    cloud_specificity: float    # 0-10: cloud-native vs generic
    technique_accuracy: float   # 0-10: correct techniques for conditions
    exploitability: float       # 0-10: how realistic is this path
    detection_evasion: float    # 0-10: would this evade logging
    composite_score: float      # weighted average
    grounded_findings: List[str]    # finding IDs this path uses
    ungrounded_steps: List[str]     # steps with no IaC evidence
    evaluator_reasoning: str
    improvement_suggestions: str


class PathEvaluator:
    """
    Uses an LLM to evaluate attack paths against confirmed security findings
    from SecurityAnalyser. Can score any path regardless of technique sequence
    — not limited to pre-coded patterns.
    """

    EVALUATOR_SYSTEM_PROMPT = """
You are a red team expert evaluating attack paths proposed by threat modeling
agents. You evaluate each path against confirmed security findings from IaC
analysis.

For each path you score five dimensions from 0 to 10:

evidence_score: How well is each step grounded in a confirmed security
  finding? A step that directly uses a finding like "IMDSv1 enabled on
  waf_ec2" scores 10. A step that is plausible but not supported by any
  specific finding scores 3. A step that contradicts the infrastructure
  (e.g. web shell on a Lambda function) scores 0.

cloud_specificity: Does the path use cloud-native attack techniques rather
  than generic ones? Using IAM credential theft via IMDS scores 10. Using
  a generic web shell when a cloud IAM path is available scores 2. This
  applies to whatever cloud services are present — not just EC2/S3.

technique_accuracy: Are the correct ATT&CK techniques used for the
  conditions present? T1552.005 for IMDS theft scores 10. T1505.003 Web
  Shell when no web server is exploitable scores 0. This requires knowing
  which techniques actually apply to each cloud service and configuration.

exploitability: How realistic is this path given the specific
  infrastructure? Low authentication required, direct network path,
  publicly exposed — scores higher. Requires physical access, multiple
  prior compromises, closed network — scores lower.

detection_evasion: Would this path evade the logging and monitoring
  configured in this infrastructure? If CloudTrail S3 data events are
  missing and the path uses S3 exfiltration, that step evades detection
  — scores higher.

Respond with JSON only:
{
  "evidence_score": 0-10,
  "cloud_specificity": 0-10,
  "technique_accuracy": 0-10,
  "exploitability": 0-10,
  "detection_evasion": 0-10,
  "grounded_findings": ["finding IDs this path correctly uses"],
  "ungrounded_steps": ["step descriptions with no IaC evidence"],
  "evaluator_reasoning": "explanation of scores",
  "improvement_suggestions": "how the path could be more accurate"
}
"""

    def __init__(self, llm_client):
        """
        Initialize PathEvaluator with an LLM client.

        Args:
            llm_client: LLM client instance (same one used by swarm agents)
        """
        self.llm = llm_client

    async def evaluate_path(
        self,
        path: Dict[str, Any],
        findings: List[Any],
        asset_graph: Dict[str, Any],
    ) -> PathEvaluationResult:
        """
        Evaluate an attack path against confirmed security findings.

        Args:
            path: Attack path dictionary with steps
            findings: List of SecurityFinding objects from SecurityAnalyser
            asset_graph: Infrastructure asset graph dictionary

        Returns:
            PathEvaluationResult with scores and analysis
        """
        findings_summary = self._summarise_findings(findings)
        path_description = self._describe_path(path)

        user_prompt = f"""
CONFIRMED SECURITY FINDINGS FROM THIS INFRASTRUCTURE:
{findings_summary}

ATTACK PATH TO EVALUATE:
{path_description}

Evaluate this attack path against the confirmed findings above.
Score each dimension and identify which steps are evidence-grounded
versus speculative. Return JSON only.
"""

        try:
            response = await self._llm_complete(
                system=self.EVALUATOR_SYSTEM_PROMPT,
                user=user_prompt,
                max_tokens=1500,
                temperature=0.1,
            )

            return self._parse_result(
                path.get('id', path.get('path_id', '')),
                response
            )

        except Exception as e:
            logger.error(f"Path evaluation failed: {e}", exc_info=True)
            # Return default scores on failure
            return PathEvaluationResult(
                path_id=path.get('id', path.get('path_id', '')),
                evidence_score=5.0,
                cloud_specificity=5.0,
                technique_accuracy=5.0,
                exploitability=5.0,
                detection_evasion=5.0,
                composite_score=5.0,
                grounded_findings=[],
                ungrounded_steps=[],
                evaluator_reasoning="Evaluation failed due to error",
                improvement_suggestions="",
            )

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
            max_tokens: Maximum tokens to generate (ignored for Bedrock compatibility)
            temperature: Sampling temperature

        Returns:
            LLM response text
        """
        # Use the LLM client's call method (CrewAI LLM interface)
        # Note: max_tokens parameter removed due to Bedrock incompatibility
        # LLM uses max_tokens configured in crews.py get_llm() instead
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        response = self.llm.call(
            messages=messages,
            temperature=temperature,
        )
        return response

    def _summarise_findings(self, findings: List[Any]) -> str:
        """
        Summarise security findings for prompt injection.

        Args:
            findings: List of SecurityFinding objects

        Returns:
            Formatted string summarizing findings
        """
        if not findings:
            return "No security findings available."

        lines = []
        for f in findings:
            # Handle both SecurityFinding objects and dicts
            if hasattr(f, 'finding_id'):
                lines.append(
                    f'[{f.finding_id}] {f.title} '
                    f'({f.severity}) on {f.resource_id}: '
                    f'{f.description[:150]}'
                )
            else:
                lines.append(
                    f'[{f.get("finding_id", "")}] {f.get("title", "")} '
                    f'({f.get("severity", "")}) on {f.get("resource_id", "")}: '
                    f'{f.get("description", "")[:150]}'
                )
        return '\n'.join(lines)

    def _describe_path(self, path: Dict[str, Any]) -> str:
        """
        Describe an attack path for prompt injection.

        Args:
            path: Attack path dictionary

        Returns:
            Formatted string describing the path
        """
        lines = [
            f'Path: {path.get("name", path.get("path_id", ""))}',
            f'Objective: {path.get("objective", "")}',
            f'Threat Actor: {path.get("threat_actor", "")}',
            '',
        ]

        steps = path.get('steps', [])
        for i, step in enumerate(steps, 1):
            lines.append(
                f'Step {i}: {step.get("technique_id", "")} '
                f'{step.get("technique_name", "")} '
                f'on {step.get("target_asset", step.get("asset_id", ""))} — '
                f'{step.get("action_description", step.get("description", ""))}'
            )

        return '\n'.join(lines)

    def _parse_result(
        self,
        path_id: str,
        response: str,
    ) -> PathEvaluationResult:
        """
        Parse LLM response into PathEvaluationResult.

        Args:
            path_id: Path identifier
            response: Raw LLM response text

        Returns:
            PathEvaluationResult with parsed scores
        """
        text = response.strip()

        # Handle markdown code blocks if present
        if '```' in text:
            match = re.search(
                r'```(?:json)?\s*([\s\S]*?)```', text
            )
            if match:
                text = match.group(1).strip()

        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM evaluation response as JSON")
            raw = {}

        # Extract scores with defaults
        e = float(raw.get('evidence_score', 5.0))
        c = float(raw.get('cloud_specificity', 5.0))
        t = float(raw.get('technique_accuracy', 5.0))
        x = float(raw.get('exploitability', 5.0))
        d = float(raw.get('detection_evasion', 5.0))

        # Calculate composite score (weighted average)
        # Prioritize evidence and cloud specificity
        composite = (
            e * 0.30 +
            c * 0.25 +
            t * 0.20 +
            x * 0.15 +
            d * 0.10
        )

        return PathEvaluationResult(
            path_id=path_id,
            evidence_score=round(e, 2),
            cloud_specificity=round(c, 2),
            technique_accuracy=round(t, 2),
            exploitability=round(x, 2),
            detection_evasion=round(d, 2),
            composite_score=round(composite, 2),
            grounded_findings=raw.get('grounded_findings', []),
            ungrounded_steps=raw.get('ungrounded_steps', []),
            evaluator_reasoning=raw.get(
                'evaluator_reasoning', ''
            ),
            improvement_suggestions=raw.get(
                'improvement_suggestions', ''
            ),
        )
