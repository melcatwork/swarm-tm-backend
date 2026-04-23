"""
Pydantic models for swarm threat modeling.

This module defines structured models for kill chain attack paths, mitigations,
and post-mitigation analysis.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class MitigationDetail(BaseModel):
    """Structured mitigation with AWS-specific actions and defense-in-depth categorization."""

    mitigation_id: str = Field(..., description="ATT&CK ID (M1048) or custom (CUSTOM-001)")
    mitigation_name: str = Field(..., description="Short mitigation name")
    description: str = Field(..., description="2-3 sentence description")
    aws_service_action: str = Field(..., description="Specific AWS implementation")
    defense_layer: Optional[str] = Field(
        default=None,
        description="Defense layer: preventive, detective, corrective, or administrative"
    )
    priority: Optional[str] = Field(
        default=None,
        description="Implementation priority: critical, high, medium, or low"
    )
    implementation_effort: Optional[str] = Field(
        default=None,
        description="Estimated effort to implement"
    )
    effectiveness: Optional[str] = Field(
        default=None,
        description="Expected effectiveness of the mitigation"
    )
    blocks_techniques: List[str] = Field(
        default_factory=list,
        description="List of technique IDs this mitigation blocks"
    )


class AttackStep(BaseModel):
    """Single step in a kill chain attack path with defense-in-depth mitigations."""

    step_number: int = Field(..., ge=1, le=10, description="Step number (1-10)")
    kill_chain_phase: str = Field(..., description="Kill chain phase name")
    technique_id: str = Field(..., description="MITRE ATT&CK T-number")
    technique_name: str = Field(..., description="Human-readable technique name")
    target_asset: str = Field(..., description="Specific asset from graph")
    action_description: str = Field(..., description="What attacker does (2-3 sentences)")
    outcome: str = Field(..., description="What attacker gains")
    mitigation: Optional[MitigationDetail] = Field(
        default=None,
        description="Primary mitigation (for backward compatibility)"
    )
    mitigations_by_layer: Optional[Dict[str, List[MitigationDetail]]] = Field(
        default=None,
        description="Defense-in-depth mitigations organized by layer: preventive, detective, corrective, administrative"
    )
    all_mitigations: Optional[List[MitigationDetail]] = Field(
        default_factory=list,
        description="All available mitigations (flat list for reference)"
    )


class AttackPath(BaseModel):
    """Complete kill chain attack path with evaluation and mitigations."""

    id: str = Field(..., description="Unique path identifier")
    name: str = Field(..., description="Descriptive scenario name")
    objective: str = Field(..., description="Attacker's end goal")
    threat_actor: str = Field(..., description="Persona name")
    impact_type: str = Field(..., description="confidentiality/integrity/availability")
    difficulty: str = Field(..., description="low/medium/high")
    steps: List[AttackStep] = Field(..., description="Up to 10 attack steps")
    composite_score: Optional[float] = Field(default=None, description="Evaluation score")
    confidence: Optional[str] = Field(default=None, description="high/medium/low")
    challenged: bool = Field(default=False, description="Whether path was challenged by blue team")
    challenge_resolution: Optional[str] = Field(default=None, description="Resolution notes")
    validation_notes: Optional[str] = Field(default=None, description="Validation notes")
    evaluation: Optional[Dict[str, Any]] = Field(default=None, description="Evaluation scores")


class MitigationSelection(BaseModel):
    """User-selected mitigations to apply."""

    path_id: str = Field(..., description="Attack path ID")
    step_number: int = Field(..., description="Step number in path")
    mitigation_id: str = Field(..., description="Mitigation ID being applied")
    selected: bool = Field(..., description="Whether mitigation is selected")


class StepImpact(BaseModel):
    """Impact of mitigations on a single attack step."""

    step_number: int
    original_status: str = Field(default="active", description="active/blocked/reduced")
    post_mitigation_status: str = Field(..., description="active/blocked/reduced")
    effectiveness: str = Field(..., description="high/medium/low/none")
    reasoning: str = Field(..., description="Why mitigation affects this step")
    applied_mitigations: List[str] = Field(default_factory=list, description="Mitigation IDs applied")


class PostMitigationPath(BaseModel):
    """Attack path after mitigations are applied."""

    path_id: str
    path_name: str
    original_objective: str
    original_difficulty: str
    post_mitigation_difficulty: str = Field(..., description="Updated difficulty after mitigations")
    steps_blocked: int = Field(..., description="Number of steps completely blocked")
    steps_reduced: int = Field(..., description="Number of steps with reduced effectiveness")
    steps_remaining: int = Field(..., description="Number of steps still active")
    step_impacts: List[StepImpact] = Field(..., description="Impact on each step")
    path_status: str = Field(..., description="neutralized/significantly_reduced/partially_mitigated/still_viable")
    residual_risk_score: float = Field(..., ge=0, le=10, description="Risk score after mitigations (0-10)")
    residual_csa_risk_score: Optional[Dict[str, Any]] = Field(
        default=None,
        description="CSA CII residual risk assessment with likelihood, impact, risk_level, risk_band"
    )


class ResidualRisk(BaseModel):
    """Overall residual risk assessment after mitigations."""

    total_paths_analyzed: int
    paths_neutralized: int = Field(..., description="Paths completely blocked")
    paths_significantly_reduced: int = Field(..., description="Paths with >50% steps blocked")
    paths_partially_mitigated: int = Field(..., description="Paths with some steps blocked")
    paths_still_viable: int = Field(..., description="Paths still executable")
    highest_residual_risk_score: float = Field(..., ge=0, le=10)
    mean_residual_risk_score: float = Field(..., ge=0, le=10)
    risk_reduction_percentage: float = Field(..., ge=0, le=100)
    top_residual_risks: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Top 3 remaining viable attack paths"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Additional mitigation recommendations"
    )


class PostMitigationAnalysisRequest(BaseModel):
    """Request to analyze attack paths after selected mitigations."""

    attack_paths: List[Dict[str, Any]] = Field(..., description="Original attack paths")
    selected_mitigations: List[MitigationSelection] = Field(..., description="User-selected mitigations")


class PostMitigationAnalysisResponse(BaseModel):
    """Response with post-mitigation analysis."""

    status: str = Field(..., description="ok or error")
    post_mitigation_paths: List[PostMitigationPath] = Field(
        default_factory=list,
        description="Attack paths after mitigations"
    )
    residual_risk: ResidualRisk = Field(..., description="Overall residual risk assessment")
    execution_time_seconds: float = Field(..., description="Analysis time")
    error: Optional[str] = Field(default=None, description="Error message if status is error")
