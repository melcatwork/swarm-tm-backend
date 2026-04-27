"""Swarm agent persona management and threat modeling exploration endpoints.

This module provides REST API endpoints for:
- Managing threat actor personas (CRUD operations)
- Running exploration, evaluation, and adversarial validation swarms
- Full end-to-end threat modeling pipeline with IaC file upload

All swarm operations require a properly configured LLM provider
(Bedrock, Anthropic, or Ollama with credentials).
"""

import json
import logging
import os
import signal
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from pydantic import BaseModel, Field

from app.swarm import PersonaRegistry
from app.swarm.job_tracker import get_job_tracker, JobStatus
from app.swarm.iac_serialiser import IaCSerialiser
from app.swarm.security_analyser import SecurityAnalyser
from app.swarm.persona_selector import select_personas_for_context, get_persona_priority_order
from app.swarm.output_filter import (
    filter_and_rank_paths,
    extract_confirmed_findings_as_paths,
    build_confirmed_findings_summary,
)
from app.swarm.consensus_aggregator import aggregate_consensus, get_high_consensus_techniques
from app.swarm.csa_risk_scorer import score_all_paths
# Note: Lazy import crews to avoid CrewAI/LiteLLM initialization at module load time
# CrewAI will default to OpenAI if imported before environment is configured
# from app.swarm.crews import (
#     build_exploration_crew,
#     parse_exploration_results,
#     build_evaluation_crew,
#     aggregate_scores,
#     build_adversarial_crew,
#     parse_adversarial_results,
# )
from app.swarm.mitigations import map_mitigations, analyze_post_mitigation_impact
from app.swarm.models import (
    PostMitigationAnalysisRequest,
    PostMitigationAnalysisResponse,
)
from app.parsers import AssetGraph, TerraformParser, CloudFormationParser
from app.threat_intel.core.feed_manager import FeedManager
from app.services.archive_service import get_archive_service
from app.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/swarm", tags=["Swarm"])

# Module-level singleton for persona registry
persona_registry = PersonaRegistry()

# Validation constants
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
SUPPORTED_EXTENSIONS = [".tf", ".yaml", ".yml", ".json"]
CREW_TIMEOUT_SECONDS = 600  # 10 minutes max for any single crew operation

# Thread pool for background pipeline execution
executor = ThreadPoolExecutor(max_workers=2)  # Max 2 concurrent pipeline runs


def check_llm_configured():
    """
    Check if LLM is properly configured with credentials.

    Raises:
        HTTPException: 503 if LLM is not configured
    """
    settings = get_settings()
    if not settings.is_llm_configured():
        logger.error(
            f"LLM provider '{settings.LLM_PROVIDER}' is not properly configured. "
            "Please set the required credentials in .env file."
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "LLM Not Configured",
                "message": f"The {settings.LLM_PROVIDER} LLM provider is not properly configured. "
                          f"Please set the required credentials in your .env file.",
                "provider": settings.LLM_PROVIDER,
                "required": (
                    "AWS_BEARER_TOKEN_BEDROCK" if settings.LLM_PROVIDER == "bedrock"
                    else "ANTHROPIC_API_KEY" if settings.LLM_PROVIDER == "anthropic"
                    else "OLLAMA_BASE_URL"
                )
            }
        )


def get_current_model_name(model_override: str = None) -> str:
    """
    Get the model name that will be used for this run.

    Args:
        model_override: Optional model override from user selection

    Returns:
        Model name string (e.g., "qwen3:14b", "gemma4:e4b")
    """
    if model_override:
        return model_override

    settings = get_settings()
    if settings.LLM_PROVIDER == "ollama":
        return settings.OLLAMA_MODEL
    elif settings.LLM_PROVIDER == "bedrock":
        return settings.BEDROCK_MODEL
    elif settings.LLM_PROVIDER == "anthropic":
        return settings.ANTHROPIC_MODEL
    else:
        return "unknown"


def validate_model_not_wip(model: str = None):
    """
    Validate that the selected model is not marked as Work In Progress.

    Only uncommented models from .env can be used for threat modeling.
    Commented models are considered Work In Progress and disabled.

    Args:
        model: Optional model override from user selection

    Raises:
        HTTPException: 400 if model is WIP (commented in .env)
    """
    settings = get_settings()

    # If no model override, use default from .env (always valid)
    if not model:
        return

    # Only check Ollama models (Bedrock/Anthropic don't support WIP)
    if settings.LLM_PROVIDER != "ollama":
        return

    # Parse .env to find commented models
    import re
    from pathlib import Path

    # Go up from backend/app/routers to project root
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    if not env_path.exists():
        logger.warning(f".env file not found at {env_path}, skipping WIP validation")
        return

    try:
        with open(env_path, "r") as f:
            content = f.read()

        # Check if the model is commented in .env
        commented_pattern = r'^\s*#\s*OLLAMA_MODEL\s*=\s*([^\s#]+)'
        for match in re.finditer(commented_pattern, content, re.MULTILINE):
            commented_model = match.group(1).strip().strip('"').strip("'")
            if commented_model == model:
                logger.warning(f"User attempted to use WIP model: {model}")
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "Model Not Available",
                        "message": f"The model '{model}' is marked as Work In Progress and cannot be used. "
                                  f"Please select the default model or another enabled model.",
                        "model": model,
                        "status": "work_in_progress"
                    }
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating model WIP status: {e}")
        # Don't block execution if validation fails
        return


class PersonaBase(BaseModel):
    """Base model for persona data."""

    display_name: str = Field(..., description="Human-readable display name")
    category: str = Field(..., description="Category: threat_actor or archetype")
    role: str = Field(..., description="Agent role description")
    goal: str = Field(..., description="Agent goal statement")
    backstory: str = Field(..., description="Detailed agent backstory")
    ttp_focus: List[str] = Field(default_factory=list, description="MITRE ATT&CK TTP IDs")


class PersonaCreate(PersonaBase):
    """Model for creating a new persona."""

    pass


class PersonaUpdate(BaseModel):
    """Model for partially updating a persona."""

    display_name: str | None = None
    category: str | None = None
    role: str | None = None
    goal: str | None = None
    backstory: str | None = None
    ttp_focus: List[str] | None = None
    enabled: bool | None = None


class PersonaToggle(BaseModel):
    """Model for toggling persona enabled status."""

    enabled: bool


class PersonaResponse(BaseModel):
    """Response model for persona operations."""

    status: str
    persona: str | None = None
    message: str | None = None


class PersonaListItem(BaseModel):
    """List item for a persona with metadata."""

    name: str
    display_name: str
    category: str
    protected: bool
    enabled: bool
    role: str
    goal: str


@router.get("/personas", response_model=Dict[str, Dict])
async def get_personas():
    """
    Get all personas with their enabled status.

    Returns a dictionary of persona names to their configuration.
    """
    try:
        personas = persona_registry.get_all()
        return personas
    except Exception as e:
        logger.error(f"Failed to get personas: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/personas/enabled", response_model=Dict[str, Dict])
async def get_enabled_personas():
    """
    Get only enabled personas.

    Returns a dictionary of enabled persona names to their configuration.
    """
    try:
        enabled_personas = persona_registry.get_enabled()
        return enabled_personas
    except Exception as e:
        logger.error(f"Failed to get enabled personas: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/personas/{name}", response_model=Dict)
async def get_persona(name: str):
    """
    Get a single persona by name.
    """
    try:
        persona = persona_registry.get_by_name(name)
        if persona is None:
            raise HTTPException(status_code=404, detail=f"Persona '{name}' not found")
        return persona
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get persona '{name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/personas", response_model=PersonaResponse)
async def create_persona(name: str, persona: PersonaCreate):
    """
    Add a new custom persona.

    Custom personas are not protected and can be modified or deleted.

    Args:
        name: Unique persona identifier (alphanumeric + underscores)
        persona: Persona configuration
    """
    try:
        persona_dict = persona.model_dump()
        persona_registry.add_persona(name, persona_dict)

        return PersonaResponse(
            status="ok",
            persona=name,
            message=f"Created persona '{name}'",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create persona '{name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/personas/{name}/toggle", response_model=PersonaResponse)
async def toggle_persona(name: str, toggle: PersonaToggle):
    """
    Enable or disable a persona.

    Both protected and custom personas can be toggled.

    Args:
        name: Persona name
        toggle: Toggle configuration with enabled status
    """
    try:
        persona_registry.toggle_persona(name, toggle.enabled)

        status = "enabled" if toggle.enabled else "disabled"
        return PersonaResponse(
            status="ok",
            persona=name,
            message=f"Persona '{name}' {status}",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to toggle persona '{name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/personas/{name}", response_model=PersonaResponse)
async def update_persona(name: str, updates: PersonaUpdate):
    """
    Update fields of an existing persona.

    Only non-None fields in the request body will be updated.
    Protected status cannot be changed.

    Args:
        name: Persona name
        updates: Partial persona data to update
    """
    try:
        # Filter out None values
        update_dict = {k: v for k, v in updates.model_dump().items() if v is not None}

        if not update_dict:
            raise HTTPException(status_code=400, detail="No fields to update")

        persona_registry.update_persona(name, update_dict)

        return PersonaResponse(
            status="ok",
            persona=name,
            message=f"Updated persona '{name}'",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update persona '{name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/personas/{name}", response_model=PersonaResponse)
async def delete_persona(name: str):
    """
    Delete a custom persona.

    Protected personas (default threat actors and archetypes) cannot be deleted,
    but they can be disabled using the toggle endpoint.

    Args:
        name: Persona name to delete
    """
    try:
        persona_registry.remove_persona(name)

        return PersonaResponse(
            status="ok",
            persona=name,
            message=f"Deleted persona '{name}'",
        )
    except ValueError as e:
        # Check if it's a protected persona error
        if "protected" in str(e).lower():
            raise HTTPException(status_code=403, detail=str(e))
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to delete persona '{name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Threat Modeling Exploration Endpoints
# ============================================================================

# Module-level singleton for feed manager
feed_manager = FeedManager()


class ExploreRequest(BaseModel):
    """Request model for threat modeling exploration."""

    asset_graph: Dict[str, Any] = Field(
        ...,
        description="Infrastructure asset graph from IaC parser",
    )
    model: str | None = Field(
        None,
        description="Optional LLM model to use (e.g., 'qwen3:14b', 'gemma4:e4b'). If not specified, uses default from .env",
    )


class ExploreResponse(BaseModel):
    """Response model for threat modeling exploration."""

    status: str = Field(..., description="Status: ok or error")
    paths: List[Dict] = Field(
        default_factory=list,
        description="List of attack paths discovered",
    )
    agent_count: int = Field(..., description="Number of agents used")
    total_paths: int = Field(..., description="Total attack paths found")
    execution_time_seconds: float = Field(
        ...,
        description="Time taken to complete analysis",
    )
    threat_intel_items: int = Field(
        default=0,
        description="Number of threat intel items used for context",
    )
    error: str | None = Field(
        default=None,
        description="Error message if status is error",
    )


def _build_threat_intel_context() -> tuple[str, int]:
    """
    Build threat intelligence context summary from feed.

    Returns:
        Tuple of (context_string, item_count)
    """
    try:
        # Fetch all items from feed
        all_items = feed_manager.fetch_all()

        if not all_items:
            return "No recent threat intelligence available.", 0

        # Sort by citation_score (highest first) and take top 20
        sorted_items = sorted(
            all_items,
            key=lambda x: x.citation_score,
            reverse=True,
        )
        items = sorted_items[:20]

        # Group by category
        cves = []
        incidents = []
        ttps = []
        news = []

        for item in items:
            category = item.category.lower()
            title = item.title
            summary = item.summary

            if category == "cve":
                cves.append(f"{title}: {summary[:100]}")
            elif category == "incident":
                incidents.append(title)
            elif category == "ttp":
                # Extract T-numbers from title/summary
                import re

                t_numbers = re.findall(r"T\d{4}(?:\.\d{3})?", title + " " + summary)
                if t_numbers:
                    ttps.extend(t_numbers)
            elif category == "news":
                news.append(title)

        # Build context string
        context_parts = []

        if cves:
            cve_summary = "; ".join(cves[:5])
            context_parts.append(f"Recent CVEs: {cve_summary}")

        if incidents:
            incidents_summary = ", ".join(incidents[:5])
            context_parts.append(f"Recent incidents: {incidents_summary}")

        if ttps:
            # Deduplicate TTPs
            unique_ttps = list(set(ttps))[:10]
            context_parts.append(f"Active TTPs: {', '.join(unique_ttps)}")

        if news:
            news_summary = ", ".join(news[:3])
            context_parts.append(f"Security news: {news_summary}")

        if not context_parts:
            return "Threat intelligence feed available but no categorized items.", len(items)

        context = " | ".join(context_parts)
        return context, len(items)

    except Exception as e:
        logger.error(f"Failed to build threat intel context: {e}")
        return "Error loading threat intelligence.", 0


async def _run_security_analysis(
    asset_graph: Dict[str, Any],
    raw_iac: Dict[str, Any] = None,
    model: str = None,
) -> tuple[str, List[Dict[str, Any]]]:
    """
    Run LLM-based security analysis on infrastructure.

    Serialises the IaC and uses an LLM to dynamically identify misconfigurations
    and vulnerabilities that agents can use as starting points.

    Args:
        asset_graph: Parsed infrastructure asset graph dictionary
        raw_iac: Optional raw IaC dictionary (Terraform HCL or CloudFormation)
        model: Optional model name to use instead of default

    Returns:
        Tuple of (formatted_findings_context, findings_list)
    """
    try:
        logger.info("Running LLM-based security analysis on IaC")

        # Serialise IaC for LLM analysis
        serialiser = IaCSerialiser()
        serialised_iac = serialiser.serialise(asset_graph, raw_iac)

        logger.info(f"Serialised IaC: {len(serialised_iac)} characters")

        # Get LLM instance for analysis
        from app.swarm.crews import get_llm
        llm = get_llm(model_override=model)

        # Run security analysis
        analyser = SecurityAnalyser(llm)
        findings = await analyser.analyse(serialised_iac, max_findings=30)

        logger.info(f"Security analysis found {len(findings)} issues")

        # Format findings for prompt injection
        findings_context = analyser.format_for_prompt(findings)

        # Convert findings to dicts for API response
        findings_dicts = [
            {
                "finding_id": f.finding_id,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "technique_id": f.technique_id,
                "technique_name": f.technique_name,
                "kill_chain_phase": f.kill_chain_phase,
                "exploitation_detail": f.exploitation_detail,
                "exploitation_commands": f.exploitation_commands,
                "detection_gap": f.detection_gap,
                "affected_relationships": f.affected_relationships,
                "remediation": f.remediation,
                "confidence": f.confidence,
                "reasoning": f.reasoning,
            }
            for f in findings
        ]

        return findings_context, findings_dicts

    except Exception as e:
        logger.error(f"Security analysis failed: {e}", exc_info=True)
        return "SECURITY ANALYSIS: Analysis failed due to error.", []


def _run_exploration(
    asset_graph: Dict[str, Any],
    threat_intel_context: str = "",
    security_findings_context: str = "",
    model: str = None,
    vuln_context = None,
) -> List[Dict]:
    """
    Internal helper to run exploration phase.

    Args:
        asset_graph: Infrastructure asset graph dictionary
        threat_intel_context: Optional threat intelligence context string
        security_findings_context: Pre-identified security findings from LLM analysis
        model: Optional model name to use instead of default
        vuln_context: Optional VulnContext with vulnerability intelligence

    Returns:
        List of attack path dictionaries

    Raises:
        Exception: If exploration fails
    """
    # Lazy import to avoid CrewAI initialization at module load
    from app.swarm.crews import build_exploration_crew, parse_exploration_results

    # Convert asset graph to JSON string
    asset_graph_json = json.dumps(asset_graph, indent=2)

    # Build and execute crew with optional model override
    logger.info(f"Building exploration crew{' with model: ' + model if model else ''}")
    crew = build_exploration_crew(
        asset_graph_json,
        threat_intel_context,
        security_findings_context=security_findings_context,
        model_override=model,
        vuln_context=vuln_context
    )

    logger.info(f"Executing exploration crew with {len(crew.agents)} agents")
    crew_output = crew.kickoff()

    # Parse results
    logger.info("Parsing exploration results")
    attack_paths = parse_exploration_results(crew_output)

    logger.info(f"Exploration complete: {len(attack_paths)} attack paths discovered")
    return attack_paths


async def _run_path_evaluation(
    attack_paths: List[Dict],
    security_findings: List[Dict],
    asset_graph: Dict[str, Any],
    model: str = None,
) -> List[Dict]:
    """
    Internal helper to run LLM-based path evaluation against security findings.

    Uses PathEvaluator to score paths based on evidence grounding, cloud
    specificity, technique accuracy, exploitability, and detection evasion.

    Args:
        attack_paths: List of attack path dictionaries from exploration
        security_findings: List of security findings from SecurityAnalyser
        asset_graph: Infrastructure asset graph dictionary
        model: Optional model name to use instead of default

    Returns:
        List of attack paths enriched with llm_evaluation and adjusted scores

    Raises:
        Exception: If evaluation fails
    """
    from app.swarm.path_evaluator import PathEvaluator
    from app.swarm.crews import get_llm

    logger.info("Running LLM-based path evaluation against security findings")

    # Get LLM instance
    llm = get_llm(model_override=model)

    # Create evaluator
    evaluator = PathEvaluator(llm)

    # Evaluate each path
    evaluated_paths = []
    for idx, path in enumerate(attack_paths, 1):
        try:
            logger.info(f"Evaluating path {idx}/{len(attack_paths)}: {path.get('name', '')}")

            # Run evaluation
            result = await evaluator.evaluate_path(
                path=path,
                findings=security_findings,
                asset_graph=asset_graph,
            )

            # Add evaluation results to path
            path['llm_evaluation'] = {
                'evidence_score': result.evidence_score,
                'cloud_specificity': result.cloud_specificity,
                'technique_accuracy': result.technique_accuracy,
                'exploitability': result.exploitability,
                'detection_evasion': result.detection_evasion,
                'composite_score': result.composite_score,
                'grounded_findings': result.grounded_findings,
                'ungrounded_steps': result.ungrounded_steps,
                'evaluator_reasoning': result.evaluator_reasoning,
                'improvement_suggestions': result.improvement_suggestions,
            }

            # Set adjusted composite score (can be used for ranking)
            path['llm_composite_score'] = result.composite_score

            evaluated_paths.append(path)

        except Exception as e:
            logger.error(f"Failed to evaluate path {idx}: {e}", exc_info=True)
            # Add path without evaluation
            evaluated_paths.append(path)
            continue

    logger.info(f"Path evaluation complete: {len(evaluated_paths)} paths evaluated")
    return evaluated_paths


def _run_evaluation(
    attack_paths: List[Dict],
    asset_graph: Dict[str, Any],
    model: str = None,
) -> List[Dict]:
    """
    Internal helper to run evaluation phase.

    Args:
        attack_paths: List of attack path dictionaries from exploration
        asset_graph: Infrastructure asset graph dictionary
        model: Optional model name to use instead of default

    Returns:
        List of attack paths enriched with evaluation scores, sorted by composite_score

    Raises:
        Exception: If evaluation fails
    """
    # Lazy import to avoid CrewAI initialization at module load
    from app.swarm.crews import build_evaluation_crew, aggregate_scores

    # Convert to JSON strings
    attack_paths_json = json.dumps(attack_paths, indent=2)
    asset_graph_json = json.dumps(asset_graph, indent=2)

    # Build and execute evaluation crew with optional model override
    logger.info(f"Building evaluation crew{' with model: ' + model if model else ''}")
    crew = build_evaluation_crew(attack_paths_json, asset_graph_json, model_override=model)

    logger.info(f"Executing evaluation crew with {len(crew.agents)} evaluators")
    crew_output = crew.kickoff()

    # Aggregate scores
    logger.info("Aggregating evaluation scores")
    scored_paths = aggregate_scores(attack_paths, crew_output)

    logger.info(f"Evaluation complete: {len(scored_paths)} paths scored and ranked")
    return scored_paths


@router.post("/explore", response_model=ExploreResponse)
async def explore_infrastructure(request: ExploreRequest):
    """
    Run full threat modeling exploration on infrastructure.

    This endpoint performs a comprehensive multi-agent threat analysis using all
    enabled personas. The analysis includes:
    - Attack path identification from initial access to impact
    - MITRE ATT&CK technique mapping
    - Impact assessment (confidentiality, integrity, availability)
    - Difficulty ratings

    **WARNING:** This endpoint is slow (several minutes) as it runs all enabled
    agents sequentially. Use /explore/quick for faster testing.

    Each enabled persona analyzes the infrastructure and produces structured
    attack paths. The results are combined and returned.

    Args:
        request: ExploreRequest with asset_graph

    Returns:
        ExploreResponse with discovered attack paths and metadata
    """
    start_time = time.time()

    try:
        # Build threat intel context
        logger.info("Building threat intelligence context")
        threat_intel_context, intel_count = _build_threat_intel_context()
        logger.info(f"Using {intel_count} threat intel items for context")

        # Run exploration using helper
        attack_paths = _run_exploration(request.asset_graph, threat_intel_context)

        # Get agent count from registry
        enabled_personas = persona_registry.get_enabled()
        agent_count = len(enabled_personas)

        execution_time = time.time() - start_time
        logger.info(
            f"Exploration completed in {execution_time:.2f}s: "
            f"{len(attack_paths)} attack paths from {agent_count} agents"
        )

        return ExploreResponse(
            status="ok",
            paths=attack_paths,
            agent_count=agent_count,
            total_paths=len(attack_paths),
            execution_time_seconds=round(execution_time, 2),
            threat_intel_items=intel_count,
        )

    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Exploration failed after {execution_time:.2f}s: {e}")

        return ExploreResponse(
            status="error",
            paths=[],
            agent_count=0,
            total_paths=0,
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )


@router.post("/explore/quick", response_model=ExploreResponse)
async def explore_infrastructure_quick(request: ExploreRequest):
    """
    Run quick threat modeling exploration on infrastructure.

    This endpoint performs a faster analysis using only 2 threat actor personas
    (APT29 and Scattered Spider) for rapid testing and iteration.

    The quick mode temporarily disables all other personas and only uses these
    two for analysis. It's ideal for:
    - Testing infrastructure changes quickly
    - Rapid prototyping
    - Development and debugging
    - Cost-conscious analysis

    Args:
        request: ExploreRequest with asset_graph

    Returns:
        ExploreResponse with discovered attack paths from 2 agents
    """
    start_time = time.time()

    try:
        # Build threat intel context
        logger.info("Building threat intelligence context (2 agents test mode)")
        threat_intel_context, intel_count = _build_threat_intel_context()

        # Temporarily save current persona states
        registry = PersonaRegistry()
        original_states = {
            name: persona.get("enabled", True)
            for name, persona in registry.get_all().items()
        }

        try:
            # Disable all personas
            logger.info("Temporarily configuring personas for 2 agents test mode")
            for name in original_states.keys():
                registry.toggle_persona(name, False)

            # Enable only APT29 and Scattered Spider
            registry.toggle_persona("apt29_cozy_bear", True)
            registry.toggle_persona("scattered_spider", True)

            # Run exploration using helper
            logger.info("Running quick exploration with 2 personas")
            attack_paths = _run_exploration(request.asset_graph, threat_intel_context)

            execution_time = time.time() - start_time
            logger.info(
                f"2 agents test exploration completed in {execution_time:.2f}s: "
                f"{len(attack_paths)} attack paths from 2 agents"
            )

            return ExploreResponse(
                status="ok",
                paths=attack_paths,
                agent_count=2,
                total_paths=len(attack_paths),
                execution_time_seconds=round(execution_time, 2),
                threat_intel_items=intel_count,
            )

        finally:
            # Restore original persona states
            logger.info("Restoring original persona states")
            for name, enabled in original_states.items():
                registry.toggle_persona(name, enabled)

    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"2 agents test exploration failed after {execution_time:.2f}s: {e}")

        # Try to restore states on error
        try:
            registry = PersonaRegistry()
            for name, enabled in original_states.items():
                registry.toggle_persona(name, enabled)
        except Exception as restore_error:
            logger.error(f"Failed to restore persona states: {restore_error}")

        return ExploreResponse(
            status="error",
            paths=[],
            agent_count=0,
            total_paths=0,
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )


# ============================================================================
# Attack Path Evaluation Endpoint
# ============================================================================


class EvaluateRequest(BaseModel):
    """Request model for attack path evaluation."""

    attack_paths: List[Dict] = Field(
        ...,
        description="List of attack paths from exploration phase",
    )
    asset_graph: Dict[str, Any] = Field(
        ...,
        description="Infrastructure asset graph for context",
    )


class ScoreSummary(BaseModel):
    """Summary statistics for evaluation scores."""

    highest: float = Field(..., description="Highest composite score")
    lowest: float = Field(..., description="Lowest composite score")
    mean: float = Field(..., description="Mean composite score")


class EvaluateResponse(BaseModel):
    """Response model for attack path evaluation."""

    status: str = Field(..., description="Status: ok or error")
    scored_paths: List[Dict] = Field(
        default_factory=list,
        description="Attack paths with evaluation scores, sorted by composite_score descending",
    )
    score_summary: ScoreSummary | None = Field(
        default=None,
        description="Summary statistics for scores",
    )
    execution_time_seconds: float = Field(
        ...,
        description="Time taken to complete evaluation",
    )
    error: str | None = Field(
        default=None,
        description="Error message if status is error",
    )


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_attack_paths(request: EvaluateRequest):
    """
    Evaluate and score attack paths from exploration phase.

    This endpoint takes attack paths discovered during exploration and runs them
    through a multi-agent evaluation crew that scores each path on:
    - **Feasibility** (30%): Can the attack realistically be executed?
    - **Detection difficulty** (15%): How stealthy is this attack?
    - **Impact** (25%): What's the business impact if successful?
    - **Novelty** (15%): How creative/unexpected is this attack?
    - **Coherence** (15%): Does the attack chain make logical sense?

    The paths are ranked by a composite score and returned sorted by priority.

    **WARNING:** This endpoint is slow (several minutes) as it runs 5 evaluator
    agents sequentially on all attack paths.

    Args:
        request: EvaluateRequest with attack_paths and asset_graph

    Returns:
        EvaluateResponse with scored and ranked attack paths
    """
    start_time = time.time()

    try:
        if not request.attack_paths:
            return EvaluateResponse(
                status="ok",
                scored_paths=[],
                score_summary=None,
                execution_time_seconds=0.0,
            )

        logger.info(f"Starting evaluation of {len(request.attack_paths)} attack paths")

        # Run evaluation using helper
        scored_paths = _run_evaluation(request.attack_paths, request.asset_graph)

        # Calculate score summary
        composite_scores = [
            path["evaluation"]["composite_score"]
            for path in scored_paths
            if "evaluation" in path and "composite_score" in path["evaluation"]
        ]

        if composite_scores:
            score_summary = ScoreSummary(
                highest=max(composite_scores),
                lowest=min(composite_scores),
                mean=round(sum(composite_scores) / len(composite_scores), 2),
            )
        else:
            score_summary = None

        execution_time = time.time() - start_time
        logger.info(
            f"Evaluation completed in {execution_time:.2f}s: "
            f"{len(scored_paths)} paths scored"
        )

        return EvaluateResponse(
            status="ok",
            scored_paths=scored_paths,
            score_summary=score_summary,
            execution_time_seconds=round(execution_time, 2),
        )

    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Evaluation failed after {execution_time:.2f}s: {e}")

        return EvaluateResponse(
            status="error",
            scored_paths=[],
            score_summary=None,
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )


# ============================================================================
# Full Pipeline Endpoint
# ============================================================================


async def _parse_iac_file(file: UploadFile) -> AssetGraph:
    """
    Internal helper to parse IaC file into AssetGraph.

    Validates file size and extension before parsing. Supports Terraform (.tf)
    and AWS CloudFormation (.yaml, .yml, .json) files.

    Args:
        file: Uploaded IaC file (.tf, .yaml, .yml, or .json)

    Returns:
        AssetGraph with parsed infrastructure

    Raises:
        HTTPException: 400 for missing filename, 413 for file too large,
                      422 for unsupported format or parse errors,
                      500 for unexpected errors
    """
    if not file.filename:
        logger.error("File upload attempted without filename")
        raise HTTPException(status_code=400, detail="No filename provided")

    filename_lower = file.filename.lower()

    # Validate file extension
    file_extension = filename_lower[filename_lower.rfind('.'):]
    if file_extension not in SUPPORTED_EXTENSIONS:
        logger.warning(f"Unsupported file extension: {file_extension}")
        raise HTTPException(
            status_code=422,
            detail={
                "error": "Unsupported File Type",
                "message": f"File extension '{file_extension}' is not supported.",
                "supported": SUPPORTED_EXTENSIONS
            }
        )

    try:
        # Read file content
        content = await file.read()

        # Validate file size
        file_size = len(content)
        if file_size > MAX_FILE_SIZE_BYTES:
            logger.warning(
                f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE_BYTES})"
            )
            raise HTTPException(
                status_code=413,
                detail={
                    "error": "File Too Large",
                    "message": f"File size {file_size / 1024 / 1024:.2f}MB exceeds maximum of {MAX_FILE_SIZE_MB}MB",
                    "max_size_mb": MAX_FILE_SIZE_MB
                }
            )

        logger.info(f"Processing file: {file.filename} ({file_size} bytes)")

        content_str = content.decode("utf-8")

        # Detect file type and parse
        if filename_lower.endswith(".tf"):
            logger.info(f"Parsing Terraform file: {file.filename}")
            parser = TerraformParser()
            asset_graph = parser.parse(content_str)

        elif filename_lower.endswith((".yaml", ".yml", ".json")):
            extension = "yaml" if filename_lower.endswith((".yaml", ".yml")) else "json"

            # For JSON files, check if it's CloudFormation
            if extension == "json":
                try:
                    parsed_json = json.loads(content_str)
                    if not isinstance(parsed_json, dict) or "Resources" not in parsed_json:
                        raise HTTPException(
                            status_code=422,
                            detail="JSON file does not appear to be a CloudFormation template (missing 'Resources' key)",
                        )
                except json.JSONDecodeError as e:
                    raise HTTPException(status_code=422, detail=f"Invalid JSON: {str(e)}")

            logger.info(f"Parsing CloudFormation {extension.upper()} file: {file.filename}")
            parser = CloudFormationParser()
            asset_graph = parser.parse(content_str, file_extension=extension)

        else:
            raise HTTPException(
                status_code=422,
                detail="Unsupported file format. Supported extensions: .tf, .yaml, .yml, .json",
            )

        logger.info(
            f"Successfully parsed {file.filename}: "
            f"{len(asset_graph.assets)} assets, "
            f"{len(asset_graph.relationships)} relationships"
        )

        return asset_graph

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Parse error for {file.filename}: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error parsing {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse file: {str(e)}")


class PipelineResponse(BaseModel):
    """Response model for full threat modeling pipeline."""

    status: str = Field(..., description="Status: ok or error")
    asset_graph: Dict[str, Any] = Field(
        ...,
        description="Parsed infrastructure asset graph",
    )
    security_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Pre-identified security findings from LLM analysis of IaC",
    )
    vulnerability_intelligence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Vulnerability intelligence including cloud signals, matched CVEs/abuse patterns, and assembled chains",
    )
    confirmed_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="High-confidence confirmed vulnerability findings from VulnMatcher (CONFIRMED confidence only)",
    )
    persona_selection: Dict[str, Any] = Field(
        default_factory=dict,
        description="Persona selection details including injected specialists for high-confidence findings",
    )
    exploration_summary: Dict[str, Any] = Field(
        ...,
        description="Summary of exploration phase (Layer 1)",
    )
    evaluation_summary: Dict[str, Any] = Field(
        ...,
        description="Summary of evaluation phase (Layer 2)",
    )
    adversarial_summary: Dict[str, Any] = Field(
        ...,
        description="Summary of adversarial validation phase (Layer 3)",
    )
    final_paths: List[Dict] = Field(
        default_factory=list,
        description="Complete validated attack paths with scores, mitigations, confidence, and provenance",
    )
    executive_summary: str = Field(
        default="",
        description="High-level summary of threat model findings",
    )
    execution_time_seconds: float = Field(
        ...,
        description="Total time for complete pipeline",
    )
    csa_risk_assessment: Dict[str, Any] | None = Field(
        default=None,
        description="CSA CII 5×5 risk matrix assessment with scored paths, risk distribution, and tolerance actions",
    )
    error: str | None = Field(
        default=None,
        description="Error message if status is error",
    )


class JobSubmittedResponse(BaseModel):
    """Response when a job is submitted for background processing."""

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Initial job status")
    message: str = Field(..., description="Human-readable message")
    estimated_time_minutes: int = Field(..., description="Estimated completion time in minutes")
    status_url: str = Field(..., description="URL to check job status")


class JobStatusResponse(BaseModel):
    """Response with job execution status and progress."""

    job_id: str = Field(..., description="Job identifier")
    filename: str = Field(..., description="IaC filename being analyzed")
    status: str = Field(..., description="Current job status")
    progress_percent: int = Field(..., description="Progress percentage (0-100)")
    current_phase: str = Field(..., description="Current execution phase")
    started_at: str = Field(..., description="Job start timestamp (ISO 8601)")
    completed_at: str | None = Field(None, description="Job completion timestamp (ISO 8601)")
    elapsed_seconds: float | None = Field(None, description="Elapsed time in seconds")
    error: str | None = Field(None, description="Error message if failed")
    logs: List[str] = Field(default_factory=list, description="Recent log entries")


class JobResultResponse(BaseModel):
    """Response with completed job results."""

    job_id: str = Field(..., description="Job identifier")
    status: str = Field(..., description="Job status (should be 'completed')")
    result: PipelineResponse = Field(..., description="Pipeline execution results")


@router.post("/run", response_model=PipelineResponse)
async def run_full_pipeline(
    file: UploadFile = File(...),
    model: str = Form(None),
    impact_score: int = Form(3)
):
    """
    Run the complete threat modeling pipeline on an IaC file.

    This endpoint orchestrates all three layers of the swarm threat modeling system:

    **Layer 1: Exploration** - Multiple threat actor personas explore the infrastructure
    and generate attack paths from different adversarial perspectives.

    **Layer 2: Evaluation** - Five evaluator agents score each attack path on:
    - Feasibility (30%)
    - Detection difficulty (15%)
    - Impact (25%)
    - Novelty (15%)
    - Coherence (15%)

    **Layer 3: Adversarial Validation** - Three agents perform red/blue/arbitrator review:
    - Red team identifies gaps in attack surface coverage
    - Blue team challenges feasibility from defender's perspective
    - Arbitrator produces final validated threat model with confidence ratings

    **Mitigation Mapping** - Each ATT&CK technique in each final path is mapped to:
    - MITRE ATT&CK mitigations from STIX data
    - AWS-specific contextual mitigations

    **CSA CII Risk Assessment** - Each path scored with 5×5 risk matrix (Likelihood × Impact)

    **WARNING:** This endpoint is very slow (10+ minutes) as it runs all three layers
    sequentially with all enabled personas. Use /run/quick for faster testing.

    Args:
        file: IaC file upload (.tf, .yaml, .yml, or .json)
        model: Optional LLM model override
        impact_score: CSA CII impact classification (1=Negligible, 2=Minor, 3=Moderate, 4=Severe, 5=Very Severe). Default: 3

    Returns:
        PipelineResponse with complete threat model including validated paths,
        scores, mitigations, CSA risk assessment, and executive summary

    Raises:
        HTTPException: 503 if LLM not configured, 413 if file too large,
                      422 if file format unsupported, 500 for other errors
    """
    # Lazy import to avoid CrewAI initialization at module load
    from app.swarm.crews import build_adversarial_crew, parse_adversarial_results

    start_time = time.time()

    # Log model selection
    if model:
        logger.info(f"Full pipeline using model override: {model}")
    else:
        logger.info("Full pipeline using default model from .env")

    try:
        # Check LLM configuration before starting
        check_llm_configured()

        # Validate model is not WIP
        validate_model_not_wip(model)

        # Phase 1: Parse IaC file
        logger.info("=" * 60)
        logger.info("Starting Multi-agents Run Pipeline")
        logger.info(f"File: {file.filename}")
        logger.info("=" * 60)
        logger.info("Pipeline Phase 1: Parsing IaC file")
        asset_graph = await _parse_iac_file(file)
        asset_graph_dict = asset_graph.model_dump()

        # Build threat intel context
        logger.info("Building threat intelligence context")
        threat_intel_context, intel_count = _build_threat_intel_context()

        # Run security analysis
        logger.info("Phase 1.5: Running LLM-based security analysis")
        security_findings_context, security_findings_list = await _run_security_analysis(
            asset_graph_dict,
            raw_iac=None,  # TODO: Pass raw IaC if available
            model=model
        )

        # Phase 1.6: Build vulnerability intelligence context
        logger.info("Phase 1.6: Building vulnerability intelligence context")
        from app.swarm.vuln_intel.vuln_context_builder import VulnContextBuilder
        vuln_builder = VulnContextBuilder(nvd_api_key=os.getenv('NVD_API_KEY'))
        vuln_context = await vuln_builder.build(
            asset_graph=asset_graph_dict,
            raw_iac=None,
            include_cve_lookup=bool(os.getenv('NVD_API_KEY')) and os.getenv('ENABLE_CVE_LOOKUP', 'true').lower() == 'true',
        )
        logger.info(
            f"Vulnerability context built: {vuln_context.stats['vulns_matched']} vulns, "
            f"{vuln_context.stats['chains_assembled']} chains"
        )

        # Phase 1.7: Dynamic persona selection based on findings
        logger.info("Phase 1.7: Dynamic persona selection")
        enabled_personas_dict = persona_registry.get_enabled()
        requested_persona_ids = list(enabled_personas_dict.keys())
        all_persona_ids = [p for p in persona_registry.get_all().keys()]

        active_personas, injected_personas = select_personas_for_context(
            requested_personas=requested_persona_ids,
            vuln_context=vuln_context,
            run_type='multi',
            all_available_personas=all_persona_ids,
        )
        active_personas = get_persona_priority_order(active_personas, vuln_context)
        logger.info(
            f"Persona selection: requested={len(requested_persona_ids)} enabled, "
            f"final={len(active_personas)}, injected={injected_personas}"
        )

        # Temporarily reconfigure personas if injections were made
        if injected_personas:
            logger.info(f"Enabling {len(injected_personas)} injected specialists")
            for persona_id in injected_personas:
                try:
                    persona_registry.toggle_persona(persona_id, True)
                except Exception as e:
                    logger.warning(f"Failed to enable {persona_id}: {e}")

        # Phase 2: Exploration (Layer 1)
        logger.info("Pipeline Phase 2: Exploration (Layer 1)")
        exploration_start = time.time()
        exploration_paths = _run_exploration(
            asset_graph_dict,
            threat_intel_context,
            security_findings_context=security_findings_context,
            model=model,
            vuln_context=vuln_context
        )
        exploration_time = time.time() - exploration_start

        # Phase 2.1: Consensus aggregation (multi-agent coordination)
        logger.info("Pipeline Phase 2.1: Consensus aggregation")
        # Group paths by agent for consensus analysis
        agent_paths = {}
        for path in exploration_paths:
            agent_name = path.get('threat_actor', 'unknown')
            if agent_name not in agent_paths:
                agent_paths[agent_name] = []
            agent_paths[agent_name].append(path)

        consensus_findings = aggregate_consensus(agent_paths)
        high_consensus = get_high_consensus_techniques(consensus_findings, min_agent_count=2)
        logger.info(
            f"Consensus aggregation: {len(consensus_findings)} unique combinations, "
            f"{len(high_consensus)} high-consensus techniques"
        )

        enabled_personas = persona_registry.get_enabled()
        exploration_summary = {
            "agents_used": len(active_personas),
            "raw_paths_found": len(exploration_paths),
            "execution_time_seconds": round(exploration_time, 2),
            "threat_intel_items": intel_count,
            "consensus_findings": len(high_consensus),
        }

        logger.info(
            f"Exploration complete: {len(exploration_paths)} paths from "
            f"{len(active_personas)} agents in {exploration_time:.2f}s"
        )

        # Phase 2.5: LLM-based Path Evaluation against Security Findings
        logger.info("Pipeline Phase 2.5: LLM-based Path Evaluation")
        path_eval_start = time.time()
        exploration_paths = await _run_path_evaluation(
            exploration_paths,
            security_findings_list,
            asset_graph_dict,
            model=model
        )
        path_eval_time = time.time() - path_eval_start
        logger.info(
            f"Path evaluation complete: {len(exploration_paths)} paths evaluated "
            f"in {path_eval_time:.2f}s"
        )

        # Phase 3: Evaluation (Layer 2)
        logger.info("Pipeline Phase 3: Evaluation (Layer 2)")
        evaluation_start = time.time()
        scored_paths = _run_evaluation(exploration_paths, asset_graph_dict, model=model)
        evaluation_time = time.time() - evaluation_start

        # Calculate evaluation summary
        composite_scores = [
            path["evaluation"]["composite_score"]
            for path in scored_paths
            if "evaluation" in path and "composite_score" in path["evaluation"]
        ]

        evaluation_summary = {
            "paths_scored": len(scored_paths),
            "highest_score": max(composite_scores) if composite_scores else 0,
            "lowest_score": min(composite_scores) if composite_scores else 0,
            "mean_score": round(sum(composite_scores) / len(composite_scores), 2) if composite_scores else 0,
            "execution_time_seconds": round(evaluation_time, 2),
        }

        logger.info(
            f"Evaluation complete: {len(scored_paths)} paths scored in {evaluation_time:.2f}s"
        )

        # Phase 4: Adversarial Validation (Layer 3)
        logger.info("Pipeline Phase 4: Adversarial Validation (Layer 3)")
        adversarial_start = time.time()

        # Convert to JSON for adversarial crew
        scored_paths_json = json.dumps(scored_paths, indent=2)
        asset_graph_json = json.dumps(asset_graph_dict, indent=2)

        # Build and execute adversarial crew
        adversarial_crew = build_adversarial_crew(scored_paths_json, asset_graph_json, model_override=model)
        adversarial_output = adversarial_crew.kickoff()

        # Parse adversarial results
        adversarial_result = parse_adversarial_results(adversarial_output, scored_paths)
        adversarial_time = time.time() - adversarial_start

        # Extract adversarial summary
        red_analysis = adversarial_result.get("red_analysis", {})
        blue_challenges = adversarial_result.get("blue_challenges", {})

        adversarial_summary = {
            "paths_challenged": len(blue_challenges.get("challenges", [])),
            "paths_added": len(red_analysis.get("additional_paths", [])),
            "coverage_estimate": adversarial_result.get("coverage_assessment", "Unknown"),
            "paths_fully_valid": len(blue_challenges.get("paths_fully_valid", [])),
            "paths_partially_valid": len(blue_challenges.get("paths_partially_valid", [])),
            "paths_invalid": len(blue_challenges.get("paths_invalid", [])),
            "execution_time_seconds": round(adversarial_time, 2),
        }

        logger.info(
            f"Adversarial validation complete: {len(adversarial_result['final_paths'])} "
            f"final paths in {adversarial_time:.2f}s"
        )

        # Phase 4.5: Output filtering and confirmed findings extraction
        logger.info("Pipeline Phase 4.5: Output filtering")
        confirmed_paths = extract_confirmed_findings_as_paths(vuln_context)
        all_paths = confirmed_paths + adversarial_result["final_paths"]
        filtered_final_paths = filter_and_rank_paths(
            paths=all_paths,
            vuln_context=vuln_context,
        )
        confirmed_findings = build_confirmed_findings_summary(vuln_context)
        logger.info(
            f"Output filtering complete: {len(confirmed_findings)} confirmed findings, "
            f"{len(filtered_final_paths)} final paths"
        )

        # Phase 5: Mitigation Mapping
        logger.info("Pipeline Phase 5: Mitigation Mapping")
        final_paths_with_mitigations = map_mitigations(filtered_final_paths)

        # Phase 5.5: CSA CII Risk Assessment
        logger.info(f"Pipeline Phase 5.5: CSA CII Risk Assessment (impact score: {impact_score})")
        csa_assessment = score_all_paths(
            paths=final_paths_with_mitigations,
            impact_score=impact_score
        )
        final_paths_with_mitigations = csa_assessment.get('scored_paths', final_paths_with_mitigations)
        logger.info(
            f"CSA risk assessment complete: {csa_assessment.get('paths_scored', 0)} paths scored, "
            f"highest band: {csa_assessment.get('highest_band', 'Unknown')}"
        )

        # Get executive summary
        executive_summary = adversarial_result.get("executive_summary", "")

        execution_time = time.time() - start_time
        logger.info(
            f"Full pipeline complete in {execution_time:.2f}s: "
            f"{len(final_paths_with_mitigations)} validated paths with mitigations"
        )

        # Build vulnerability intelligence response
        vuln_intel_response = {
            "stats": vuln_context.stats,
            "matched_vulns": [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "name": v.name,
                    "resource_id": v.resource_id,
                    "technique_id": v.technique_id,
                    "cvss_score": v.cvss_score,
                    "risk_score": v.risk_score,
                    "in_kev": v.in_kev,
                    "match_confidence": v.match_confidence,
                    "exploitation_commands": v.exploitation_commands[:3],
                    "detection_gap": v.detection_gap,
                }
                for v in vuln_context.matched_vulns[:20]
            ],
            "assembled_chains": [
                {
                    "chain_id": c.chain_id,
                    "chain_score": c.chain_score,
                    "has_kev_vuln": c.has_kev_vuln,
                    "undetectable_steps": c.undetectable_steps,
                    "summary": c.summary,
                }
                for c in vuln_context.assembled_chains
            ],
        }

        response = PipelineResponse(
            status="ok",
            asset_graph=asset_graph_dict,
            security_findings=security_findings_list,
            vulnerability_intelligence=vuln_intel_response,
            confirmed_findings=confirmed_findings,
            persona_selection={
                'requested': requested_persona_ids,
                'final': active_personas,
                'injected_for_high_confidence_findings': injected_personas,
                'consensus': high_consensus[:10],  # Top 10 high-consensus techniques
            },
            exploration_summary=exploration_summary,
            evaluation_summary=evaluation_summary,
            adversarial_summary=adversarial_summary,
            final_paths=final_paths_with_mitigations,
            executive_summary=executive_summary,
            execution_time_seconds=round(execution_time, 2),
            csa_risk_assessment=csa_assessment,
        )

        # Auto-save to archive
        try:
            archive_service = get_archive_service()
            archive_service.save_run(
                pipeline_result=response.model_dump(),
                file_name=file.filename,
                mode="full",
                agent_name=None,
                model_used=get_current_model_name(),
            )
            logger.info(f"Archived full pipeline run for {file.filename}")
        except Exception as e:
            logger.error(f"Failed to archive run: {e}", exc_info=True)
            # Continue - don't fail the pipeline if archiving fails

        return response

    except HTTPException:
        # Re-raise HTTP exceptions (validation errors, LLM not configured, etc.)
        raise
    except TimeoutError as e:
        execution_time = time.time() - start_time
        logger.error(f"Full pipeline timeout after {execution_time:.2f}s: {e}")
        raise HTTPException(
            status_code=504,
            detail={
                "error": "Pipeline Timeout",
                "message": "Threat modeling pipeline exceeded maximum execution time",
                "execution_time_seconds": round(execution_time, 2)
            }
        )
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Full pipeline failed after {execution_time:.2f}s: {e}", exc_info=True)

        # Return error response instead of raising to provide partial results if any
        return PipelineResponse(
            status="error",
            asset_graph={},
            security_findings=[],
            vulnerability_intelligence={},
            confirmed_findings=[],
            persona_selection={},
            exploration_summary={},
            evaluation_summary={},
            adversarial_summary={},
            final_paths=[],
            executive_summary="",
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )


@router.post("/run/quick", response_model=PipelineResponse)
async def run_quick_pipeline(
    file: UploadFile = File(...),
    model: str = Form(None),
    impact_score: int = Form(3)
):
    """
    Run a 2 agents test version of the threat modeling pipeline with reduced agents.

    This endpoint runs the same three-layer pipeline as /run but uses only
    2 threat actor personas in the exploration phase for faster execution:
    - APT29 (Cozy Bear)
    - Scattered Spider

    The evaluation and adversarial validation phases run normally with all agents.

    This is ideal for:
    - Rapid prototyping and testing
    - Development iterations
    - Quick infrastructure assessments
    - Cost-conscious analysis

    **Typical execution time:** 5-8 minutes (vs 10+ for full pipeline)

    Args:
        file: IaC file upload (.tf, .yaml, .yml, or .json)
        model: Optional LLM model name to use (e.g., "qwen3:14b", "gemma4:e4b")
        impact_score: CSA CII impact classification (1=Negligible, 2=Minor, 3=Moderate, 4=Severe, 5=Very Severe). Default: 3

    Returns:
        PipelineResponse with threat model from 2 exploration agents

    Raises:
        HTTPException: 503 if LLM not configured, 413 if file too large,
                      422 if file format unsupported, 500 for other errors
    """
    # Lazy import to avoid CrewAI initialization at module load
    from app.swarm.crews import build_adversarial_crew, parse_adversarial_results

    start_time = time.time()

    # Log model selection
    if model:
        logger.info(f"Quick pipeline using model override: {model}")
    else:
        logger.info("Quick pipeline using default model from .env")

    # Save original persona states
    registry = PersonaRegistry()
    original_states = {
        name: persona.get("enabled", True)
        for name, persona in registry.get_all().items()
    }

    try:
        # Check LLM configuration before starting
        check_llm_configured()

        # Validate model is not WIP
        validate_model_not_wip(model)

        # Phase 1: Parse IaC file
        logger.info("=" * 60)
        logger.info("Starting 2 agents test Pipeline")
        logger.info(f"File: {file.filename}")
        logger.info("=" * 60)
        logger.info("2 agents test Phase 1: Parsing IaC file")
        asset_graph = await _parse_iac_file(file)
        asset_graph_dict = asset_graph.model_dump()

        # Build threat intel context
        logger.info("Building threat intelligence context")
        threat_intel_context, intel_count = _build_threat_intel_context()

        # Run security analysis
        logger.info("Phase 1.5: Running LLM-based security analysis")
        security_findings_context, security_findings_list = await _run_security_analysis(
            asset_graph_dict,
            raw_iac=None,
            model=model
        )

        # Phase 1.6: Build vulnerability intelligence context
        logger.info("Phase 1.6: Building vulnerability intelligence context")
        from app.swarm.vuln_intel.vuln_context_builder import VulnContextBuilder
        vuln_builder = VulnContextBuilder(nvd_api_key=os.getenv('NVD_API_KEY'))
        vuln_context = await vuln_builder.build(
            asset_graph=asset_graph_dict,
            raw_iac=None,
            include_cve_lookup=bool(os.getenv('NVD_API_KEY')) and os.getenv('ENABLE_CVE_LOOKUP', 'true').lower() == 'true',
        )
        logger.info(
            f"Vulnerability context built: {vuln_context.stats['vulns_matched']} vulns, "
            f"{vuln_context.stats['chains_assembled']} chains"
        )

        # Phase 1.7: Dynamic persona selection based on findings
        logger.info("Phase 1.7: Dynamic persona selection")
        all_persona_ids = list(original_states.keys())
        active_personas, injected_personas = select_personas_for_context(
            requested_personas=["apt29_cozy_bear", "scattered_spider"],
            vuln_context=vuln_context,
            run_type='quick',
            all_available_personas=all_persona_ids,
        )
        active_personas = get_persona_priority_order(active_personas, vuln_context)
        logger.info(
            f"Persona selection: requested=['apt29_cozy_bear', 'scattered_spider'], "
            f"final={active_personas}, injected={injected_personas}"
        )

        # Temporarily configure personas for 2 agents test mode
        logger.info("Configuring personas for 2 agents test mode with selected personas")
        for name in original_states.keys():
            registry.toggle_persona(name, False)

        # Enable selected personas
        for persona_id in active_personas:
            registry.toggle_persona(persona_id, True)

        # Phase 2: Exploration (Layer 1) - 2 agents test mode with 2 agents
        logger.info("2 agents test Phase 2: Exploration with 2 agents")
        exploration_start = time.time()
        exploration_paths = _run_exploration(
            asset_graph_dict,
            threat_intel_context,
            security_findings_context=security_findings_context,
            model=model,
            vuln_context=vuln_context
        )
        exploration_time = time.time() - exploration_start

        exploration_summary = {
            "agents_used": 2,
            "raw_paths_found": len(exploration_paths),
            "execution_time_seconds": round(exploration_time, 2),
            "threat_intel_items": intel_count,
        }

        logger.info(
            f"2 agents test exploration complete: {len(exploration_paths)} paths from "
            f"2 agents in {exploration_time:.2f}s"
        )

        # Phase 2.5: LLM-based Path Evaluation against Security Findings
        logger.info("2 agents test Phase 2.5: LLM-based Path Evaluation")
        path_eval_start = time.time()
        exploration_paths = await _run_path_evaluation(
            exploration_paths,
            security_findings_list,
            asset_graph_dict,
            model=model
        )
        path_eval_time = time.time() - path_eval_start
        logger.info(
            f"Path evaluation complete: {len(exploration_paths)} paths evaluated "
            f"in {path_eval_time:.2f}s"
        )

        # Phase 3: Evaluation (Layer 2)
        logger.info("2 agents test Phase 3: Evaluation (Layer 2)")
        evaluation_start = time.time()
        scored_paths = _run_evaluation(exploration_paths, asset_graph_dict, model=model)
        evaluation_time = time.time() - evaluation_start

        composite_scores = [
            path["evaluation"]["composite_score"]
            for path in scored_paths
            if "evaluation" in path and "composite_score" in path["evaluation"]
        ]

        evaluation_summary = {
            "paths_scored": len(scored_paths),
            "highest_score": max(composite_scores) if composite_scores else 0,
            "lowest_score": min(composite_scores) if composite_scores else 0,
            "mean_score": round(sum(composite_scores) / len(composite_scores), 2) if composite_scores else 0,
            "execution_time_seconds": round(evaluation_time, 2),
        }

        logger.info(
            f"Evaluation complete: {len(scored_paths)} paths scored in {evaluation_time:.2f}s"
        )

        # Phase 4: Adversarial Validation (Layer 3)
        logger.info("2 agents test Phase 4: Adversarial Validation (Layer 3)")
        adversarial_start = time.time()

        scored_paths_json = json.dumps(scored_paths, indent=2)
        asset_graph_json = json.dumps(asset_graph_dict, indent=2)

        adversarial_crew = build_adversarial_crew(scored_paths_json, asset_graph_json, model_override=model)
        adversarial_output = adversarial_crew.kickoff()

        adversarial_result = parse_adversarial_results(adversarial_output, scored_paths)
        adversarial_time = time.time() - adversarial_start

        red_analysis = adversarial_result.get("red_analysis", {})
        blue_challenges = adversarial_result.get("blue_challenges", {})

        adversarial_summary = {
            "paths_challenged": len(blue_challenges.get("challenges", [])),
            "paths_added": len(red_analysis.get("additional_paths", [])),
            "coverage_estimate": adversarial_result.get("coverage_assessment", "Unknown"),
            "paths_fully_valid": len(blue_challenges.get("paths_fully_valid", [])),
            "paths_partially_valid": len(blue_challenges.get("paths_partially_valid", [])),
            "paths_invalid": len(blue_challenges.get("paths_invalid", [])),
            "execution_time_seconds": round(adversarial_time, 2),
        }

        logger.info(
            f"Adversarial validation complete: {len(adversarial_result['final_paths'])} "
            f"final paths in {adversarial_time:.2f}s"
        )

        # Phase 4.5: Output filtering and confirmed findings extraction
        logger.info("2 agents test Phase 4.5: Output filtering")
        confirmed_paths = extract_confirmed_findings_as_paths(vuln_context)
        all_paths = confirmed_paths + adversarial_result["final_paths"]
        filtered_final_paths = filter_and_rank_paths(
            paths=all_paths,
            vuln_context=vuln_context,
        )
        confirmed_findings = build_confirmed_findings_summary(vuln_context)
        logger.info(
            f"Output filtering complete: {len(confirmed_findings)} confirmed findings, "
            f"{len(filtered_final_paths)} final paths"
        )

        # Phase 5: Mitigation Mapping
        logger.info("2 agents test Phase 5: Mitigation Mapping")
        final_paths_with_mitigations = map_mitigations(filtered_final_paths)

        # Phase 5.5: CSA CII Risk Assessment
        logger.info(f"2 agents test Phase 5.5: CSA CII Risk Assessment (impact score: {impact_score})")
        csa_assessment = score_all_paths(
            paths=final_paths_with_mitigations,
            impact_score=impact_score
        )
        final_paths_with_mitigations = csa_assessment.get('scored_paths', final_paths_with_mitigations)
        logger.info(
            f"CSA risk assessment complete: {csa_assessment.get('paths_scored', 0)} paths scored, "
            f"highest band: {csa_assessment.get('highest_band', 'Unknown')}"
        )

        executive_summary = adversarial_result.get("executive_summary", "")

        execution_time = time.time() - start_time
        logger.info(
            f"Quick pipeline complete in {execution_time:.2f}s: "
            f"{len(final_paths_with_mitigations)} validated paths with mitigations"
        )

        # Build vulnerability intelligence response
        vuln_intel_response = {
            "stats": vuln_context.stats,
            "matched_vulns": [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "name": v.name,
                    "resource_id": v.resource_id,
                    "technique_id": v.technique_id,
                    "cvss_score": v.cvss_score,
                    "risk_score": v.risk_score,
                    "in_kev": v.in_kev,
                    "match_confidence": v.match_confidence,
                    "exploitation_commands": v.exploitation_commands[:3],
                    "detection_gap": v.detection_gap,
                }
                for v in vuln_context.matched_vulns[:20]
            ],
            "assembled_chains": [
                {
                    "chain_id": c.chain_id,
                    "chain_score": c.chain_score,
                    "has_kev_vuln": c.has_kev_vuln,
                    "undetectable_steps": c.undetectable_steps,
                    "summary": c.summary,
                }
                for c in vuln_context.assembled_chains
            ],
        }

        response = PipelineResponse(
            status="ok",
            asset_graph=asset_graph_dict,
            security_findings=security_findings_list,
            vulnerability_intelligence=vuln_intel_response,
            confirmed_findings=confirmed_findings,
            persona_selection={
                'requested': ["apt29_cozy_bear", "scattered_spider"],
                'final': active_personas,
                'injected_for_high_confidence_findings': injected_personas,
            },
            exploration_summary=exploration_summary,
            evaluation_summary=evaluation_summary,
            adversarial_summary=adversarial_summary,
            final_paths=final_paths_with_mitigations,
            executive_summary=executive_summary,
            execution_time_seconds=round(execution_time, 2),
            csa_risk_assessment=csa_assessment,
        )

        # Auto-save to archive
        try:
            archive_service = get_archive_service()
            archive_service.save_run(
                pipeline_result=response.model_dump(),
                file_name=file.filename,
                mode="quick",
                agent_name=None,
                model_used=get_current_model_name(model),
            )
            logger.info(f"Archived quick pipeline run for {file.filename}")
        except Exception as e:
            logger.error(f"Failed to archive run: {e}", exc_info=True)
            # Continue - don't fail the pipeline if archiving fails

        return response

    except HTTPException:
        # Re-raise HTTP exceptions (validation errors, LLM not configured, etc.)
        raise
    except TimeoutError as e:
        execution_time = time.time() - start_time
        logger.error(f"Quick pipeline timeout after {execution_time:.2f}s: {e}")
        raise HTTPException(
            status_code=504,
            detail={
                "error": "Pipeline Timeout",
                "message": "Quick pipeline exceeded maximum execution time",
                "execution_time_seconds": round(execution_time, 2)
            }
        )
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Quick pipeline failed after {execution_time:.2f}s: {e}", exc_info=True)

        return PipelineResponse(
            status="error",
            asset_graph={},
            security_findings=[],
            vulnerability_intelligence={},
            confirmed_findings=[],
            persona_selection={},
            exploration_summary={},
            evaluation_summary={},
            adversarial_summary={},
            final_paths=[],
            executive_summary="",
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )

    finally:
        # Restore original persona states
        logger.info("Restoring original persona states")
        for name, enabled in original_states.items():
            try:
                registry.toggle_persona(name, enabled)
            except Exception as e:
                logger.error(f"Failed to restore persona {name}: {e}")


@router.post("/run/single", response_model=PipelineResponse)
async def run_single_agent_pipeline(
    file: UploadFile = File(...),
    agent_name: str = "apt29_cozy_bear",
    model: str = Form(None),
    impact_score: int = Form(3)
):
    """
    Run threat modeling pipeline with a single selected agent.

    This endpoint runs the full three-layer pipeline using only one attacker
    agent for exploration. This is ideal for:
    - Testing specific threat actor perspectives
    - Rapid iteration on infrastructure changes
    - Focused analysis on particular attack vectors
    - Learning how different agents approach the same infrastructure

    The evaluation and adversarial validation phases run normally with all agents.

    **Typical execution time:** 3-5 minutes

    Args:
        file: IaC file upload (.tf, .yaml, .yml, or .json)
        agent_name: Name of the persona to use (default: apt29_cozy_bear)
        model: Optional LLM model override
        impact_score: CSA CII impact classification (1=Negligible, 2=Minor, 3=Moderate, 4=Severe, 5=Very Severe). Default: 3

    Returns:
        PipelineResponse with threat model from 1 exploration agent

    Raises:
        HTTPException: 503 if LLM not configured, 404 if agent not found,
                      413 if file too large, 422 if file format unsupported,
                      500 for other errors
    """
    # Lazy import to avoid CrewAI initialization at module load
    from app.swarm.crews import build_adversarial_crew, parse_adversarial_results

    start_time = time.time()

    # Save original persona states
    registry = PersonaRegistry()
    original_states = {
        name: persona.get("enabled", True)
        for name, persona in registry.get_all().items()
    }

    try:
        # Check LLM configuration before starting
        check_llm_configured()

        # Validate model is not WIP
        validate_model_not_wip(model)

        # Validate that the requested agent exists
        selected_persona = registry.get_by_name(agent_name)
        if selected_persona is None:
            raise HTTPException(
                status_code=404,
                detail=f"Persona '{agent_name}' not found. Use /api/swarm/personas to get available personas."
            )

        # Phase 1: Parse IaC file
        logger.info("=" * 60)
        logger.info(f"Starting single agent run Pipeline with {selected_persona['display_name']}")
        logger.info(f"File: {file.filename}")
        logger.info("=" * 60)
        logger.info("single agent run Phase 1: Parsing IaC file")
        asset_graph = await _parse_iac_file(file)
        asset_graph_dict = asset_graph.model_dump()

        # Build threat intel context
        logger.info("Building threat intelligence context")
        threat_intel_context, intel_count = _build_threat_intel_context()

        # Run security analysis
        logger.info("Phase 1.5: Running LLM-based security analysis")
        security_findings_context, security_findings_list = await _run_security_analysis(
            asset_graph_dict,
            raw_iac=None,
            model=model
        )

        # Phase 1.6: Build vulnerability intelligence context
        logger.info("Phase 1.6: Building vulnerability intelligence context")
        from app.swarm.vuln_intel.vuln_context_builder import VulnContextBuilder
        vuln_builder = VulnContextBuilder(nvd_api_key=os.getenv('NVD_API_KEY'))
        vuln_context = await vuln_builder.build(
            asset_graph=asset_graph_dict,
            raw_iac=None,
            include_cve_lookup=bool(os.getenv('NVD_API_KEY')) and os.getenv('ENABLE_CVE_LOOKUP', 'true').lower() == 'true',
        )
        logger.info(
            f"Vulnerability context built: {vuln_context.stats['vulns_matched']} vulns, "
            f"{vuln_context.stats['chains_assembled']} chains"
        )

        # Phase 1.7: Dynamic persona selection based on findings
        logger.info("Phase 1.7: Dynamic persona selection")
        all_persona_ids = list(original_states.keys())
        active_personas, injected_personas = select_personas_for_context(
            requested_personas=[agent_name],
            vuln_context=vuln_context,
            run_type='single',
            all_available_personas=all_persona_ids,
        )
        active_personas = get_persona_priority_order(active_personas, vuln_context)
        logger.info(
            f"Persona selection: requested=[{agent_name}], "
            f"final={active_personas}, injected={injected_personas}"
        )

        # Temporarily configure personas for single agent run mode
        logger.info(f"Configuring for single agent run mode with selected personas")
        for name in original_states.keys():
            registry.toggle_persona(name, False)

        # Enable selected personas
        for persona_id in active_personas:
            registry.toggle_persona(persona_id, True)

        # Phase 2: Exploration (Layer 1) - single agent run mode
        logger.info(f"single agent run Phase 2: Exploration with {selected_persona['display_name']}")
        exploration_start = time.time()
        exploration_paths = _run_exploration(
            asset_graph_dict,
            threat_intel_context,
            security_findings_context=security_findings_context,
            model=model,
            vuln_context=vuln_context
        )
        exploration_time = time.time() - exploration_start

        exploration_summary = {
            "agents_used": 1,
            "agent_name": agent_name,
            "agent_display_name": selected_persona["display_name"],
            "raw_paths_found": len(exploration_paths),
            "execution_time_seconds": round(exploration_time, 2),
            "threat_intel_items": intel_count,
        }

        logger.info(
            f"Single agent exploration complete: {len(exploration_paths)} paths from "
            f"{selected_persona['display_name']} in {exploration_time:.2f}s"
        )

        # Phase 2.5: LLM-based Path Evaluation against Security Findings
        logger.info("single agent run Phase 2.5: LLM-based Path Evaluation")
        path_eval_start = time.time()
        exploration_paths = await _run_path_evaluation(
            exploration_paths,
            security_findings_list,
            asset_graph_dict,
            model=model
        )
        path_eval_time = time.time() - path_eval_start
        logger.info(
            f"Path evaluation complete: {len(exploration_paths)} paths evaluated "
            f"in {path_eval_time:.2f}s"
        )

        # Phase 3: Evaluation (Layer 2)
        logger.info("single agent run Phase 3: Evaluation (Layer 2)")
        evaluation_start = time.time()
        scored_paths = _run_evaluation(exploration_paths, asset_graph_dict, model=model)
        evaluation_time = time.time() - evaluation_start

        composite_scores = [
            path["evaluation"]["composite_score"]
            for path in scored_paths
            if "evaluation" in path and "composite_score" in path["evaluation"]
        ]

        evaluation_summary = {
            "paths_scored": len(scored_paths),
            "highest_score": max(composite_scores) if composite_scores else 0,
            "lowest_score": min(composite_scores) if composite_scores else 0,
            "mean_score": round(sum(composite_scores) / len(composite_scores), 2) if composite_scores else 0,
            "execution_time_seconds": round(evaluation_time, 2),
        }

        logger.info(
            f"Evaluation complete: {len(scored_paths)} paths scored in {evaluation_time:.2f}s"
        )

        # Phase 4: Adversarial Validation (Layer 3)
        logger.info("single agent run Phase 4: Adversarial Validation (Layer 3)")
        adversarial_start = time.time()

        scored_paths_json = json.dumps(scored_paths, indent=2)
        asset_graph_json = json.dumps(asset_graph_dict, indent=2)

        adversarial_crew = build_adversarial_crew(scored_paths_json, asset_graph_json, model_override=model)
        adversarial_output = adversarial_crew.kickoff()

        adversarial_result = parse_adversarial_results(adversarial_output, scored_paths)
        adversarial_time = time.time() - adversarial_start

        red_analysis = adversarial_result.get("red_analysis", {})
        blue_challenges = adversarial_result.get("blue_challenges", {})

        adversarial_summary = {
            "paths_challenged": len(blue_challenges.get("challenges", [])),
            "paths_added": len(red_analysis.get("additional_paths", [])),
            "coverage_estimate": adversarial_result.get("coverage_assessment", "Unknown"),
            "paths_fully_valid": len(blue_challenges.get("paths_fully_valid", [])),
            "paths_partially_valid": len(blue_challenges.get("paths_partially_valid", [])),
            "paths_invalid": len(blue_challenges.get("paths_invalid", [])),
            "execution_time_seconds": round(adversarial_time, 2),
        }

        logger.info(
            f"Adversarial validation complete: {len(adversarial_result['final_paths'])} "
            f"final paths in {adversarial_time:.2f}s"
        )

        # Phase 4.5: Output filtering and confirmed findings extraction
        logger.info("single agent run Phase 4.5: Output filtering")
        confirmed_paths = extract_confirmed_findings_as_paths(vuln_context)
        all_paths = confirmed_paths + adversarial_result["final_paths"]
        filtered_final_paths = filter_and_rank_paths(
            paths=all_paths,
            vuln_context=vuln_context,
        )
        confirmed_findings = build_confirmed_findings_summary(vuln_context)
        logger.info(
            f"Output filtering complete: {len(confirmed_findings)} confirmed findings, "
            f"{len(filtered_final_paths)} final paths"
        )

        # Phase 5: Mitigation Mapping
        logger.info("single agent run Phase 5: Mitigation Mapping")
        final_paths_with_mitigations = map_mitigations(filtered_final_paths)

        # Phase 5.5: CSA CII Risk Assessment
        logger.info(f"single agent run Phase 5.5: CSA CII Risk Assessment (impact score: {impact_score})")
        csa_assessment = score_all_paths(
            paths=final_paths_with_mitigations,
            impact_score=impact_score
        )
        final_paths_with_mitigations = csa_assessment.get('scored_paths', final_paths_with_mitigations)
        logger.info(
            f"CSA risk assessment complete: {csa_assessment.get('paths_scored', 0)} paths scored, "
            f"highest band: {csa_assessment.get('highest_band', 'Unknown')}"
        )

        executive_summary = adversarial_result.get("executive_summary", "")

        execution_time = time.time() - start_time
        logger.info(
            f"Single agent pipeline complete in {execution_time:.2f}s: "
            f"{len(final_paths_with_mitigations)} validated paths with mitigations"
        )

        # Build vulnerability intelligence response
        vuln_intel_response = {
            "stats": vuln_context.stats,
            "matched_vulns": [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "name": v.name,
                    "resource_id": v.resource_id,
                    "technique_id": v.technique_id,
                    "cvss_score": v.cvss_score,
                    "risk_score": v.risk_score,
                    "in_kev": v.in_kev,
                    "match_confidence": v.match_confidence,
                    "exploitation_commands": v.exploitation_commands[:3],
                    "detection_gap": v.detection_gap,
                }
                for v in vuln_context.matched_vulns[:20]
            ],
            "assembled_chains": [
                {
                    "chain_id": c.chain_id,
                    "chain_score": c.chain_score,
                    "has_kev_vuln": c.has_kev_vuln,
                    "undetectable_steps": c.undetectable_steps,
                    "summary": c.summary,
                }
                for c in vuln_context.assembled_chains
            ],
        }

        response = PipelineResponse(
            status="ok",
            asset_graph=asset_graph_dict,
            security_findings=security_findings_list,
            vulnerability_intelligence=vuln_intel_response,
            confirmed_findings=confirmed_findings,
            persona_selection={
                'requested': [agent_name],
                'final': active_personas,
                'injected_for_high_confidence_findings': injected_personas,
            },
            exploration_summary=exploration_summary,
            evaluation_summary=evaluation_summary,
            adversarial_summary=adversarial_summary,
            final_paths=final_paths_with_mitigations,
            executive_summary=executive_summary,
            execution_time_seconds=round(execution_time, 2),
            csa_risk_assessment=csa_assessment,
        )

        # Auto-save to archive
        try:
            archive_service = get_archive_service()
            archive_service.save_run(
                pipeline_result=response.model_dump(),
                file_name=file.filename,
                mode="single",
                agent_name=agent_name,
                model_used=get_current_model_name(model),
            )
            logger.info(f"Archived single agent pipeline run for {file.filename} (agent: {agent_name})")
        except Exception as e:
            logger.error(f"Failed to archive run: {e}", exc_info=True)
            # Continue - don't fail the pipeline if archiving fails

        return response

    except HTTPException:
        raise
    except TimeoutError as e:
        execution_time = time.time() - start_time
        logger.error(f"Single agent pipeline timeout after {execution_time:.2f}s: {e}")
        raise HTTPException(
            status_code=504,
            detail={
                "error": "Pipeline Timeout",
                "message": "Single agent pipeline exceeded maximum execution time",
                "execution_time_seconds": round(execution_time, 2)
            }
        )
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Single agent pipeline failed after {execution_time:.2f}s: {e}", exc_info=True)

        return PipelineResponse(
            status="error",
            asset_graph={},
            security_findings=[],
            vulnerability_intelligence={},
            confirmed_findings=[],
            persona_selection={},
            exploration_summary={},
            evaluation_summary={},
            adversarial_summary={},
            final_paths=[],
            executive_summary="",
            execution_time_seconds=round(execution_time, 2),
            error=str(e),
        )

    finally:
        # Restore original persona states
        logger.info("Restoring original persona states")
        for name, enabled in original_states.items():
            try:
                registry.toggle_persona(name, enabled)
            except Exception as e:
                logger.error(f"Failed to restore persona {name}: {e}")


# =============================================================================
# Job Status and Background Processing Endpoints
# =============================================================================


@router.get("/job/{job_id}/status", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """
    Get the status of a background pipeline job.

    Use this endpoint to check the progress of a long-running pipeline analysis.
    The job_id is returned when you submit a file to /run/background or /run/quick/background.

    Args:
        job_id: Unique job identifier

    Returns:
        JobStatusResponse with current status, progress, and phase information

    Raises:
        HTTPException: 404 if job not found
    """
    tracker = get_job_tracker()
    job = tracker.get_job(job_id)

    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return JobStatusResponse(**job.to_dict())


@router.get("/job/{job_id}/result", response_model=JobResultResponse)
async def get_job_result(job_id: str):
    """
    Get the results of a completed pipeline job.

    This endpoint returns the full pipeline results once the job is completed.
    Check /job/{job_id}/status first to ensure the job has finished.

    Args:
        job_id: Unique job identifier

    Returns:
        JobResultResponse with complete pipeline results

    Raises:
        HTTPException: 404 if job not found, 425 if job not yet completed, 500 if job failed
    """
    tracker = get_job_tracker()
    job = tracker.get_job(job_id)

    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Job failed: {job.error}"
        )

    if job.status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=425,  # Too Early
            detail=f"Job is still running (status: {job.status.value}, {job.progress_percent}% complete). Check /job/{job_id}/status for progress."
        )

    return JobResultResponse(
        job_id=job_id,
        status=job.status.value,
        result=PipelineResponse(**job.result)
    )


@router.get("/jobs", response_model=List[JobStatusResponse])
async def list_jobs(limit: int = 20):
    """
    List recent pipeline jobs.

    Args:
        limit: Maximum number of jobs to return (default 20)

    Returns:
        List of job status summaries
    """
    tracker = get_job_tracker()
    jobs = tracker.list_jobs(limit)
    return [JobStatusResponse(**job) for job in jobs]


@router.post("/cancel/{job_id}")
async def cancel_job(job_id: str):
    """
    Cancel a running pipeline job.

    Args:
        job_id: Job ID to cancel

    Returns:
        Cancellation status message

    Raises:
        HTTPException 404: Job not found
        HTTPException 400: Job cannot be cancelled (already completed/failed/cancelled)
    """
    tracker = get_job_tracker()
    job = tracker.get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail=f"Job {job_id} not found"
        )

    # Check if job can be cancelled
    if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel job: already {job.status.value}"
        )

    # Cancel the job
    success = tracker.cancel_job(job_id)

    if success:
        logger.info(f"Job {job_id[:8]} cancelled successfully via API")
        return {
            "status": "success",
            "message": f"Job {job_id} has been cancelled",
            "job_id": job_id
        }
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to cancel job"
        )


# =============================================================================
# Background Pipeline Execution
# =============================================================================


def _run_quick_pipeline_sync(job_id: str, file_content: bytes, filename: str, model: str = None):
    """
    Run quick pipeline synchronously in background thread.

    This function updates job status as it progresses through each phase.

    Args:
        job_id: Job tracking ID
        file_content: IaC file content
        filename: Name of the file
        model: Optional model name to use instead of default
    """
    tracker = get_job_tracker()
    
    try:
        tracker.update_job(job_id, JobStatus.PARSING, 5, "Parsing IaC file")
        
        # Parse the IaC file
        import io
        from fastapi import UploadFile
        
        file_like = io.BytesIO(file_content)
        # We need to parse manually since we're in a thread
        content_str = file_content.decode("utf-8")
        
        if filename.lower().endswith(".tf"):
            parser = TerraformParser()
            asset_graph = parser.parse(content_str)
        elif filename.lower().endswith((".yaml", ".yml", ".json")):
            extension = "yaml" if filename.lower().endswith((".yaml", ".yml")) else "json"
            parser = CloudFormationParser()
            asset_graph = parser.parse(content_str, file_extension=extension)
        else:
            raise ValueError("Unsupported file format")
        
        asset_graph_dict = asset_graph.model_dump() if hasattr(asset_graph, 'model_dump') else asset_graph.dict()
        
        # Check LLM configuration
        settings = get_settings()
        if not settings.is_llm_configured():
            raise RuntimeError("LLM not configured")
        
        # Build threat intel context
        tracker.update_job(job_id, JobStatus.PARSING, 10, "Loading threat intelligence")
        threat_intel_context, intel_count = _build_threat_intel_context()

        # Note: Security analysis is skipped in background jobs to keep sync execution
        # TODO: Make background jobs async to enable security analysis
        security_findings_context = ""

        # Check for cancellation after parsing
        if tracker.is_job_cancelled(job_id):
            logger.info(f"Job {job_id[:8]} cancelled after parsing phase")
            return

        # Configure personas for 2 agents test mode
        registry = PersonaRegistry()
        original_states = {name: p.get("enabled", True) for name, p in registry.get_all().items()}

        for name in original_states.keys():
            registry.toggle_persona(name, False)
        registry.toggle_persona("apt29_cozy_bear", True)
        registry.toggle_persona("scattered_spider", True)

        try:
            # Phase 1: Exploration
            tracker.update_job(job_id, JobStatus.EXPLORATION, 20, "Exploring attack paths (2 agents test)")
            exploration_start = time.time()
            exploration_paths = _run_exploration(
                asset_graph_dict,
                threat_intel_context,
                security_findings_context=security_findings_context,
                model=model
            )
            exploration_time = time.time() - exploration_start

            exploration_summary = {
                "agents_used": 2,
                "raw_paths_found": len(exploration_paths),
                "execution_time_seconds": round(exploration_time, 2),
            }

            # Check for cancellation after exploration
            if tracker.is_job_cancelled(job_id):
                logger.info(f"Job {job_id[:8]} cancelled after exploration phase")
                return

            # Phase 2: Evaluation
            tracker.update_job(job_id, JobStatus.EVALUATION, 50, "Scoring attack paths (5 evaluators)")
            evaluation_start = time.time()
            scored_paths = _run_evaluation(exploration_paths, asset_graph_dict, model=model)
            evaluation_time = time.time() - evaluation_start
            
            evaluation_summary = {
                "evaluators_used": 5,
                "paths_scored": len(scored_paths),
                "execution_time_seconds": round(evaluation_time, 2),
            }

            # Check for cancellation after evaluation
            if tracker.is_job_cancelled(job_id):
                logger.info(f"Job {job_id[:8]} cancelled after evaluation phase")
                return

            # Phase 3: Adversarial Validation
            tracker.update_job(job_id, JobStatus.ADVERSARIAL, 75, "Adversarial validation (red/blue/arbitrator)")
            
            from app.swarm.crews import build_adversarial_crew, parse_adversarial_results
            
            adversarial_start = time.time()
            scored_paths_json = json.dumps(scored_paths, indent=2)
            asset_graph_json = json.dumps(asset_graph_dict, indent=2)

            adversarial_crew = build_adversarial_crew(scored_paths_json, asset_graph_json, model_override=model)
            adversarial_output = adversarial_crew.kickoff()
            adversarial_result = parse_adversarial_results(adversarial_output, scored_paths)
            adversarial_time = time.time() - adversarial_start
            
            red_analysis = adversarial_result.get("red_analysis", {})
            blue_challenges = adversarial_result.get("blue_challenges", {})
            
            adversarial_summary = {
                "paths_challenged": len(blue_challenges.get("challenges", [])),
                "paths_added": len(red_analysis.get("additional_paths", [])),
                "execution_time_seconds": round(adversarial_time, 2),
            }

            # Check for cancellation after adversarial validation
            if tracker.is_job_cancelled(job_id):
                logger.info(f"Job {job_id[:8]} cancelled after adversarial validation phase")
                return

            # Phase 4: Mitigation Mapping
            tracker.update_job(job_id, JobStatus.MITIGATIONS, 90, "Mapping mitigations")
            final_paths_with_mitigations = map_mitigations(adversarial_result["final_paths"])
            
            executive_summary = adversarial_result.get("executive_summary", "")
            
            # Complete the job
            result = {
                "status": "ok",
                "asset_graph": asset_graph_dict,
                "security_findings": [],  # Skipped in background jobs
                "exploration_summary": exploration_summary,
                "evaluation_summary": evaluation_summary,
                "adversarial_summary": adversarial_summary,
                "final_paths": final_paths_with_mitigations,
                "executive_summary": executive_summary,
                "execution_time_seconds": round(time.time() - exploration_start, 2),
            }
            
            tracker.complete_job(job_id, result)

            # Auto-save to archive
            try:
                archive_service = get_archive_service()
                archive_service.save_run(
                    pipeline_result=result,
                    file_name=filename,
                    mode="quick",
                    agent_name=None,
                    model_used=get_current_model_name(model),
                )
                logger.info(f"Archived background pipeline run for {filename}")
            except Exception as archive_error:
                logger.error(f"Failed to archive background run: {archive_error}", exc_info=True)
                # Continue - don't fail the pipeline if archiving fails

        finally:
            # Restore personas
            for name, was_enabled in original_states.items():
                registry.toggle_persona(name, was_enabled)
            
    except Exception as e:
        logger.error(f"Background pipeline failed for job {job_id}: {e}", exc_info=True)
        tracker.fail_job(job_id, str(e))


@router.post("/run/quick/background", response_model=JobSubmittedResponse)
async def run_quick_pipeline_background(
    file: UploadFile = File(...),
    model: str = None
):
    """
    Run quick pipeline in the background and return immediately with a job ID.

    This endpoint starts the pipeline execution in a background thread and returns
    a job ID that you can use to check status and retrieve results later.

    **Workflow:**
    1. Submit file to this endpoint → get job_id
    2. Poll GET /job/{job_id}/status to check progress
    3. When status is "completed", call GET /job/{job_id}/result to get full results

    **Benefits:**
    - Returns immediately (no long HTTP connection)
    - Track progress in real-time
    - Backend stays responsive
    - No connection timeouts

    Args:
        file: IaC file upload (.tf, .yaml, .yml, or .json)
        model: Optional LLM model to use (e.g., "qwen3:14b", "gemma4:e4b"). If not specified, uses default from .env

    Returns:
        JobSubmittedResponse with job_id and status URL

    Raises:
        HTTPException: 503 if LLM not configured, 413 if file too large,
                      422 if file format unsupported
    """
    # Validate file before starting
    check_llm_configured()

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    filename_lower = file.filename.lower()
    if not any(filename_lower.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file format. Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    # Read file content
    file_content = await file.read()
    if len(file_content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE_MB}MB"
        )

    # Create job
    tracker = get_job_tracker()
    job_id = tracker.create_job(file.filename)

    # Start background execution with optional model
    executor.submit(_run_quick_pipeline_sync, job_id, file_content, file.filename, model)

    model_info = f" using model: {model}" if model else ""
    logger.info(f"Started background pipeline job {job_id} for {file.filename}{model_info}")

    return JobSubmittedResponse(
        job_id=job_id,
        status="pending",
        message=f"Pipeline started for {file.filename}{model_info}. Use the status_url to check progress.",
        estimated_time_minutes=7,
        status_url=f"/api/swarm/job/{job_id}/status"
    )


# =============================================================================
# Post-Mitigation Analysis Endpoint
# =============================================================================


@router.post("/post-mitigation/analyze", response_model=PostMitigationAnalysisResponse)
async def analyze_post_mitigation(request: PostMitigationAnalysisRequest):
    """
    Analyze attack paths after applying user-selected mitigations.

    This endpoint takes the original attack paths and a list of selected mitigations,
    then computes the post-mitigation state for each path. For each attack step,
    it determines whether the step is:
    - **Blocked**: Mitigation completely prevents the attack step
    - **Reduced**: Mitigation makes the attack harder but not impossible
    - **Active**: No effective mitigation applied, step remains fully viable

    The analysis produces:
    - Post-mitigation attack paths with step-by-step impact assessment
    - Residual risk scores for each path
    - Overall residual risk summary with recommendations
    - Top remaining viable attack paths

    **Use Case:**
    1. User reviews initial attack paths and proposed mitigations
    2. User selects which mitigations they plan to implement (checkboxes in UI)
    3. User clicks "Apply Mitigations" to see post-mitigation analysis
    4. System shows side-by-side comparison: pre-mitigation vs post-mitigation
    5. User reviews residual risks and decides if additional mitigations are needed

    Args:
        request: PostMitigationAnalysisRequest with attack_paths and selected_mitigations

    Returns:
        PostMitigationAnalysisResponse with post-mitigation paths and residual risk assessment

    Raises:
        HTTPException: 400 if request is invalid, 500 for unexpected errors
    """
    start_time = time.time()

    try:
        if not request.attack_paths:
            raise HTTPException(
                status_code=400,
                detail="No attack paths provided for analysis"
            )

        if not request.selected_mitigations:
            # No mitigations selected - all paths remain unchanged
            logger.info("No mitigations selected, returning original paths as still viable")

            from app.swarm.models import PostMitigationPath, StepImpact, ResidualRisk

            post_mitigation_paths = []
            for path in request.attack_paths:
                steps = path.get("steps", [])
                step_impacts = [
                    StepImpact(
                        step_number=step.get("step_number", i+1),
                        original_status="active",
                        post_mitigation_status="active",
                        effectiveness="none",
                        reasoning="No mitigations selected",
                        applied_mitigations=[]
                    )
                    for i, step in enumerate(steps)
                ]

                post_mitigation_paths.append(
                    PostMitigationPath(
                        path_id=path.get("id", ""),
                        path_name=path.get("name", ""),
                        original_objective=path.get("objective", ""),
                        original_difficulty=path.get("difficulty", "medium"),
                        post_mitigation_difficulty=path.get("difficulty", "medium"),
                        steps_blocked=0,
                        steps_reduced=0,
                        steps_remaining=len(steps),
                        step_impacts=step_impacts,
                        path_status="still_viable",
                        residual_risk_score=path.get("composite_score", 5.0)
                    )
                )

            residual_risk = ResidualRisk(
                total_paths_analyzed=len(request.attack_paths),
                paths_neutralized=0,
                paths_significantly_reduced=0,
                paths_partially_mitigated=0,
                paths_still_viable=len(request.attack_paths),
                highest_residual_risk_score=max([p.residual_risk_score for p in post_mitigation_paths]),
                mean_residual_risk_score=sum([p.residual_risk_score for p in post_mitigation_paths]) / len(post_mitigation_paths),
                risk_reduction_percentage=0.0,
                top_residual_risks=[
                    {
                        "path_id": p.path_id,
                        "path_name": p.path_name,
                        "residual_risk_score": p.residual_risk_score,
                        "path_status": p.path_status,
                        "steps_remaining": p.steps_remaining,
                    }
                    for p in sorted(post_mitigation_paths, key=lambda x: x.residual_risk_score, reverse=True)[:3]
                ],
                recommendations=[
                    "No mitigations selected. Review recommended mitigations for each attack path step and select controls to implement."
                ]
            )

            return PostMitigationAnalysisResponse(
                status="ok",
                post_mitigation_paths=[p.model_dump() for p in post_mitigation_paths],
                residual_risk=residual_risk.model_dump(),
                execution_time_seconds=round(time.time() - start_time, 2)
            )

        logger.info(
            f"Analyzing post-mitigation impact for {len(request.attack_paths)} paths "
            f"with {len(request.selected_mitigations)} mitigation selections"
        )

        # Perform analysis
        result = analyze_post_mitigation_impact(
            request.attack_paths,
            [m.model_dump() for m in request.selected_mitigations]
        )

        execution_time = time.time() - start_time
        logger.info(f"Post-mitigation analysis complete in {execution_time:.2f}s")

        return PostMitigationAnalysisResponse(
            status="ok",
            post_mitigation_paths=result["post_mitigation_paths"],
            residual_risk=result["residual_risk"],
            execution_time_seconds=round(execution_time, 2)
        )

    except HTTPException:
        raise
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Post-mitigation analysis failed after {execution_time:.2f}s: {e}", exc_info=True)

        return PostMitigationAnalysisResponse(
            status="error",
            post_mitigation_paths=[],
            residual_risk={
                "total_paths_analyzed": 0,
                "paths_neutralized": 0,
                "paths_significantly_reduced": 0,
                "paths_partially_mitigated": 0,
                "paths_still_viable": 0,
                "highest_residual_risk_score": 0.0,
                "mean_residual_risk_score": 0.0,
                "risk_reduction_percentage": 0.0,
                "top_residual_risks": [],
                "recommendations": []
            },
            execution_time_seconds=round(execution_time, 2),
            error=str(e)
        )


class StigmergicSwarmResponse(BaseModel):
    """Response model for stigmergic swarm exploration (Phase 10)."""

    run_type: str = Field(default="multi_agents_swarm", description="Type of run executed")
    execution_order: str = Field(..., description="Persona execution order strategy used")
    personas_used: List[str] = Field(..., description="Display names of personas executed")
    attack_paths: List[Dict[str, Any]] = Field(..., description="All discovered attack paths")
    shared_graph_snapshot: Dict[str, Any] = Field(..., description="Final shared attack graph state")
    emergent_insights: Dict[str, Any] = Field(
        ...,
        description="Emergent patterns from collective agent behavior"
    )
    activity_log: List[Dict[str, Any]] = Field(..., description="Complete agent activity log")
    personas_execution_sequence: List[str] = Field(
        ...,
        description="Ordered list of persona names as executed"
    )
    asset_graph: Dict[str, Any] = Field(..., description="Parsed infrastructure asset graph")
    security_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Pre-identified security findings from LLM analysis of IaC"
    )
    vulnerability_intelligence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Vulnerability intelligence including cloud signals, matched CVEs/abuse patterns, and assembled chains",
    )
    confirmed_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="High-confidence confirmed vulnerability findings from VulnMatcher (CONFIRMED confidence only)",
    )
    evaluation_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of evaluation metrics across all paths"
    )
    csa_risk_assessment: Dict[str, Any] | None = Field(
        default=None,
        description="CSA CII 5×5 risk matrix assessment with scored paths, risk distribution, and tolerance actions",
    )
    status: str = Field(default="ok", description="Status: ok or error")
    execution_time_seconds: float = Field(..., description="Total execution time")
    error: str | None = Field(default=None, description="Error message if status is error")


@router.post("/run/stigmergic", response_model=StigmergicSwarmResponse)
async def run_stigmergic_swarm_pipeline(
    file: UploadFile = File(...),
    execution_order: str = "capability_ascending",
    persona_limit: int | None = None,
    model: str = Form(None),
    impact_score: int = Form(3)
):
    """
    Run Phase 10: Stigmergic Swarm Exploration with sequential agent coordination.

    This endpoint implements stigmergic coordination where threat actor personas
    explore infrastructure sequentially while sharing knowledge through a shared
    attack graph. Each agent deposits their findings, and later agents can see
    and reinforce paths discovered by earlier agents (ant colony optimization).

    **Stigmergic Coordination Features:**
    - Sequential execution with configurable persona ordering
    - Shared attack graph for indirect agent-to-agent coordination
    - Pheromone-based reinforcement when multiple agents discover same techniques
    - High-confidence techniques emerge from collective agent behavior
    - Coverage gap analysis across infrastructure assets

    **Execution Order Strategies:**
    - `capability_ascending` (default): Execute from least to most sophisticated
    - `random`: Randomize execution order to reduce bias
    - `threat_actor_first`: Execute real threat actors before archetypes

    **Emergent Insights:**
    - High-confidence techniques: Reinforced by 2+ agents
    - Convergent paths: Multi-step sequences discovered by multiple agents
    - Coverage gaps: Assets with no attack deposits
    - Technique clusters: Techniques that frequently co-occur

    Args:
        file: IaC file upload (.tf, .yaml, .yml, or .json)
        execution_order: Persona ordering strategy (default: capability_ascending)
        persona_limit: Optional limit on number of personas to execute (default: all)
        model: Optional model override for this run
        impact_score: CSA CII impact classification (1=Negligible, 2=Minor, 3=Moderate, 4=Severe, 5=Very Severe). Default: 3

    Returns:
        StigmergicSwarmResponse with attack paths, shared graph, emergent insights

    Raises:
        HTTPException: 503 if LLM not configured, 413 if file too large,
                      422 if file format unsupported, 500 for other errors
    """
    # Lazy import to avoid initialization at module load
    from app.swarm.swarm_exploration import run_swarm_exploration

    start_time = time.time()

    # Log model override if provided
    if model:
        logger.info(f"Stigmergic swarm pipeline using model override: {model}")
    else:
        logger.info("Stigmergic swarm pipeline using default model from .env")

    try:
        # Check LLM configuration before starting
        check_llm_configured()

        # Validate model is not WIP
        validate_model_not_wip(model)

        # Phase 1: Parse IaC file
        logger.info("=" * 60)
        logger.info("Starting Phase 10: Stigmergic Swarm Exploration Pipeline")
        logger.info(f"File: {file.filename}")
        logger.info(f"Execution order: {execution_order}")
        if persona_limit:
            logger.info(f"Persona limit: {persona_limit}")
        logger.info("=" * 60)

        logger.info("Phase 1: Parsing IaC file")
        asset_graph = await _parse_iac_file(file)
        asset_graph_dict = asset_graph.model_dump()

        # Get enabled personas
        enabled_personas_dict = persona_registry.get_enabled()

        # Convert personas dict to list format expected by run_swarm_exploration
        enabled_personas_list = []
        for persona_name, persona_config in enabled_personas_dict.items():
            persona_entry = {
                "name": persona_name,
                **persona_config
            }
            enabled_personas_list.append(persona_entry)

        # Apply persona limit if specified
        if persona_limit and persona_limit > 0:
            enabled_personas_list = enabled_personas_list[:persona_limit]
            logger.info(f"Limited to {len(enabled_personas_list)} personas")

        if not enabled_personas_list:
            raise HTTPException(
                status_code=400,
                detail="No enabled personas found. Enable at least one persona to run stigmergic swarm."
            )

        logger.info(f"Executing with {len(enabled_personas_list)} enabled personas")

        # Run security analysis
        logger.info("Phase 1.5: Running LLM-based security analysis")
        security_findings_context, security_findings_list = await _run_security_analysis(
            asset_graph_dict,
            raw_iac=None,
            model=model
        )

        # Phase 1.6: Build vulnerability intelligence context
        logger.info("Phase 1.6: Building vulnerability intelligence context")
        from app.swarm.vuln_intel.vuln_context_builder import VulnContextBuilder
        vuln_builder = VulnContextBuilder(nvd_api_key=os.getenv('NVD_API_KEY'))
        vuln_context = await vuln_builder.build(
            asset_graph=asset_graph_dict,
            raw_iac=None,
            include_cve_lookup=bool(os.getenv('NVD_API_KEY')) and os.getenv('ENABLE_CVE_LOOKUP', 'true').lower() == 'true',
        )
        logger.info(
            f"Vulnerability context built: {vuln_context.stats['vulns_matched']} vulns, "
            f"{vuln_context.stats['chains_assembled']} chains"
        )

        # Build LLM config
        llm_config = {
            "model": model,
            "provider": get_settings().LLM_PROVIDER
        }

        # Phase 2: Run stigmergic swarm exploration
        logger.info("Phase 2: Stigmergic Swarm Exploration")
        swarm_result = await run_swarm_exploration(
            asset_graph=asset_graph_dict,
            enabled_personas=enabled_personas_list,
            llm_config=llm_config,
            execution_order=execution_order,
            security_findings_context=security_findings_context,
            security_findings_list=security_findings_list,  # Pass findings for seeding
            progress_callback=None,  # No callback for now
            vuln_context=vuln_context
        )

        # Extract results
        attack_paths = swarm_result.get("attack_paths", [])
        shared_graph_snapshot = swarm_result.get("shared_graph_snapshot", {})
        emergent_insights = swarm_result.get("emergent_insights", {})
        activity_log = swarm_result.get("activity_log", [])
        execution_summary = swarm_result.get("execution_summary", {})

        # Phase 2.5: LLM-based Path Evaluation against Security Findings
        logger.info("Phase 2.5: LLM-based Path Evaluation")
        path_eval_start = time.time()
        attack_paths = await _run_path_evaluation(
            attack_paths,
            security_findings_list,
            asset_graph_dict,
            model=model
        )
        path_eval_time = time.time() - path_eval_start
        logger.info(
            f"Path evaluation complete: {len(attack_paths)} paths evaluated "
            f"in {path_eval_time:.2f}s"
        )

        # Phase 3: Evaluation (add scores to paths like regular pipeline)
        logger.info("Phase 3: Evaluation")
        evaluation_start = time.time()
        scored_paths = _run_evaluation(attack_paths, asset_graph_dict, model=model)
        evaluation_time = time.time() - evaluation_start

        # Calculate evaluation summary
        composite_scores = [
            path["evaluation"]["composite_score"]
            for path in scored_paths
            if "evaluation" in path and "composite_score" in path["evaluation"]
        ]

        evaluation_summary = {
            "paths_scored": len(scored_paths),
            "highest_score": max(composite_scores) if composite_scores else 0,
            "lowest_score": min(composite_scores) if composite_scores else 0,
            "mean_score": round(sum(composite_scores) / len(composite_scores), 2) if composite_scores else 0,
            "execution_time_seconds": round(evaluation_time, 2),
        }

        logger.info(
            f"Evaluation complete: {len(scored_paths)} paths scored in {evaluation_time:.2f}s"
        )

        # Phase 3.5: Output filtering and confirmed findings extraction
        logger.info("Phase 3.5: Output filtering")
        confirmed_paths = extract_confirmed_findings_as_paths(vuln_context)
        all_paths = confirmed_paths + scored_paths
        filtered_paths = filter_and_rank_paths(
            paths=all_paths,
            vuln_context=vuln_context,
        )
        confirmed_findings = build_confirmed_findings_summary(vuln_context)
        logger.info(
            f"Output filtering complete: {len(confirmed_findings)} confirmed findings, "
            f"{len(filtered_paths)} final paths"
        )

        # Phase 4: Mitigation Mapping (add defence-in-depth mitigations)
        logger.info("Phase 4: Mitigation Mapping")
        final_paths_with_mitigations = map_mitigations(filtered_paths)

        # Phase 4.5: CSA CII Risk Assessment
        logger.info(f"Phase 4.5: CSA CII Risk Assessment (impact score: {impact_score})")
        csa_assessment = score_all_paths(
            paths=final_paths_with_mitigations,
            impact_score=impact_score
        )
        final_paths_with_mitigations = csa_assessment.get('scored_paths', final_paths_with_mitigations)
        logger.info(
            f"CSA risk assessment complete: {csa_assessment.get('paths_scored', 0)} paths scored, "
            f"highest band: {csa_assessment.get('highest_band', 'Unknown')}"
        )

        execution_time = time.time() - start_time

        personas_executed = execution_summary.get("personas_executed", [])

        logger.info("=" * 60)
        logger.info("Phase 10: Stigmergic Swarm Exploration Complete")
        logger.info(f"Total execution time: {execution_time:.2f}s")
        logger.info(f"Total attack paths: {len(final_paths_with_mitigations)}")
        logger.info(f"Total nodes in shared graph: {shared_graph_snapshot.get('statistics', {}).get('total_nodes', 0)}")
        logger.info(f"Reinforced nodes: {shared_graph_snapshot.get('statistics', {}).get('reinforced_nodes', 0)}")
        logger.info(f"High-confidence techniques: {len(emergent_insights.get('high_confidence_techniques', []))}")
        logger.info("=" * 60)

        # Build vulnerability intelligence response
        vuln_intel_response = {
            "stats": vuln_context.stats,
            "matched_vulns": [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "name": v.name,
                    "resource_id": v.resource_id,
                    "technique_id": v.technique_id,
                    "cvss_score": v.cvss_score,
                    "risk_score": v.risk_score,
                    "in_kev": v.in_kev,
                    "match_confidence": v.match_confidence,
                    "exploitation_commands": v.exploitation_commands[:3],
                    "detection_gap": v.detection_gap,
                }
                for v in vuln_context.matched_vulns[:20]
            ],
            "assembled_chains": [
                {
                    "chain_id": c.chain_id,
                    "chain_score": c.chain_score,
                    "has_kev_vuln": c.has_kev_vuln,
                    "undetectable_steps": c.undetectable_steps,
                    "summary": c.summary,
                }
                for c in vuln_context.assembled_chains
            ],
        }

        response = StigmergicSwarmResponse(
            run_type="multi_agents_swarm",
            execution_order=execution_order,
            personas_used=personas_executed,
            attack_paths=final_paths_with_mitigations,
            shared_graph_snapshot=shared_graph_snapshot,
            emergent_insights=emergent_insights,
            activity_log=activity_log,
            personas_execution_sequence=personas_executed,
            asset_graph=asset_graph_dict,
            security_findings=security_findings_list,
            vulnerability_intelligence=vuln_intel_response,
            confirmed_findings=confirmed_findings,
            evaluation_summary=evaluation_summary,
            csa_risk_assessment=csa_assessment,
            status="ok",
            execution_time_seconds=round(execution_time, 2)
        )

        # Auto-save to archive
        try:
            archive_service = get_archive_service()
            archive_service.save_run(
                pipeline_result=response.model_dump(),
                file_name=file.filename,
                mode="stigmergic",
                agent_name=None,
                model_used=get_current_model_name(model),
            )
            logger.info(f"Archived stigmergic swarm run for {file.filename}")
        except Exception as e:
            logger.error(f"Failed to archive run: {e}", exc_info=True)
            # Continue - don't fail the pipeline if archiving fails

        return response

    except HTTPException:
        raise
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Stigmergic swarm pipeline failed after {execution_time:.2f}s: {e}", exc_info=True)

        return StigmergicSwarmResponse(
            run_type="multi_agents_swarm",
            execution_order=execution_order,
            personas_used=[],
            attack_paths=[],
            shared_graph_snapshot={},
            emergent_insights={
                "high_confidence_techniques": [],
                "convergent_paths": [],
                "coverage_gaps": [],
                "technique_clusters": []
            },
            activity_log=[],
            personas_execution_sequence=[],
            asset_graph={},
            security_findings=[],
            vulnerability_intelligence={},
            confirmed_findings=[],
            evaluation_summary={},
            status="error",
            execution_time_seconds=round(execution_time, 2),
            error=str(e)
        )


