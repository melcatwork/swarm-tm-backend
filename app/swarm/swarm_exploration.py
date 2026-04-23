"""Phase 10: Stigmergic Swarm Exploration Orchestrator

This module orchestrates the stigmergic swarm exploration phase, where multiple
threat actor personas explore infrastructure sequentially while sharing knowledge
through a shared attack graph. Each agent deposits their findings, reinforcing
paths discovered by others (stigmergic coordination).

Key Features:
- Sequential execution with persona ordering strategies
- Shared attack graph for indirect agent coordination
- High-pheromone techniques guide later agents
- Emergent pattern detection from collective behavior
"""

import json
import logging
import random
import re
from typing import List, Dict, Any, Optional, Callable
from uuid import uuid4

from crewai import Agent, Crew, Task, Process

from .shared_graph import SharedAttackGraph, AttackNode
from .crews import get_llm, parse_exploration_results
from .agents.persona_registry import PersonaRegistry
from .models import AttackPath, AttackStep
from .knowledge.kb_loader import get_technique_context

logger = logging.getLogger(__name__)


# Capability levels for ordering personas (higher = more sophisticated)
PERSONA_CAPABILITY_LEVELS = {
    "opportunistic_attacker": 1,
    "social_engineering_hybrid": 2,
    "insider_threat": 3,
    "data_exfiltration_optimizer": 4,
    "lateral_movement_specialist": 4,
    "cloud_native_attacker": 5,
    "supply_chain_attacker": 5,
    "fin7": 6,
    "scattered_spider": 6,
    "nation_state_apt": 7,
    "apt29_cozy_bear": 8,
    "lazarus_group": 8,
    "volt_typhoon": 9,
}


def build_swarm_aware_prompt(
    persona: dict,
    asset_graph_summary: str,
    shared_graph_snapshot: dict,
    security_findings_context: str = "",
    vuln_context = None
) -> str:
    """Build a swarm-aware prompt that includes shared graph intelligence.

    Injects high-pheromone techniques and coverage information into the
    persona's context, enabling stigmergic coordination without direct
    agent-to-agent communication.

    Args:
        persona: Persona configuration dict with role, goal, backstory, etc.
        asset_graph_summary: JSON string of infrastructure asset graph
        shared_graph_snapshot: Current state of shared attack graph
        security_findings_context: Pre-identified security findings from LLM analysis
        vuln_context: Optional VulnContext with vulnerability intelligence

    Returns:
        Enhanced backstory string with swarm intelligence context
    """
    # Extract high-pheromone techniques (reinforced by multiple agents)
    high_pheromone_techniques = shared_graph_snapshot.get("high_pheromone_techniques", [])

    # Build swarm intelligence section
    swarm_intel = "\n\n=== SHARED SWARM INTELLIGENCE ===\n"

    if high_pheromone_techniques:
        swarm_intel += "The following techniques have been discovered and REINFORCED by multiple agents "
        swarm_intel += "(high confidence paths):\n\n"

        for tech in high_pheromone_techniques[:10]:  # Top 10 reinforced techniques
            swarm_intel += (
                f"  • {tech['technique_id']} ({tech['technique_name']}) on {tech['asset_id']}\n"
                f"    Pheromone: {tech['pheromone_strength']:.2f}, "
                f"Reinforced: {tech['times_reinforced']} times, "
                f"First discovered by: {tech['deposited_by']}\n"
            )

        swarm_intel += "\n"
    else:
        swarm_intel += "No techniques have been reinforced yet. You are among the first agents exploring.\n\n"

    # Coverage statistics
    stats = shared_graph_snapshot.get("statistics", {})
    swarm_intel += "Swarm Exploration Statistics:\n"
    swarm_intel += f"  • Total nodes deposited: {stats.get('total_nodes', 0)}\n"
    swarm_intel += f"  • Total edges (sequences): {stats.get('total_edges', 0)}\n"
    swarm_intel += f"  • Reinforced nodes: {stats.get('reinforced_nodes', 0)}\n"
    swarm_intel += f"  • Unique assets covered: {stats.get('unique_assets', 0)}\n"
    swarm_intel += f"  • Unique techniques seen: {stats.get('unique_techniques', 0)}\n"

    swarm_intel += "\n=== YOUR MISSION ===\n"
    swarm_intel += "As you analyze this infrastructure, you should:\n"
    swarm_intel += "1. Consider the high-pheromone techniques above (they are high-confidence paths)\n"
    swarm_intel += "2. You MAY choose to build upon these techniques (reinforcement)\n"
    swarm_intel += "3. OR you may diverge and explore completely new attack vectors (exploration)\n"
    swarm_intel += "4. In your JSON output, flag each path as EITHER:\n"
    swarm_intel += "   - reinforces_swarm: true (if your path uses techniques already discovered)\n"
    swarm_intel += "   - diverges_from_swarm: true (if your path explores new techniques)\n\n"

    swarm_intel += "CRITICAL: Maintain the standard kill chain output schema:\n"
    swarm_intel += "- Each attack path must have up to 10 steps\n"
    swarm_intel += "- Each step MUST include: technique_id (MITRE ATT&CK), technique_name, target_asset, "
    swarm_intel += "action_description, outcome, mitigation (with mitigation_id, mitigation_name, description, aws_service_action)\n"
    swarm_intel += "- Add the reinforces_swarm OR diverges_from_swarm flag at the PATH level (not step level)\n"

    # Build complete backstory with swarm intelligence and dynamic security reasoning
    security_reasoning = persona.get('security_reasoning_approach', '')

    full_backstory = (
        f"{persona['backstory']}\n\n"
        f"=== YOUR SECURITY REASONING APPROACH ===\n"
        f"{security_reasoning}\n\n"
        f"=== INFRASTRUCTURE TO ANALYZE ===\n"
        f"You are analysing the following cloud infrastructure. Apply your security reasoning approach "
        f"to identify EVERY misconfiguration, vulnerability, and attack-enabling condition you can find. "
        f"Do not limit yourself to well-known conditions. Use your full security knowledge to discover "
        f"what specific attributes or relationships make resources dangerous and how you would exploit them.\n\n"
        f"{asset_graph_summary}\n\n"
    )

    # Add security findings if available
    if security_findings_context:
        full_backstory += f"\n{security_findings_context}\n\n"
        full_backstory += (
            "These findings were identified through LLM security analysis of the complete IaC. "
            "Use these as starting points for your attack path generation. You may also identify "
            "additional findings the initial analysis missed—your reasoning is not limited to this list.\n\n"
        )

        # === SELECTIVE TECHNIQUE REFERENCE INJECTION ===
        # Extract technique IDs from security findings context and inject
        # only the relevant KB entries (not the entire KB)
        technique_ids = set(re.findall(r'T\d{4}(?:\.\d{3})?', security_findings_context))

        if technique_ids:
            logger.info(f"Injecting KB context for {len(technique_ids)} techniques: {sorted(technique_ids)}")

            # Build technique reference section header
            full_backstory += "\n" + "=" * 80 + "\n"
            full_backstory += "TECHNIQUE REFERENCE (relevant to findings above)\n"
            full_backstory += "=" * 80 + "\n\n"
            full_backstory += (
                f"The following {len(technique_ids)} techniques were identified in the security analysis.\n"
                "Reference material is provided below to guide your attack path construction.\n\n"
            )

            # Inject context for each discovered technique
            for tid in sorted(technique_ids):
                ctx = get_technique_context(tid)
                if ctx:
                    full_backstory += ctx + "\n"
                else:
                    logger.debug(f"No KB entry found for technique {tid}")

            full_backstory += "=" * 80 + "\n\n"

    # Add vulnerability intelligence if available
    if vuln_context:
        full_backstory += f"\n{vuln_context.combined_prompt}\n\n"

    full_backstory += swarm_intel

    return full_backstory


def order_personas(personas: List[dict], strategy: str = "capability_ascending") -> List[dict]:
    """Order personas for sequential execution based on strategy.

    Strategies:
    - capability_ascending: Execute from least to most sophisticated (builds complexity)
    - random: Randomize execution order (reduces bias)
    - threat_actor_first: Execute real threat actors before archetypes

    Args:
        personas: List of persona configuration dictionaries
        strategy: Ordering strategy name

    Returns:
        Ordered list of persona dictionaries
    """
    if strategy == "capability_ascending":
        # Sort by capability level (ascending)
        def get_capability(p):
            persona_name = p.get("name", "unknown")
            return PERSONA_CAPABILITY_LEVELS.get(persona_name, 5)  # Default to 5

        ordered = sorted(personas, key=get_capability)
        logger.info(f"Ordered {len(ordered)} personas by capability (ascending)")
        return ordered

    elif strategy == "random":
        # Randomize order
        ordered = personas.copy()
        random.shuffle(ordered)
        logger.info(f"Randomized order of {len(ordered)} personas")
        return ordered

    elif strategy == "threat_actor_first":
        # Separate threat actors from archetypes
        threat_actors = [p for p in personas if p.get("category") == "threat_actor"]
        archetypes = [p for p in personas if p.get("category") != "threat_actor"]

        ordered = threat_actors + archetypes
        logger.info(
            f"Ordered {len(threat_actors)} threat actors first, "
            f"then {len(archetypes)} archetypes"
        )
        return ordered

    else:
        # Unknown strategy - return original order
        logger.warning(f"Unknown ordering strategy '{strategy}', using original order")
        return personas


def deposit_path_to_shared_graph(
    path: dict,
    persona_name: str,
    shared_graph: SharedAttackGraph
) -> None:
    """Deposit an attack path into the shared graph.

    Iterates through kill chain steps and deposits each as a node, then
    creates edges between consecutive steps. This enables stigmergic
    reinforcement when other agents discover similar paths.

    Args:
        path: Attack path dictionary with steps
        persona_name: Name of persona depositing this path
        shared_graph: SharedAttackGraph instance
    """
    steps = path.get("steps", [])

    if not steps:
        logger.warning(f"Path '{path.get('name', 'unknown')}' has no steps, skipping deposit")
        return

    # Deposit each step as a node
    node_ids = []
    for step in steps:
        technique_id = step.get("technique_id", "UNKNOWN")
        technique_name = step.get("technique_name", "Unknown Technique")
        target_asset = step.get("target_asset", "unknown_asset")
        kill_chain_phase = step.get("kill_chain_phase", "Unknown Phase")

        # Create tags from step metadata
        tags = [
            path.get("impact_type", "unknown"),
            path.get("difficulty", "unknown"),
            f"step_{step.get('step_number', 0)}"
        ]

        node_id = shared_graph.deposit_node(
            asset_id=target_asset,
            technique_id=technique_id,
            technique_name=technique_name,
            kill_chain_phase=kill_chain_phase,
            deposited_by=persona_name,
            tags=tags
        )
        node_ids.append(node_id)

    # Deposit edges between consecutive steps
    for i in range(len(node_ids) - 1):
        source_id = node_ids[i]
        target_id = node_ids[i + 1]

        shared_graph.deposit_edge(
            source_node_id=source_id,
            target_node_id=target_id,
            deposited_by=persona_name,
            relationship="leads_to"
        )

    logger.info(
        f"Deposited {len(node_ids)} nodes and {len(node_ids) - 1} edges "
        f"from path '{path.get('name', 'unknown')}' by {persona_name}"
    )


async def run_swarm_exploration(
    asset_graph: dict,
    enabled_personas: List[Dict[str, Any]],
    llm_config: dict,
    execution_order: str = "capability_ascending",
    security_findings_context: str = "",
    security_findings_list: Optional[List[Any]] = None,
    progress_callback: Optional[Callable[[str, int, int, dict], None]] = None,
    vuln_context = None
) -> dict:
    """Run stigmergic swarm exploration with sequential persona execution.

    Each persona executes sequentially, reading the current shared graph state
    and depositing their findings. Later agents benefit from earlier discoveries
    through stigmergic reinforcement.

    Args:
        asset_graph: Parsed infrastructure asset graph dictionary
        enabled_personas: List of enabled persona configuration dicts
        llm_config: LLM configuration dict with model and provider
        execution_order: Persona ordering strategy (default: capability_ascending)
        security_findings_context: Pre-identified security findings from LLM analysis
        security_findings_list: Optional list of SecurityFinding objects for seeding
        progress_callback: Optional callback(persona_name, step, total, snapshot)
        vuln_context: Optional VulnContext with vulnerability intelligence

    Returns:
        Dictionary with attack_paths, shared_graph_snapshot, emergent_insights, activity_log
    """
    logger.info("=" * 60)
    logger.info("Starting Phase 10: Stigmergic Swarm Exploration")
    logger.info(f"Personas: {len(enabled_personas)}")
    logger.info(f"Execution order: {execution_order}")
    logger.info("=" * 60)

    # Create shared attack graph
    shared_graph = SharedAttackGraph()

    # Seed graph from security findings if available
    if security_findings_list:
        logger.info("Seeding shared graph from security findings")
        seeded_count = shared_graph.seed_from_findings(security_findings_list)
        logger.info(f"Seeded {seeded_count} high-priority nodes from findings")

    # Seed graph from matched vulnerabilities if available
    if vuln_context:
        logger.info("Seeding shared graph from matched vulnerabilities")
        vuln_seed_count = 0
        for vuln in vuln_context.matched_vulns[:5]:  # Top 5 highest risk vulns
            if vuln.risk_score >= 7.0:
                shared_graph.deposit_node(
                    asset_id=vuln.resource_id,
                    technique_id=vuln.technique_id,
                    technique_name=vuln.technique_name,
                    kill_chain_phase=vuln.kill_chain_phase,
                    deposited_by=f'vuln_seed:{vuln.vuln_id}',
                    tags=['vuln_seeded', vuln.match_confidence, vuln.vuln_type],
                    initial_pheromone=vuln.risk_score / 10.0 * 2.5,  # Scale to 0-2.5 range
                )
                vuln_seed_count += 1
        logger.info(f"Seeded {vuln_seed_count} high-risk vulnerability nodes")

    # Serialize asset graph for prompts
    asset_graph_json = json.dumps(asset_graph, indent=2)

    # Order personas based on strategy
    ordered_personas = order_personas(enabled_personas, strategy=execution_order)

    # Collect all attack paths
    all_attack_paths = []

    # Execute each persona sequentially
    total_personas = len(ordered_personas)
    for idx, persona in enumerate(ordered_personas, start=1):
        persona_name = persona.get("name", f"persona_{idx}")
        display_name = persona.get("display_name", persona_name)

        logger.info("-" * 60)
        logger.info(f"Executing Persona {idx}/{total_personas}: {display_name}")
        logger.info("-" * 60)

        # Get current shared graph snapshot
        snapshot = shared_graph.get_snapshot()

        # Build swarm-aware prompt
        full_backstory = build_swarm_aware_prompt(
            persona=persona,
            asset_graph_summary=asset_graph_json,
            shared_graph_snapshot=snapshot,
            security_findings_context=security_findings_context,
            vuln_context=vuln_context
        )

        # Get LLM instance
        model_override = llm_config.get("model")
        llm = get_llm(model_override=model_override)

        # Create single-agent crew
        agent = Agent(
            role=persona["role"],
            goal=persona["goal"],
            backstory=full_backstory,
            verbose=True,
            allow_delegation=False,
            llm=llm,
        )

        # Build TTP focus list
        ttp_focus_list = ", ".join(persona.get("ttp_focus", []))

        # Create exploration task
        task_description = (
            f"Analyse the provided AWS cloud infrastructure through the lens of {display_name}.\n\n"
            f"Identify realistic, end-to-end attack paths from initial reconnaissance to achieving an objective.\n\n"
            f"Each attack path MUST follow the cyber kill chain with up to 10 steps.\n\n"
            f"CRITICAL REQUIREMENTS:\n"
            f"1. Each step MUST include: technique_id (MITRE ATT&CK T-number), technique_name, "
            f"target_asset (exact name from infrastructure), action_description, outcome, mitigation\n"
            f"2. Add reinforces_swarm: true OR diverges_from_swarm: true at the PATH level\n"
            f"3. Focus on your group's known TTPs: {ttp_focus_list}\n\n"
            f"The SHARED SWARM INTELLIGENCE section in your backstory shows techniques discovered by other agents. "
            f"You may reinforce these (build upon them) OR diverge (explore new vectors)."
        )

        expected_output = (
            "JSON array of attack paths with up to 10 steps each. "
            "Each path must include: name, objective, impact_type, difficulty, threat_actor, steps (array), "
            "and EITHER reinforces_swarm: true OR diverges_from_swarm: true. "
            "Each step must have: step_number, kill_chain_phase, technique_id, technique_name, "
            "target_asset, action_description, outcome, mitigation (object). "
            "Return ONLY valid JSON array, no markdown, no explanation."
        )

        task = Task(
            description=task_description,
            expected_output=expected_output,
            agent=agent,
        )

        # Build and execute crew
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        logger.info(f"Executing crew for {display_name}...")

        try:
            crew_output = crew.kickoff()
            logger.info(f"✓ {display_name} completed execution")

            # Parse results
            attack_paths = parse_exploration_results(crew_output)

            if attack_paths:
                logger.info(f"✓ Parsed {len(attack_paths)} attack paths from {display_name}")

                # Deposit each path to shared graph
                for path in attack_paths:
                    # Add persona name to path if not present
                    if "threat_actor" not in path:
                        path["threat_actor"] = display_name

                    # Generate ID if missing
                    if "id" not in path:
                        path["id"] = f"path_{uuid4().hex[:12]}"

                    # Deposit to shared graph
                    deposit_path_to_shared_graph(path, persona_name, shared_graph)

                    # Add to collection
                    all_attack_paths.append(path)

            else:
                logger.warning(f"⚠ {display_name} produced no parseable attack paths")

        except Exception as e:
            logger.error(f"✗ {display_name} failed: {e}", exc_info=True)
            continue

        # Call progress callback if provided
        if progress_callback:
            try:
                progress_callback(display_name, idx, total_personas, snapshot)
            except Exception as cb_error:
                logger.error(f"Progress callback error: {cb_error}")

        logger.info(f"Completed {idx}/{total_personas} personas")

    # Get final snapshot
    final_snapshot = shared_graph.get_snapshot()

    # Extract asset IDs from asset graph for coverage analysis
    asset_ids = []
    if isinstance(asset_graph, dict):
        if "nodes" in asset_graph:
            asset_ids = [node.get("id", node.get("name", "unknown")) for node in asset_graph.get("nodes", [])]
        elif "resources" in asset_graph:
            asset_ids = list(asset_graph.get("resources", {}).keys())
        else:
            # Fallback: extract all string values that look like asset IDs
            asset_ids = [k for k in asset_graph.keys() if isinstance(k, str)]

    # Extract emergent insights
    emergent_insights = shared_graph.extract_emergent_insights(asset_ids)

    logger.info("=" * 60)
    logger.info("Phase 10: Stigmergic Swarm Exploration Complete")
    logger.info(f"Total attack paths discovered: {len(all_attack_paths)}")
    logger.info(f"Total nodes in shared graph: {final_snapshot['statistics']['total_nodes']}")
    logger.info(f"Reinforced nodes: {final_snapshot['statistics']['reinforced_nodes']}")
    logger.info(f"High-confidence techniques: {len(emergent_insights['high_confidence_techniques'])}")
    logger.info(f"Convergent paths: {len(emergent_insights['convergent_paths'])}")
    logger.info(f"Coverage: {emergent_insights['summary']['coverage_percentage']:.1f}%")
    logger.info("=" * 60)

    return {
        "attack_paths": all_attack_paths,
        "shared_graph_snapshot": final_snapshot,
        "emergent_insights": emergent_insights,
        "activity_log": shared_graph.agent_activity_log,
        "execution_summary": {
            "total_personas_executed": total_personas,
            "total_paths_discovered": len(all_attack_paths),
            "execution_order_strategy": execution_order,
            "personas_executed": [p.get("display_name", "unknown") for p in ordered_personas]
        }
    }
