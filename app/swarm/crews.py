"""Crew construction for threat modeling swarms.

Dynamically builds CrewAI crews from enabled personas in the PersonaRegistry.
"""

import json
import logging
import os
import re
from typing import List, Dict, Any
from uuid import uuid4

from crewai import Agent, Crew, Task, Process, LLM

from .agents.persona_registry import PersonaRegistry
from app.config import get_settings

logger = logging.getLogger(__name__)


def get_llm(model_override: str = None, provider_override: str = None) -> LLM:
    """
    Get configured LLM instance based on settings.

    Args:
        model_override: Optional model name to use instead of settings (e.g., "qwen3:14b", "gemma4:e4b")
        provider_override: Optional provider to use instead of settings ("ollama", "bedrock", "anthropic")

    Returns:
        LLM instance configured for the selected provider (Bedrock, Anthropic, or Ollama)
    """
    settings = get_settings()

    # Allow provider override
    provider = provider_override or settings.LLM_PROVIDER

    # Allow model override
    if model_override:
        logger.info(f"[get_llm] Using model override: {model_override}")
        # Detect provider from model override if not explicitly provided
        if not provider_override:
            if model_override.startswith("bedrock/") or model_override.startswith("anthropic.claude"):
                provider = "bedrock"
            elif "claude" in model_override.lower() and not model_override.startswith("ollama/") and not model_override.startswith("anthropic."):
                provider = "anthropic"
            else:
                provider = settings.LLM_PROVIDER  # Keep current provider

    logger.info(f"[get_llm] LLM_PROVIDER: {provider}")
    logger.info(f"[get_llm] Model: {model_override or settings.OLLAMA_MODEL}")
    logger.info(f"[get_llm] OLLAMA_BASE_URL: {settings.OLLAMA_BASE_URL}")

    # CRITICAL: Disable OpenAI globally to prevent any fallback attempts
    # Set dummy values to prevent LiteLLM from trying to connect to OpenAI
    os.environ["OPENAI_API_KEY"] = "sk-disabled-no-openai"
    os.environ["OPENAI_API_BASE"] = settings.OLLAMA_BASE_URL  # Redirect OpenAI to Ollama
    os.environ["OPENAI_API_TYPE"] = "ollama"

    # Set LiteLLM specific variables
    os.environ["LITELLM_LOG"] = "DEBUG"  # Enable debug logging
    os.environ["LITELLM_DROP_PARAMS"] = "true"  # Drop unsupported params

    if provider == "bedrock":
        # Set environment variables for LiteLLM/boto3 to use Bedrock with bearer token
        if not settings.AWS_BEARER_TOKEN_BEDROCK:
            logger.error("No AWS bearer token configured for Bedrock")
            raise RuntimeError("AWS Bedrock requires AWS_BEARER_TOKEN_BEDROCK to be set")

        os.environ["AWS_BEARER_TOKEN_BEDROCK"] = settings.AWS_BEARER_TOKEN_BEDROCK
        logger.info("Using AWS bearer token for Bedrock")

        if settings.AWS_REGION:
            os.environ["AWS_REGION_NAME"] = settings.AWS_REGION
            os.environ["AWS_DEFAULT_REGION"] = settings.AWS_REGION
            os.environ["AWS_REGION"] = settings.AWS_REGION

        # Format model name for Bedrock
        bedrock_model = model_override or settings.BEDROCK_MODEL
        # If model doesn't have bedrock/ prefix, add it
        if not bedrock_model.startswith("bedrock/"):
            bedrock_model = f"bedrock/{bedrock_model}"

        logger.info(f"Using AWS Bedrock with model: {bedrock_model}, region: {settings.AWS_REGION}, temp={settings.LLM_TEMPERATURE}")
        llm = LLM(
            model=bedrock_model,
            temperature=settings.LLM_TEMPERATURE,
            max_tokens=settings.LLM_MAX_TOKENS,
        )

    elif provider == "ollama":
        # Use Ollama (local LLM server)
        # Set multiple environment variables to ensure LiteLLM routes to Ollama
        os.environ["OLLAMA_API_BASE"] = settings.OLLAMA_BASE_URL

        # Test Ollama connectivity before creating LLM
        import requests
        try:
            test_response = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=5)
            if test_response.status_code == 200:
                logger.info(f"✓ Ollama server is reachable at {settings.OLLAMA_BASE_URL}")
            else:
                logger.error(f"✗ Ollama server returned status {test_response.status_code}")
        except Exception as e:
            logger.error(f"✗ Cannot reach Ollama server: {e}")
            raise RuntimeError(f"Ollama server not reachable at {settings.OLLAMA_BASE_URL}")

        ollama_model = model_override or settings.OLLAMA_MODEL
        logger.info(
            f"Using Ollama with model: {ollama_model} at {settings.OLLAMA_BASE_URL}, "
            f"temp={settings.LLM_TEMPERATURE}, max_tokens={settings.LLM_MAX_TOKENS}"
        )

        try:
            llm = LLM(
                model=f"ollama/{ollama_model}",
                temperature=settings.LLM_TEMPERATURE,
                max_tokens=settings.LLM_MAX_TOKENS,
                api_base=settings.OLLAMA_BASE_URL,
            )
            logger.info("✓ LLM instance created successfully")
        except Exception as e:
            logger.error(f"✗ Failed to create LLM instance: {e}")
            raise

    else:
        # Use direct Anthropic API
        if settings.ANTHROPIC_API_KEY:
            os.environ["ANTHROPIC_API_KEY"] = settings.ANTHROPIC_API_KEY

        anthropic_model = model_override or settings.ANTHROPIC_MODEL
        logger.info(f"Using Anthropic API with model: {anthropic_model}, temp={settings.LLM_TEMPERATURE}")
        llm = LLM(
            model=f"anthropic/{anthropic_model}",
            temperature=settings.LLM_TEMPERATURE,
            max_tokens=settings.LLM_MAX_TOKENS,
        )

    return llm


def build_exploration_crew(
    asset_graph_json: str,
    threat_intel_context: str = "",
    security_findings_context: str = "",
    model_override: str = None,
    vuln_context = None,
) -> Crew:
    """
    Build a threat modeling exploration crew from enabled personas.

    The crew is dynamically constructed from all enabled personas in the
    PersonaRegistry. When users enable/disable personas, the next swarm
    run will reflect those changes.

    Args:
        asset_graph_json: JSON string representation of the infrastructure asset graph
        threat_intel_context: Optional threat intelligence context
        security_findings_context: Pre-identified security findings from LLM analysis
        model_override: Optional model name to use instead of default (e.g., "qwen3:14b")
        vuln_context: Optional VulnContext with vulnerability intelligence

    Returns:
        CrewAI Crew ready to execute threat modeling tasks
    """
    # Load enabled personas from registry
    registry = PersonaRegistry()
    enabled_personas = registry.get_enabled()

    if not enabled_personas:
        logger.warning("No enabled personas found. Using default set.")
        # Fallback: enable some default personas if none are enabled
        registry.toggle_persona("opportunistic_attacker", True)
        registry.toggle_persona("cloud_native_attacker", True)
        enabled_personas = registry.get_enabled()

    logger.info(f"Building crew with {len(enabled_personas)} enabled personas")

    # Get configured LLM instance with optional model override
    llm = get_llm(model_override=model_override)

    # Build agents and tasks from personas
    agents = []
    tasks = []

    for persona_name, persona_config in enabled_personas.items():
        # Build backstory with infrastructure context and dynamic security reasoning
        security_reasoning = persona_config.get('security_reasoning_approach', '')

        full_backstory = (
            f"{persona_config['backstory']}\n\n"
            f"=== YOUR SECURITY REASONING APPROACH ===\n"
            f"{security_reasoning}\n\n"
            f"=== INFRASTRUCTURE TO ANALYZE ===\n"
            f"Apply your security reasoning approach to the infrastructure below. Identify every misconfiguration, "
            f"vulnerability, and attack-enabling condition you can find—not just the well-known ones. For each finding, "
            f"explain what specific attribute or relationship makes it dangerous and how you would exploit it. "
            f"Do not limit yourself to conditions you have been pre-briefed on. Use your full security knowledge.\n\n"
            f"{asset_graph_json}\n\n"
        )

        # Add security findings if available
        if security_findings_context:
            full_backstory += f"\n{security_findings_context}\n\n"
            full_backstory += (
                "These findings were identified through LLM security analysis of the complete IaC. "
                "Use these as starting points for your attack path generation. You may also identify "
                "additional findings the initial analysis missed—your reasoning is not limited to this list.\n\n"
            )

        # Add vulnerability intelligence if available
        if vuln_context:
            full_backstory += f"\n{vuln_context.combined_prompt}\n\n"

        full_backstory += (
            f"Current threat intelligence context:\n"
            f"{threat_intel_context if threat_intel_context else 'No specific threat intelligence provided.'}"
        )

        # Create agent
        agent = Agent(
            role=persona_config["role"],
            goal=persona_config["goal"],
            backstory=full_backstory,
            verbose=True,
            allow_delegation=False,
            llm=llm,
        )
        agents.append(agent)
        logger.debug(f"Created agent: {persona_config['display_name']}")

        # Build TTP focus list for task description
        ttp_focus_list = ", ".join(persona_config.get("ttp_focus", []))

        # Create task for this agent with kill chain structure
        # Enhanced prompt with explicit field requirements and examples
        task_description = (
            f"Analyse the provided AWS cloud infrastructure asset graph through the lens of {persona_config['display_name']}.\n\n"
            f"Identify realistic, end-to-end attack paths from initial reconnaissance to achieving an objective "
            f"(data exfiltration, system disruption, or persistent access).\n\n"
            f"Each attack path MUST follow the cyber kill chain with up to 10 steps. "
            f"Each step must map to one of these kill chain phases in order:\n\n"
            f"Step 1 - Reconnaissance or Initial Access: How the attacker gains their first foothold. "
            f"Could be exploiting a public-facing service, using phished credentials, or abusing a supply chain dependency.\n\n"
            f"Step 2 - Execution & Persistence: What the attacker executes after gaining access and how they establish persistence. "
            f"Could be deploying a web shell, modifying IAM policies, or injecting code into a Lambda function.\n\n"
            f"Step 3 - Lateral Movement & Privilege Escalation: How the attacker moves from their initial position to reach higher-value targets. "
            f"Could be assuming IAM roles, pivoting through VPC peering, abusing metadata service, or exploiting trust relationships.\n\n"
            f"Step 4 - Objective (Exfiltration/Impact): The attacker achieves their goal. "
            f"Could be exfiltrating data from S3/RDS, deploying ransomware, or disrupting availability.\n\n"
            f"Step 5 (optional) - Covering Tracks / Maintaining Access: How the attacker hides their activity or ensures they can return. "
            f"Could be clearing CloudTrail logs, creating backdoor IAM users, or establishing reverse tunnels.\n\n"
            f"CRITICAL REQUIREMENTS - EVERY FIELD MUST BE FILLED:\n"
            f"1. technique_id: MUST be a valid MITRE ATT&CK T-number (e.g., T1190, T1078, T1098, T1566, T1072, T1021)\n"
            f"2. technique_name: MUST be the human-readable technique name (e.g., 'Exploit Public-Facing Application')\n"
            f"3. target_asset: MUST be an EXACT asset name from the infrastructure (e.g., 'aws_instance.web_server_1', 'aws_s3_bucket.customer_data')\n"
            f"4. action_description: MUST be 2-3 sentences describing the specific attack action\n"
            f"5. outcome: MUST describe what the attacker gains from this step\n"
            f"6. mitigation: MUST include mitigation_id, mitigation_name, description, aws_service_action\n"
            f"7. DO NOT leave fields empty, null, or use placeholder text\n"
            f"8. Focus on your group's known TTPs: {ttp_focus_list}.\n\n"
            f"EXAMPLE JSON FORMAT (YOU MUST FOLLOW THIS STRUCTURE):\n"
            f"[\n"
            f"  {{\n"
            f'    "name": "Web Server Compromise to Data Exfiltration",\n'
            f'    "objective": "Exfiltrate customer data from S3 bucket",\n'
            f'    "impact_type": "confidentiality",\n'
            f'    "difficulty": "medium",\n'
            f'    "threat_actor": "{persona_config["display_name"]}",\n'
            f'    "steps": [\n'
            f"      {{\n"
            f'        "step_number": 1,\n'
            f'        "kill_chain_phase": "Initial Access",\n'
            f'        "technique_id": "T1190",\n'
            f'        "technique_name": "Exploit Public-Facing Application",\n'
            f'        "target_asset": "aws_instance.web_server_1",\n'
            f'        "action_description": "Attacker scans and exploits a known vulnerability in the web server application to gain initial access. The vulnerability allows remote code execution.",\n'
            f'        "outcome": "Initial foothold on web server with shell access",\n'
            f'        "mitigation": {{\n'
            f'          "mitigation_id": "M1050",\n'
            f'          "mitigation_name": "Exploit Protection",\n'
            f'          "description": "Deploy web application firewall and implement regular patching",\n'
            f'          "aws_service_action": "Enable AWS WAF on ALB and configure AWS Systems Manager Patch Manager"\n'
            f"        }}\n"
            f"      }},\n"
            f"      {{\n"
            f'        "step_number": 2,\n'
            f'        "kill_chain_phase": "Lateral Movement",\n'
            f'        "technique_id": "T1078",\n'
            f'        "technique_name": "Valid Accounts",\n'
            f'        "target_asset": "aws_s3_bucket.customer_data",\n'
            f'        "action_description": "Using compromised IAM credentials from the web server, attacker accesses the S3 bucket containing customer data.",\n'
            f'        "outcome": "Access to customer data bucket established",\n'
            f'        "mitigation": {{\n'
            f'          "mitigation_id": "M1026",\n'
            f'          "mitigation_name": "Privileged Account Management",\n'
            f'          "description": "Implement least privilege IAM policies",\n'
            f'          "aws_service_action": "Use IAM Access Analyzer and implement least privilege policies"\n'
            f"        }}\n"
            f"      }}\n"
            f"    ]\n"
            f"  }}\n"
            f"]\n\n"
            f"Return a JSON array of EXACTLY 2 attack paths following this EXACT structure. "
            f"Ensure EVERY field in EVERY step is populated with valid, specific data from the asset graph. "
            f"Keep each attack path to 3-5 steps maximum to ensure complete JSON generation."
        )

        expected_output = (
            "A JSON array of attack path objects. CRITICAL: Each step object MUST include ALL these fields:\n"
            "- technique_id (string, MITRE ATT&CK T-number like 'T1190')\n"
            "- technique_name (string, human readable like 'Exploit Public-Facing Application')\n"
            "- target_asset (string, exact asset name from graph like 'aws_instance.web_server_1')\n"
            "- action_description (string, 2-3 sentences)\n"
            "- outcome (string)\n"
            "- mitigation (object with mitigation_id, mitigation_name, description, aws_service_action)\n"
            "DO NOT OMIT ANY FIELDS. Return ONLY valid JSON array, no markdown, no explanation, no placeholders."
        )

        task = Task(
            description=task_description,
            expected_output=expected_output,
            agent=agent,
        )
        tasks.append(task)

    # Build the crew
    crew = Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )

    logger.info(f"Crew built with {len(agents)} agents and {len(tasks)} tasks")
    return crew


def parse_exploration_results(crew_output) -> List[Dict]:
    """
    Parse exploration results from crew execution with robust normalization.

    Extracts JSON output from each task, handles markdown code blocks,
    normalizes field names, validates kill chain structure, and combines
    all attack paths into a single list.

    Args:
        crew_output: Output from crew.kickoff()

    Returns:
        List of normalized attack path dictionaries from all agents
    """
    all_attack_paths = []

    # Mapping of kill chain phases by step number (fallback)
    step_to_phase = {
        1: "Initial Access",
        2: "Execution & Persistence",
        3: "Lateral Movement & Privilege Escalation",
        4: "Objective (Exfiltration/Impact)",
        5: "Covering Tracks",
    }

    try:
        # CrewAI crew output can be a string or have task outputs
        if hasattr(crew_output, "tasks_output"):
            task_outputs = crew_output.tasks_output
        elif hasattr(crew_output, "task_outputs"):
            task_outputs = crew_output.task_outputs
        else:
            task_outputs = [crew_output]

        for idx, task_output in enumerate(task_outputs):
            try:
                # Extract the raw output text
                if hasattr(task_output, "raw"):
                    output_text = task_output.raw
                elif hasattr(task_output, "result"):
                    output_text = task_output.result
                else:
                    output_text = str(task_output)

                logger.debug(f"Processing task output {idx + 1}: {output_text[:200]}...")

                # Strip markdown code blocks if present
                output_text = output_text.strip()
                if output_text.startswith("```"):
                    output_text = re.sub(r"^```(?:json)?", "", output_text, flags=re.IGNORECASE)
                    output_text = re.sub(r"```$", "", output_text)
                    output_text = output_text.strip()

                # Log the cleaned output for debugging model responses
                logger.debug(f"Cleaned output from task {idx + 1} (first 1000 chars):\n{output_text[:1000]}")

                # Parse JSON
                try:
                    parsed_output = json.loads(output_text)
                    logger.info(f"✓ Successfully parsed JSON from task {idx + 1}")
                except json.JSONDecodeError as json_err:
                    logger.error(f"✗ JSON parse error in task {idx + 1}: {json_err}")
                    logger.debug(f"Failed JSON content: {output_text[:500]}")
                    continue

                # Handle both array and single object
                if isinstance(parsed_output, list):
                    attack_paths = parsed_output
                    logger.info(f"Task {idx + 1}: Parsed as list with {len(attack_paths)} items")
                elif isinstance(parsed_output, dict):
                    if "attack_paths" in parsed_output:
                        attack_paths = parsed_output["attack_paths"]
                        logger.info(f"Task {idx + 1}: Extracted {len(attack_paths)} paths from 'attack_paths' key")
                    else:
                        attack_paths = [parsed_output]
                        logger.info(f"Task {idx + 1}: Treating dict as single path")
                else:
                    logger.warning(f"Task {idx + 1} output is neither list nor dict, skipping")
                    continue

                # Normalize each attack path
                paths_before = len(all_attack_paths)
                for path in attack_paths:
                    try:
                        # Normalize top-level fields
                        if "name" not in path:
                            # Generate a default name instead of skipping
                            threat_actor = path.get("threat_actor", "Unknown")
                            objective = path.get("objective", "Attack")
                            default_name = f"{threat_actor} - {objective}"
                            if default_name == "Unknown - Attack":
                                default_name = f"Attack Path {len(all_attack_paths) + 1}"
                            logger.warning(f"Attack path missing 'name', using default: {default_name}")
                            path["name"] = default_name

                        # Ensure required fields exist
                        path.setdefault("objective", "")
                        path.setdefault("threat_actor", "Unknown")
                        path.setdefault("impact_type", "confidentiality")
                        path.setdefault("difficulty", "medium")

                        # Normalize steps
                        if "steps" in path and isinstance(path["steps"], list):
                            normalized_steps = []
                            for step_idx, step in enumerate(path["steps"][:10]):  # Limit to 10 steps
                                try:
                                    normalized_step = {}

                                    # Normalize step_number
                                    normalized_step["step_number"] = step.get("step_number", step.get("stepNumber", step_idx + 1))

                                    # Normalize kill_chain_phase
                                    phase = step.get("kill_chain_phase") or step.get("killChainPhase") or step.get("phase")
                                    if not phase:
                                        phase = step_to_phase.get(normalized_step["step_number"], "Objective (Exfiltration/Impact)")
                                    normalized_step["kill_chain_phase"] = phase

                                    # Normalize technique_id
                                    tech_id = step.get("technique_id") or step.get("techniqueId") or step.get("attack_technique") or ""
                                    # Validate technique ID format
                                    if tech_id and not re.match(r"T\d{4}(\.\d{3})?", tech_id):
                                        # Try to extract from technique_name
                                        tech_name = step.get("technique_name", "")
                                        match = re.search(r"T\d{4}(\.\d{3})?", tech_name)
                                        if match:
                                            tech_id = match.group(0)
                                        else:
                                            logger.warning(f"Invalid technique_id: {tech_id}, step: {step}")

                                    if not tech_id:
                                        logger.error(f"Missing technique_id in step {step_idx + 1}, raw step data: {step}")
                                        # Use a more descriptive fallback
                                        tech_id = "T1000"

                                    normalized_step["technique_id"] = tech_id

                                    # Normalize technique_name
                                    tech_name = step.get("technique_name") or step.get("techniqueName") or step.get("technique") or ""
                                    if not tech_name:
                                        logger.error(f"Missing technique_name in step {step_idx + 1}, raw step data: {step}")
                                        tech_name = "Unknown Technique"
                                    normalized_step["technique_name"] = tech_name

                                    # Normalize target_asset
                                    target = step.get("target_asset") or step.get("targetAsset") or step.get("target") or step.get("asset") or ""
                                    if not target:
                                        logger.error(f"Missing target_asset in step {step_idx + 1}, raw step data: {step}")
                                        target = "unknown_asset"
                                    normalized_step["target_asset"] = target

                                    # Normalize action_description
                                    action_desc = (
                                        step.get("action_description")
                                        or step.get("description")
                                        or step.get("attack_details")
                                        or step.get("action")
                                        or ""
                                    )
                                    normalized_step["action_description"] = action_desc

                                    # Normalize outcome
                                    normalized_step["outcome"] = step.get("outcome") or step.get("impact") or ""

                                    # Normalize mitigation (can be None)
                                    mitigation = step.get("mitigation")
                                    if mitigation and isinstance(mitigation, dict):
                                        normalized_step["mitigation"] = {
                                            "mitigation_id": mitigation.get("mitigation_id", ""),
                                            "mitigation_name": mitigation.get("mitigation_name", ""),
                                            "description": mitigation.get("description", ""),
                                            "aws_service_action": mitigation.get("aws_service_action", ""),
                                        }
                                    else:
                                        normalized_step["mitigation"] = None

                                    # Preserve legacy fields for backward compatibility
                                    normalized_step["prerequisites"] = step.get("prerequisites", "")

                                    normalized_steps.append(normalized_step)

                                except Exception as step_error:
                                    logger.error(f"Error normalizing step {step_idx}: {step_error}")
                                    continue

                            path["steps"] = normalized_steps

                            if len(normalized_steps) < 3:
                                logger.warning(f"Attack path '{path['name']}' has fewer than 3 steps, skipping")
                                continue

                            # Validate path quality - reject paths with too many fallback values
                            fallback_count = sum(
                                1 for step in normalized_steps
                                if step.get("technique_id") == "T1000"
                                or step.get("target_asset") == "unknown_asset"
                                or step.get("technique_name") == "Unknown Technique"
                            )
                            fallback_ratio = fallback_count / len(normalized_steps)

                            # TEMPORARILY DISABLED: Relaxed validation for debugging
                            # Only reject if ALL steps are fallback values
                            if fallback_ratio >= 1.0:  # 100% fallback values
                                logger.warning(
                                    f"Attack path '{path['name']}' has {fallback_count}/{len(normalized_steps)} "
                                    f"steps with fallback values ({fallback_ratio:.0%}), skipping low-quality path"
                                )
                                continue
                            elif fallback_count > 0:
                                logger.info(
                                    f"Attack path '{path['name']}' has {fallback_count}/{len(normalized_steps)} "
                                    f"steps with fallback values ({fallback_ratio:.0%}), but keeping path (below threshold)"
                                )

                        else:
                            logger.warning(f"Attack path '{path['name']}' has no valid steps, skipping")
                            continue

                        # Generate unique ID if missing (required for mitigation tracking)
                        if "id" not in path:
                            path["id"] = f"path_{uuid4().hex[:12]}"
                            logger.debug(f"Generated ID for path '{path['name']}': {path['id']}")

                        all_attack_paths.append(path)
                        logger.info(f"✓ Added attack path: {path['name']} with {len(normalized_steps)} steps")

                    except Exception as path_error:
                        logger.error(f"Error normalizing attack path: {path_error}")
                        continue

                paths_added = len(all_attack_paths) - paths_before
                logger.info(f"Task {idx + 1} complete: Processed {len(attack_paths)} raw paths, added {paths_added} valid paths to results")

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from task {idx + 1}: {e}")
                logger.debug(f"Raw output: {output_text[:500]}")
                continue
            except Exception as e:
                logger.error(f"Error processing task {idx + 1} output: {e}")
                continue

        logger.info(f"Total attack paths extracted and normalized: {len(all_attack_paths)}")

    except Exception as e:
        logger.error(f"Failed to parse exploration results: {e}")

    return all_attack_paths


def _summarize_asset_graph(asset_graph: Dict[str, Any]) -> str:
    """
    Create a text summary of the asset graph for agent consumption.

    Args:
        asset_graph: Parsed infrastructure asset graph

    Returns:
        Human-readable summary of the infrastructure
    """
    summary_lines = []

    # Assets summary
    assets = asset_graph.get("assets", [])
    summary_lines.append(f"Infrastructure Assets ({len(assets)} total):")

    # Group assets by type
    assets_by_type: Dict[str, List[Dict]] = {}
    for asset in assets:
        asset_type = asset.get("type", "unknown")
        if asset_type not in assets_by_type:
            assets_by_type[asset_type] = []
        assets_by_type[asset_type].append(asset)

    for asset_type, type_assets in sorted(assets_by_type.items()):
        summary_lines.append(f"  {asset_type}: {len(type_assets)} assets")
        for asset in type_assets[:3]:  # Show first 3 of each type
            props = asset.get("properties", {})
            sensitive = asset.get("data_sensitivity", "unknown")
            boundary = asset.get("trust_boundary", "unknown")

            prop_highlights = []
            if props.get("internet_facing"):
                prop_highlights.append("internet-facing")
            if props.get("public"):
                prop_highlights.append("public")
            if props.get("encryption_at_rest") is False:
                prop_highlights.append("unencrypted")
            if props.get("ports"):
                ports = props["ports"]
                prop_highlights.append(f"ports {ports}")

            highlights = f" ({', '.join(prop_highlights)})" if prop_highlights else ""
            summary_lines.append(
                f"    - {asset['name']} [{asset['service']}] "
                f"sensitivity={sensitive}, boundary={boundary}{highlights}"
            )

        if len(type_assets) > 3:
            summary_lines.append(f"    ... and {len(type_assets) - 3} more")

    # Relationships summary
    relationships = asset_graph.get("relationships", [])
    summary_lines.append(f"\nRelationships ({len(relationships)} total):")

    rel_by_type: Dict[str, int] = {}
    for rel in relationships:
        rel_type = rel.get("type", "unknown")
        rel_by_type[rel_type] = rel_by_type.get(rel_type, 0) + 1

    for rel_type, count in sorted(rel_by_type.items()):
        summary_lines.append(f"  {rel_type}: {count}")

    # Trust boundaries summary
    boundaries = asset_graph.get("trust_boundaries", [])
    summary_lines.append(f"\nTrust Boundaries ({len(boundaries)} total):")

    for boundary in boundaries:
        exposure = boundary.get("exposure", "unknown")
        asset_count = len(boundary.get("assets", []))
        summary_lines.append(
            f"  {boundary['name']}: {asset_count} assets (exposure={exposure})"
        )

    # Metadata
    metadata = asset_graph.get("metadata", {})
    format_type = metadata.get("format", "unknown")
    resource_count = metadata.get("resource_count", 0)

    summary_lines.append(f"\nMetadata:")
    summary_lines.append(f"  Format: {format_type}")
    summary_lines.append(f"  Resources: {resource_count}")

    return "\n".join(summary_lines)


def build_evaluation_crew(
    attack_paths_json: str,
    asset_graph_json: str,
    model_override: str = None,
) -> Crew:
    """
    Build an evaluation crew to score and rank attack paths.

    The crew consists of 5 evaluator agents that assess attack paths on
    different dimensions: feasibility, detection difficulty, impact,
    novelty, and logical coherence.

    Args:
        attack_paths_json: JSON string of attack paths to evaluate
        asset_graph_json: JSON string of the infrastructure asset graph
        model_override: Optional model name to use instead of default

    Returns:
        CrewAI Crew ready to evaluate attack paths
    """
    logger.info("Building evaluation crew")

    # Get configured LLM instance with optional model override
    llm = get_llm(model_override=model_override)

    # Build context for evaluators
    evaluation_context = (
        f"You are evaluating attack paths against the following infrastructure:\n"
        f"{asset_graph_json}\n\n"
        f"Attack paths to evaluate:\n"
        f"{attack_paths_json}\n\n"
    )

    # Feasibility Scorer Agent
    feasibility_agent = Agent(
        role="Attack Path Feasibility Analyst",
        goal="Evaluate whether each step in an attack path can realistically be executed given the specific architecture. Check if prerequisites are met, tools exist, privileges are obtainable, and network paths exist between the attacker's position and the target.",
        backstory=(
            f"{evaluation_context}"
            "You are an expert penetration tester with deep knowledge of AWS security, "
            "privilege escalation techniques, and lateral movement. You assess whether attack "
            "paths are practically executable in the real world."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    feasibility_task = Task(
        description=(
            "Evaluate the feasibility of each kill chain attack path. For each path, assess whether "
            "each kill chain step logically follows from the previous step. Does the attacker actually have "
            "the prerequisites from the previous step's outcome to execute this step? "
            "Are the required tools and techniques available? Can the attacker obtain necessary privileges? "
            "Do network paths exist between source and target? Does each step's outcome realistically enable the next step? "
            "Rate each path on a scale of 1-10 (1=impossible, 10=trivially easy)."
        ),
        expected_output=(
            "A JSON array of objects, each with: path_name (string), feasibility_score (number 1-10), "
            "justification (string explaining the score, referencing specific kill chain steps). Return ONLY valid JSON, no markdown."
        ),
        agent=feasibility_agent,
    )

    # Detection Scorer Agent
    detection_agent = Agent(
        role="Security Monitoring and Detection Analyst",
        goal="Evaluate how likely each attack path is to be detected by standard AWS monitoring. Consider CloudTrail logging, VPC Flow Logs, GuardDuty, and common SIEM rules. High score = hard to detect = more dangerous.",
        backstory=(
            f"{evaluation_context}"
            "You are a security operations analyst with expertise in AWS security monitoring, "
            "SIEM rules, CloudTrail analysis, and detection engineering. You understand what "
            "attackers do to evade detection and how effective different monitoring strategies are."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    detection_task = Task(
        description=(
            "Evaluate how difficult each kill chain attack path is to detect. For each kill chain step, "
            "assess the likelihood of detection. Which steps would trigger CloudTrail events, GuardDuty findings, "
            "or VPC Flow Log alerts? Consider: Are actions logged by CloudTrail? Would VPC Flow Logs capture the activity? "
            "Would GuardDuty flag it? Are there common SIEM rules that would alert? "
            "Would each step generate security events that defenders could correlate? "
            "Rate on 1-10 scale where 10 means very stealthy/hard to detect (more dangerous), and 1 means easily detected."
        ),
        expected_output=(
            "A JSON array of objects, each with: path_name (string), detection_score (number 1-10, "
            "where 10=very stealthy), justification (string referencing specific kill chain steps and detection mechanisms). "
            "Return ONLY valid JSON, no markdown."
        ),
        agent=detection_agent,
    )

    # Impact Scorer Agent
    impact_agent = Agent(
        role="Business Impact Assessment Analyst",
        goal="Evaluate the blast radius and business impact if each attack path succeeds. Consider data sensitivity, system criticality, blast radius to other systems, and whether the impact is to confidentiality, integrity, or availability.",
        backstory=(
            f"{evaluation_context}"
            "You are a risk analyst specializing in cyber security impact assessment. You understand "
            "business-critical systems, data classification, regulatory requirements, and how technical "
            "compromises translate to business harm."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    impact_task = Task(
        description=(
            "Evaluate the business impact if each kill chain attack path succeeds. Focus on evaluating the final objective step — "
            "what is the real business impact if the attacker reaches this goal? Consider: What data is exposed? "
            "How critical are the affected systems? Can the attack spread to other systems after achieving the objective? "
            "What is the impact type (confidentiality, integrity, availability)? What is the blast radius? "
            "Rate on 1-10 scale where 10 is catastrophic business impact."
        ),
        expected_output=(
            "A JSON array of objects, each with: path_name (string), impact_score (number 1-10), "
            "justification (string explaining the business impact of the final objective). Return ONLY valid JSON, no markdown."
        ),
        agent=impact_agent,
    )

    # Novelty Scorer Agent
    novelty_agent = Agent(
        role="Threat Research and Novelty Analyst",
        goal="Evaluate how novel or unexpected each attack path is. Penalise well-known generic attacks (e.g., 'S3 bucket is public'). Reward creative chains using uncommon technique sequences or cross-service pivots the client likely hasn't considered.",
        backstory=(
            f"{evaluation_context}"
            "You are a threat researcher who stays current with offensive security research, APT campaigns, "
            "and novel attack techniques. You can distinguish between generic vulnerability scanner findings "
            "and genuinely creative attack chains that demonstrate real adversary thinking."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    novelty_task = Task(
        description=(
            "Evaluate how novel and creative each kill chain attack path is. Does this kill chain represent a creative or unexpected path, "
            "or is it a well-known pattern? Penalise well-known, generic kill chains that any scanner would find. "
            "Reward unusual technique combinations, creative cross-service pivots, and attack chains that demonstrate sophisticated "
            "adversary thinking. Consider: Are the kill chain steps in an unexpected order? Does the path use uncommon lateral movement techniques? "
            "Are there creative uses of AWS services? Rate on 1-10 scale where 10 is highly novel and unexpected."
        ),
        expected_output=(
            "A JSON array of objects, each with: path_name (string), novelty_score (number 1-10), "
            "justification (string explaining what makes this kill chain novel or generic). Return ONLY valid JSON, no markdown."
        ),
        agent=novelty_agent,
    )

    # Chain Coherence Checker Agent
    coherence_agent = Agent(
        role="Attack Chain Logical Validator",
        goal="Verify each attack path makes logical sense end-to-end. Check: does each step's output enable the next step? Are there missing privilege escalation steps? Are there impossible transitions (e.g., jumping from one VPC to an isolated one without a pivot)?",
        backstory=(
            f"{evaluation_context}"
            "You are a senior penetration tester who specializes in attack path validation. You scrutinize "
            "attack chains for logical consistency, ensuring each step naturally flows from the previous one "
            "and that all necessary intermediate steps are present."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    coherence_task = Task(
        description=(
            "Validate the logical coherence of each kill chain attack path. Does the kill chain flow logically? "
            "Does each step's outcome provide the prerequisite for the next step? Are there missing intermediate steps? "
            "For each path, verify: Does each step's output actually enable the next step in the kill chain? "
            "Are there missing privilege escalation or lateral movement steps? Are there impossible transitions "
            "(e.g., network isolation violations)? Does the sequence of kill chain phases make sense? "
            "Identify any logical gaps or inconsistencies. Rate on 1-10 scale where 10 is perfectly coherent and 1 is logically broken."
        ),
        expected_output=(
            "A JSON array of objects, each with: path_name (string), coherence_score (number 1-10), "
            "justification (string explaining kill chain coherence), issues_found (array of strings describing logical problems in the kill chain, empty if none). "
            "Return ONLY valid JSON, no markdown."
        ),
        agent=coherence_agent,
    )

    # Build the crew
    crew = Crew(
        agents=[
            feasibility_agent,
            detection_agent,
            impact_agent,
            novelty_agent,
            coherence_agent,
        ],
        tasks=[
            feasibility_task,
            detection_task,
            impact_task,
            novelty_task,
            coherence_task,
        ],
        process=Process.sequential,
        verbose=True,
    )

    logger.info(f"Evaluation crew built with {len(crew.agents)} agents")
    return crew


def aggregate_scores(
    exploration_paths: List[Dict],
    evaluation_results,
) -> List[Dict]:
    """
    Aggregate evaluation scores with attack paths and calculate composite scores.

    Matches evaluation scores to attack paths by path name, calculates a weighted
    composite score, and sorts paths by score descending.

    Composite score formula:
    - Feasibility: 30%
    - Detection difficulty: 15%
    - Impact: 25%
    - Novelty: 15%
    - Coherence: 15%

    Args:
        exploration_paths: List of attack path dictionaries from exploration phase
        evaluation_results: Raw output from evaluation crew.kickoff()

    Returns:
        List of attack paths enriched with evaluation scores, sorted by composite_score descending
    """
    logger.info("Aggregating evaluation scores with attack paths")

    # Parse evaluation results to extract scores
    evaluation_scores = parse_exploration_results(evaluation_results)

    # Build lookup dictionaries by path_name for each score type
    feasibility_lookup = {}
    detection_lookup = {}
    impact_lookup = {}
    novelty_lookup = {}
    coherence_lookup = {}

    for score_obj in evaluation_scores:
        path_name = score_obj.get("path_name")
        if not path_name:
            continue

        if "feasibility_score" in score_obj:
            feasibility_lookup[path_name] = score_obj
        elif "detection_score" in score_obj:
            detection_lookup[path_name] = score_obj
        elif "impact_score" in score_obj:
            impact_lookup[path_name] = score_obj
        elif "novelty_score" in score_obj:
            novelty_lookup[path_name] = score_obj
        elif "coherence_score" in score_obj:
            coherence_lookup[path_name] = score_obj

    # Enrich each attack path with evaluation scores
    enriched_paths = []
    for path in exploration_paths:
        path_name = path.get("name", "")

        # Get individual scores (default to 5 if not found)
        feasibility_data = feasibility_lookup.get(path_name, {})
        detection_data = detection_lookup.get(path_name, {})
        impact_data = impact_lookup.get(path_name, {})
        novelty_data = novelty_lookup.get(path_name, {})
        coherence_data = coherence_lookup.get(path_name, {})

        feasibility_score = feasibility_data.get("feasibility_score", 5)
        detection_score = detection_data.get("detection_score", 5)
        impact_score = impact_data.get("impact_score", 5)
        novelty_score = novelty_data.get("novelty_score", 5)
        coherence_score = coherence_data.get("coherence_score", 5)

        # Calculate composite score (weighted average)
        composite_score = (
            feasibility_score * 0.30 +
            detection_score * 0.15 +
            impact_score * 0.25 +
            novelty_score * 0.15 +
            coherence_score * 0.15
        )

        # Create enriched path object
        enriched_path = {
            **path,  # Original path data
            "evaluation": {
                "feasibility_score": feasibility_score,
                "feasibility_justification": feasibility_data.get("justification", ""),
                "detection_score": detection_score,
                "detection_justification": detection_data.get("justification", ""),
                "impact_score": impact_score,
                "impact_justification": impact_data.get("justification", ""),
                "novelty_score": novelty_score,
                "novelty_justification": novelty_data.get("justification", ""),
                "coherence_score": coherence_score,
                "coherence_justification": coherence_data.get("justification", ""),
                "coherence_issues": coherence_data.get("issues_found", []),
                "composite_score": round(composite_score, 2),
            }
        }
        enriched_paths.append(enriched_path)

    # Sort by composite score descending (highest priority first)
    enriched_paths.sort(key=lambda p: p["evaluation"]["composite_score"], reverse=True)

    logger.info(f"Aggregated scores for {len(enriched_paths)} attack paths")
    return enriched_paths


def build_adversarial_crew(
    scored_paths_json: str,
    asset_graph_json: str,
    model_override: str = None,
) -> Crew:
    """
    Build an adversarial red/blue/arbitrator crew to validate and refine attack paths.

    The crew consists of 3 agents in sequential process:
    1. Red Agent - identifies gaps in attack surface coverage
    2. Blue Agent - challenges feasibility from defender's perspective
    3. Arbitrator - produces final validated threat model

    Args:
        scored_paths_json: JSON string of scored attack paths from evaluation
        asset_graph_json: JSON string of the infrastructure asset graph
        model_override: Optional model name to use instead of default

    Returns:
        CrewAI Crew ready to perform adversarial validation
    """
    logger.info("Building adversarial crew")

    # Get configured LLM instance with optional model override
    llm = get_llm(model_override=model_override)

    # Build context for adversarial agents
    adversarial_context = (
        f"You are reviewing a threat model based on the following infrastructure:\n"
        f"{asset_graph_json}\n\n"
        f"Attack paths that have been identified and scored:\n"
        f"{scored_paths_json}\n\n"
    )

    # Red Team Gap Analyst Agent
    red_agent = Agent(
        role="Red Team Gap Analyst",
        goal="Review the attack paths identified by other analysts and find what they MISSED. Look for: attack surfaces not covered by any path, technique chains that combine elements across multiple paths, entry points identified but not fully exploited to maximum impact, and any assets in the graph that no path targets. Propose 1-3 additional attack paths that fill the gaps.",
        backstory=(
            f"{adversarial_context}"
            "You are an expert red team operator who specializes in finding blind spots. "
            "You've seen countless threat models and know where analysts typically miss coverage. "
            "Your job is to identify what hasn't been explored yet and propose additional attack "
            "paths that fill those gaps."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    red_task = Task(
        description=(
            "Analyze the existing kill chain attack paths and infrastructure to identify gaps in coverage. "
            "Look for kill chain paths that no exploration agent covered. Are there assets in the graph that are never targeted "
            "at any step in any path? Look for: 1) Attack surfaces or assets not targeted by any kill chain step, "
            "2) Entry points that could be exploited more fully, "
            "3) Alternative kill chain sequences using different technique combinations, "
            "4) High-value targets missed by exploration. "
            "Propose 1-3 additional kill chain attack paths (up to 10 steps each) that fill significant gaps."
            "Assess what percentage of the attack surface has been covered by the existing kill chains."
        ),
        expected_output=(
            "A JSON object with: "
            "gap_analysis (string describing what was missed in the kill chains), "
            "additional_paths (array of attack path objects with: name, objective, threat_actor, impact_type, difficulty, "
            "steps array with step_number/kill_chain_phase/technique_id/technique_name/target_asset/action_description/outcome/mitigation), "
            "coverage_assessment (string with percentage estimate of attack surface covered, e.g., '65%'). "
            "Return ONLY valid JSON, no markdown."
        ),
        agent=red_agent,
    )

    # Blue Team Defensive Challenger Agent
    blue_agent = Agent(
        role="Blue Team Defensive Challenger",
        goal="Challenge the feasibility of each proposed attack path from a defender's perspective. For each path, identify which specific steps would be blocked by the architecture as described. For example: 'Step 3 assumes metadata service access, but the task uses awsvpc mode with a security group blocking 169.254.169.254' or 'Step 2 requires internet egress, but the Lambda is in a VPC with no NAT gateway'. Be specific and reference actual asset properties from the graph.",
        backstory=(
            f"{adversarial_context}"
            "You are a defensive security architect who deeply understands AWS security controls, "
            "network isolation, IAM boundaries, and detection capabilities. Your job is to challenge "
            "attack path assumptions by identifying architectural controls that would block specific steps. "
            "You reference concrete asset properties and security configurations."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    blue_task = Task(
        description=(
            "Challenge each kill chain attack path by identifying specific steps that would be blocked by the architecture. "
            "For each kill chain step, identify if the architecture would actually block that step. "
            "Be specific — reference security groups, IAM policies, encryption settings, and network topology from the asset graph. "
            "Reference actual asset properties from the infrastructure graph: network isolation, security groups, IAM policies, "
            "VPC configuration, encryption settings, etc. For each challenged step, explain why it would fail and propose a revised feasibility score. "
            "Categorize paths as fully valid (no blocking controls in any kill chain step), partially valid (some steps blocked), "
            "or invalid (critical kill chain steps impossible)."
        ),
        expected_output=(
            "A JSON object with: "
            "challenges (array of objects with: path_name, step_challenged (step number), kill_chain_phase (which phase), "
            "challenge_reason (string explaining the architectural control that blocks this step), revised_feasibility_score (number 1-10)), "
            "paths_fully_valid (array of path names), "
            "paths_partially_valid (array of path names), "
            "paths_invalid (array of path names). "
            "Return ONLY valid JSON, no markdown."
        ),
        agent=blue_agent,
    )

    # Arbitrator Agent
    arbitrator_agent = Agent(
        role="Threat Model Quality Arbitrator",
        goal="Review the red team's gap analysis and additional paths, the blue team's challenges, and the original scored paths. Produce the final validated set: confirm paths that survived blue team challenge, integrate red team additions with scores, demote or revise challenged paths, and produce a final confidence rating for each path.",
        backstory=(
            f"{adversarial_context}"
            "You are a senior security consultant who produces final threat models for clients. "
            "You've reviewed the exploration, evaluation, red team gaps, and blue team challenges. "
            "Your job is to synthesize all inputs into a final validated threat model with confidence "
            "ratings and clear justifications. You balance red and blue perspectives to deliver "
            "actionable findings."
        ),
        verbose=True,
        allow_delegation=False,
        llm=llm,
    )

    arbitrator_task = Task(
        description=(
            "Produce the final validated threat model by synthesizing all inputs. "
            "For each attack path (original scored paths + red team additions): "
            "1) Apply blue team challenges - if a path was challenged, decide if it's still valid or needs revision, "
            "2) Assign a confidence rating: high (validated, no significant challenges), "
            "medium (partially challenged but still viable), low (significant challenges or gaps), "
            "3) Add validation notes explaining the confidence rating and any challenge resolutions, "
            "4) Mark whether the path was challenged and how the challenge was resolved. "
            "Include an executive summary (2-3 sentences) of the overall threat model findings."
        ),
        expected_output=(
            "A JSON object with: "
            "final_paths (array of complete path objects with all original data plus: "
            "confidence ('high'|'medium'|'low'), validation_notes (string), "
            "challenged (boolean), challenge_resolution (string or null)), "
            "executive_summary (string: 2-3 sentence summary of threat model findings). "
            "Return ONLY valid JSON, no markdown."
        ),
        agent=arbitrator_agent,
    )

    # Build the crew with sequential process (red -> blue -> arbitrator)
    crew = Crew(
        agents=[red_agent, blue_agent, arbitrator_agent],
        tasks=[red_task, blue_task, arbitrator_task],
        process=Process.sequential,
        verbose=True,
    )

    logger.info("Adversarial crew built with 3 agents in sequential process")
    return crew


def parse_adversarial_results(
    crew_output,
    scored_paths: List[Dict],
) -> Dict[str, Any]:
    """
    Parse adversarial crew results and merge with scored paths.

    Extracts outputs from red, blue, and arbitrator agents, then combines
    the final validated paths with all original scoring data.

    Args:
        crew_output: Raw output from adversarial crew.kickoff()
        scored_paths: Original scored paths from evaluation phase

    Returns:
        Dictionary with:
        - final_paths: Complete validated paths with all scores and validation data
        - red_analysis: Gap analysis from red team
        - blue_challenges: Challenge summary from blue team
        - executive_summary: High-level findings from arbitrator
        - coverage_assessment: Attack surface coverage estimate
    """
    logger.info("Parsing adversarial crew results")

    result = {
        "final_paths": [],
        "red_analysis": {},
        "blue_challenges": {},
        "executive_summary": "",
        "coverage_assessment": "",
    }

    try:
        # Extract task outputs
        if hasattr(crew_output, "tasks_output"):
            task_outputs = crew_output.tasks_output
        elif hasattr(crew_output, "task_outputs"):
            task_outputs = crew_output.task_outputs
        else:
            task_outputs = [crew_output]

        # Parse each task output
        red_output = None
        blue_output = None
        arbitrator_output = None

        for idx, task_output in enumerate(task_outputs):
            try:
                # Extract raw text
                if hasattr(task_output, "raw"):
                    output_text = task_output.raw
                elif hasattr(task_output, "result"):
                    output_text = task_output.result
                else:
                    output_text = str(task_output)

                logger.debug(f"Processing adversarial task {idx + 1}: {output_text[:200]}...")

                # Strip markdown code blocks
                output_text = output_text.strip()
                if output_text.startswith("```"):
                    output_text = re.sub(r"^```(?:json)?", "", output_text, flags=re.IGNORECASE)
                    output_text = re.sub(r"```$", "", output_text)
                    output_text = output_text.strip()

                # Parse JSON
                parsed = json.loads(output_text)

                # Assign to correct output based on task index
                if idx == 0:
                    red_output = parsed
                elif idx == 1:
                    blue_output = parsed
                elif idx == 2:
                    arbitrator_output = parsed

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from adversarial task {idx + 1}: {e}")
                logger.debug(f"Raw output: {output_text[:500]}")
                continue
            except Exception as e:
                logger.error(f"Error processing adversarial task {idx + 1}: {e}")
                continue

        # Extract red team analysis
        if red_output:
            result["red_analysis"] = {
                "gap_analysis": red_output.get("gap_analysis", ""),
                "additional_paths": red_output.get("additional_paths", []),
            }
            result["coverage_assessment"] = red_output.get("coverage_assessment", "Unknown")
            logger.info(f"Red team identified {len(result['red_analysis']['additional_paths'])} additional paths")

        # Extract blue team challenges
        if blue_output:
            result["blue_challenges"] = {
                "challenges": blue_output.get("challenges", []),
                "paths_fully_valid": blue_output.get("paths_fully_valid", []),
                "paths_partially_valid": blue_output.get("paths_partially_valid", []),
                "paths_invalid": blue_output.get("paths_invalid", []),
            }
            logger.info(f"Blue team issued {len(result['blue_challenges']['challenges'])} challenges")

        # Extract arbitrator final paths and summary
        if arbitrator_output:
            final_paths = arbitrator_output.get("final_paths", [])
            result["executive_summary"] = arbitrator_output.get("executive_summary", "")

            # Merge final paths with original scored paths to preserve all data
            # Build lookup of scored paths by name
            scored_lookup = {path.get("name", ""): path for path in scored_paths}

            enriched_final_paths = []
            for final_path in final_paths:
                # Try both "path_name" (from arbitrator LLM) and "name" (standard key)
                path_name = final_path.get("path_name") or final_path.get("name", "")

                # Start with scored path data if it exists, otherwise use final path as base
                if path_name and path_name in scored_lookup:
                    enriched_path = {**scored_lookup[path_name]}
                    logger.info(f"Merged arbitrator validation with scored path: {path_name}")
                else:
                    # This is a new path from red team or lookup failed
                    enriched_path = {**final_path}
                    if path_name:
                        logger.warning(f"Could not find scored path for: {path_name}")
                    else:
                        logger.warning("Arbitrator path missing name/path_name key")

                # Overlay arbitrator's validation data
                enriched_path.update({
                    "confidence": final_path.get("confidence", "medium"),
                    "validation_notes": final_path.get("validation_notes", ""),
                    "challenged": final_path.get("challenged", False),
                    "challenge_resolution": final_path.get("challenge_resolution"),
                    "challenged_steps": final_path.get("challenged_steps", []),
                    "status": final_path.get("status", "valid"),
                })

                # Ensure "name" key exists for frontend compatibility
                if "name" not in enriched_path and path_name:
                    enriched_path["name"] = path_name

                enriched_final_paths.append(enriched_path)

            result["final_paths"] = enriched_final_paths
            logger.info(f"Arbitrator produced {len(enriched_final_paths)} final validated paths")

            # Fallback if arbitrator returned empty final_paths
            if len(enriched_final_paths) == 0:
                logger.warning(f"Arbitrator returned 0 paths despite {len(scored_paths)} scored paths available")
                logger.warning("Using scored paths as fallback for final_paths")
                # Add default validation metadata to scored paths
                for scored_path in scored_paths:
                    scored_path.setdefault("confidence", "medium")
                    scored_path.setdefault("validation_notes", "Arbitrator did not produce final_paths; using evaluation scores")
                    scored_path.setdefault("challenged", False)
                result["final_paths"] = scored_paths
                logger.info(f"Fallback: Using {len(scored_paths)} scored paths as final paths")

        else:
            # Fallback: if arbitrator didn't run, use scored paths as final paths
            logger.warning("Arbitrator output not available, using scored paths as final")
            result["final_paths"] = scored_paths

    except Exception as e:
        logger.error(f"Failed to parse adversarial results: {e}")
        # Return scored paths as fallback
        result["final_paths"] = scored_paths

    return result


def run_threat_modeling_swarm(
    asset_graph: Dict[str, Any],
    threat_intel_context: str = "",
) -> Dict[str, Any]:
    """
    Run the threat modeling swarm on an asset graph.

    Args:
        asset_graph: Parsed infrastructure asset graph (dict)
        threat_intel_context: Optional threat intelligence context

    Returns:
        Dictionary with swarm results and parsed attack paths
    """
    try:
        # Convert asset graph to JSON string
        asset_graph_json = json.dumps(asset_graph, indent=2)

        # Build the crew
        crew = build_exploration_crew(asset_graph_json, threat_intel_context)

        # Execute the crew
        logger.info("Starting threat modeling swarm execution")
        result = crew.kickoff()

        logger.info("Threat modeling swarm completed successfully")

        # Parse results to extract attack paths
        attack_paths = parse_exploration_results(result)

        return {
            "status": "success",
            "attack_paths": attack_paths,
            "agents_used": len(crew.agents),
            "tasks_completed": len(crew.tasks),
            "raw_result": str(result),
        }

    except Exception as e:
        logger.error(f"Threat modeling swarm failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "attack_paths": [],
            "agents_used": 0,
            "tasks_completed": 0,
        }
