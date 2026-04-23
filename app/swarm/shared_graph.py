"""Phase 10: Stigmergic Shared Attack Graph

This module implements a stigmergic coordination mechanism inspired by ant colony
optimization. Multiple threat actor personas deposit attack nodes and edges into
a shared graph, with pheromone-like reinforcement when different agents discover
the same techniques. This enables emergent pattern detection without direct
agent-to-agent communication.

Key concepts:
- Pheromone strength: Increases when multiple agents discover the same path
- Decay: Older deposits fade over time unless reinforced
- Frontier nodes: Nodes deposited by other agents (exploration guidance)
- Emergent insights: Patterns that emerge from collective agent behavior
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import RLock
from typing import List, Dict, Set, Optional, Tuple, Any
from uuid import uuid4


@dataclass
class AttackNode:
    """Represents a single attack technique applied to a specific asset.

    Pheromone strength increases when multiple agents independently discover
    the same technique on the same asset, indicating high-confidence paths.
    """
    node_id: str
    asset_id: str
    technique_id: str
    technique_name: str
    kill_chain_phase: str
    deposited_by: str  # Persona name that first deposited this node
    pheromone_strength: float = 1.0
    deposit_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    times_reinforced: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize node to dictionary."""
        return asdict(self)


@dataclass
class AttackEdge:
    """Represents a transition between two attack techniques.

    Edges capture the sequence of techniques in attack paths. Reinforcement
    indicates that multiple agents chose the same progression.
    """
    edge_id: str
    source_node_id: str
    target_node_id: str
    deposited_by: str  # Persona name that first deposited this edge
    pheromone_strength: float = 1.0
    deposit_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    times_reinforced: int = 0
    relationship: str = "leads_to"  # Type of relationship (leads_to, enables, requires)

    def to_dict(self) -> dict:
        """Serialize edge to dictionary."""
        return asdict(self)


class SharedAttackGraph:
    """Thread-safe stigmergic shared attack graph.

    This graph accumulates attack knowledge from multiple agent personas running
    in parallel. Thread safety is critical as multiple agents may deposit nodes
    simultaneously during the exploration phase.

    Stigmergic coordination properties:
    1. Indirect communication: Agents read what others have deposited
    2. Reinforcement: Convergent discoveries increase pheromone strength
    3. Decay: Unreinforced paths fade over time
    4. Emergence: High-level patterns emerge from individual deposits
    """

    def __init__(self):
        """Initialize empty shared attack graph with thread safety."""
        self._lock = RLock()
        self._nodes: Dict[str, AttackNode] = {}
        self._edges: Dict[str, AttackEdge] = {}
        self._asset_technique_index: Dict[Tuple[str, str], str] = {}  # (asset_id, technique_id) -> node_id
        self._edge_index: Dict[Tuple[str, str], str] = {}  # (source_id, target_id) -> edge_id
        self.agent_activity_log: List[Dict] = []

    def deposit_node(
        self,
        asset_id: str,
        technique_id: str,
        technique_name: str,
        kill_chain_phase: str,
        deposited_by: str,
        tags: Optional[List[str]] = None
    ) -> str:
        """Deposit an attack node into the shared graph.

        If a node with the same asset_id + technique_id already exists,
        reinforce it (stigmergic reinforcement). Otherwise, create a new node.

        Reinforcement logic:
        - Pheromone += 0.5 (capped at 3.0)
        - times_reinforced += 1

        Args:
            asset_id: Infrastructure asset identifier
            technique_id: MITRE ATT&CK technique ID (e.g., T1190)
            technique_name: Human-readable technique name
            kill_chain_phase: Kill chain phase (Initial Access, Execution, etc.)
            deposited_by: Persona name depositing this node
            tags: Optional list of tags for categorization

        Returns:
            node_id: ID of the deposited or reinforced node
        """
        with self._lock:
            index_key = (asset_id, technique_id)

            # Check if node already exists (stigmergic reinforcement)
            if index_key in self._asset_technique_index:
                existing_node_id = self._asset_technique_index[index_key]
                existing_node = self._nodes[existing_node_id]

                # Reinforce only if deposited by a different agent
                if existing_node.deposited_by != deposited_by:
                    # Apply reinforcement
                    old_strength = existing_node.pheromone_strength
                    existing_node.pheromone_strength = min(
                        existing_node.pheromone_strength + 0.5,
                        3.0  # Cap at 3.0
                    )
                    existing_node.times_reinforced += 1

                    # Log reinforcement activity
                    self.agent_activity_log.append({
                        "action": "reinforce_node",
                        "node_id": existing_node_id,
                        "asset_id": asset_id,
                        "technique_id": technique_id,
                        "deposited_by": deposited_by,
                        "original_depositor": existing_node.deposited_by,
                        "pheromone_before": old_strength,
                        "pheromone_after": existing_node.pheromone_strength,
                        "times_reinforced": existing_node.times_reinforced,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

                    return existing_node_id
                else:
                    # Same agent re-depositing - no reinforcement
                    self.agent_activity_log.append({
                        "action": "rediscover_own_node",
                        "node_id": existing_node_id,
                        "asset_id": asset_id,
                        "technique_id": technique_id,
                        "deposited_by": deposited_by,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    return existing_node_id

            # Create new node
            node_id = f"node_{uuid4().hex[:12]}"
            new_node = AttackNode(
                node_id=node_id,
                asset_id=asset_id,
                technique_id=technique_id,
                technique_name=technique_name,
                kill_chain_phase=kill_chain_phase,
                deposited_by=deposited_by,
                pheromone_strength=1.0,
                times_reinforced=0,
                tags=tags or []
            )

            self._nodes[node_id] = new_node
            self._asset_technique_index[index_key] = node_id

            # Log deposit activity
            self.agent_activity_log.append({
                "action": "deposit_node",
                "node_id": node_id,
                "asset_id": asset_id,
                "technique_id": technique_id,
                "deposited_by": deposited_by,
                "pheromone_strength": 1.0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            return node_id

    def deposit_edge(
        self,
        source_node_id: str,
        target_node_id: str,
        deposited_by: str,
        relationship: str = "leads_to"
    ) -> str:
        """Deposit an attack edge into the shared graph.

        If an edge with the same source + target already exists, reinforce it.
        Otherwise, create a new edge.

        Reinforcement logic:
        - Pheromone += 0.5 (capped at 3.0)
        - times_reinforced += 1

        Args:
            source_node_id: ID of source node
            target_node_id: ID of target node
            deposited_by: Persona name depositing this edge
            relationship: Type of relationship (leads_to, enables, requires)

        Returns:
            edge_id: ID of the deposited or reinforced edge
        """
        with self._lock:
            index_key = (source_node_id, target_node_id)

            # Check if edge already exists (stigmergic reinforcement)
            if index_key in self._edge_index:
                existing_edge_id = self._edge_index[index_key]
                existing_edge = self._edges[existing_edge_id]

                # Reinforce only if deposited by a different agent
                if existing_edge.deposited_by != deposited_by:
                    old_strength = existing_edge.pheromone_strength
                    existing_edge.pheromone_strength = min(
                        existing_edge.pheromone_strength + 0.5,
                        3.0  # Cap at 3.0
                    )
                    existing_edge.times_reinforced += 1

                    # Log reinforcement activity
                    self.agent_activity_log.append({
                        "action": "reinforce_edge",
                        "edge_id": existing_edge_id,
                        "source_node_id": source_node_id,
                        "target_node_id": target_node_id,
                        "deposited_by": deposited_by,
                        "original_depositor": existing_edge.deposited_by,
                        "pheromone_before": old_strength,
                        "pheromone_after": existing_edge.pheromone_strength,
                        "times_reinforced": existing_edge.times_reinforced,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

                    return existing_edge_id
                else:
                    # Same agent re-depositing - no reinforcement
                    self.agent_activity_log.append({
                        "action": "rediscover_own_edge",
                        "edge_id": existing_edge_id,
                        "source_node_id": source_node_id,
                        "target_node_id": target_node_id,
                        "deposited_by": deposited_by,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    return existing_edge_id

            # Create new edge
            edge_id = f"edge_{uuid4().hex[:12]}"
            new_edge = AttackEdge(
                edge_id=edge_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                deposited_by=deposited_by,
                pheromone_strength=1.0,
                times_reinforced=0,
                relationship=relationship
            )

            self._edges[edge_id] = new_edge
            self._edge_index[index_key] = edge_id

            # Log deposit activity
            self.agent_activity_log.append({
                "action": "deposit_edge",
                "edge_id": edge_id,
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "deposited_by": deposited_by,
                "relationship": relationship,
                "pheromone_strength": 1.0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            return edge_id

    def read_high_pheromone_nodes(self, threshold: float = 1.3) -> List[AttackNode]:
        """Read nodes with pheromone strength above threshold after applying decay.

        High-pheromone nodes indicate attack techniques that multiple agents
        have independently discovered, suggesting high-confidence paths.

        Args:
            threshold: Minimum pheromone strength to include (default 1.3)

        Returns:
            List of AttackNode objects above threshold, sorted by pheromone (desc)
        """
        with self._lock:
            # Apply decay to get current pheromone values
            self.apply_decay()

            high_pheromone = [
                node for node in self._nodes.values()
                if node.pheromone_strength >= threshold
            ]

            # Sort by pheromone strength descending
            high_pheromone.sort(key=lambda n: n.pheromone_strength, reverse=True)

            return high_pheromone

    def read_frontier_nodes(self, deposited_by: str) -> List[AttackNode]:
        """Read nodes NOT deposited by the specified persona.

        Frontier nodes represent attack paths discovered by other agents,
        guiding exploration toward unexplored areas or reinforcing known paths.

        This implements stigmergic exploration guidance: agents follow the
        "pheromone trails" left by other agents.

        Args:
            deposited_by: Persona name to exclude

        Returns:
            List of AttackNode objects deposited by other personas
        """
        with self._lock:
            frontier = [
                node for node in self._nodes.values()
                if node.deposited_by != deposited_by
            ]

            # Sort by pheromone strength descending (strongest trails first)
            frontier.sort(key=lambda n: n.pheromone_strength, reverse=True)

            return frontier

    def apply_decay(self, decay_rate: float = 0.02) -> None:
        """Apply pheromone decay to all nodes and edges.

        Decay formula: pheromone *= (1 - decay_rate * age_hours)
        Floor: pheromone cannot go below 0.1

        This ensures that unreinforced paths fade over time, while actively
        reinforced paths remain strong.

        Args:
            decay_rate: Decay rate per hour (default 0.02 = 2% per hour)
        """
        with self._lock:
            now = datetime.now(timezone.utc)

            # Decay nodes
            for node in self._nodes.values():
                deposit_time = datetime.fromisoformat(node.deposit_time)
                age_hours = (now - deposit_time).total_seconds() / 3600

                decay_factor = 1 - (decay_rate * age_hours)
                node.pheromone_strength = max(
                    node.pheromone_strength * decay_factor,
                    0.1  # Floor at 0.1
                )

            # Decay edges
            for edge in self._edges.values():
                deposit_time = datetime.fromisoformat(edge.deposit_time)
                age_hours = (now - deposit_time).total_seconds() / 3600

                decay_factor = 1 - (decay_rate * age_hours)
                edge.pheromone_strength = max(
                    edge.pheromone_strength * decay_factor,
                    0.1  # Floor at 0.1
                )

    def get_snapshot(self) -> Dict:
        """Get a serialized snapshot of the entire graph state.

        Returns a dictionary containing:
        - All nodes and edges
        - High-pheromone techniques (times_reinforced >= 1)
        - Statistics about the graph
        - Activity log

        Returns:
            Dictionary with complete graph state
        """
        with self._lock:
            # Apply decay before snapshot
            self.apply_decay()

            # Identify high-pheromone techniques
            high_pheromone_techniques = [
                {
                    "technique_id": node.technique_id,
                    "technique_name": node.technique_name,
                    "asset_id": node.asset_id,
                    "pheromone_strength": node.pheromone_strength,
                    "times_reinforced": node.times_reinforced,
                    "deposited_by": node.deposited_by
                }
                for node in self._nodes.values()
                if node.times_reinforced >= 1
            ]

            # Sort by times reinforced (desc) then pheromone strength (desc)
            high_pheromone_techniques.sort(
                key=lambda t: (t["times_reinforced"], t["pheromone_strength"]),
                reverse=True
            )

            return {
                "nodes": [node.to_dict() for node in self._nodes.values()],
                "edges": [edge.to_dict() for edge in self._edges.values()],
                "high_pheromone_techniques": high_pheromone_techniques,
                "statistics": {
                    "total_nodes": len(self._nodes),
                    "total_edges": len(self._edges),
                    "reinforced_nodes": sum(1 for n in self._nodes.values() if n.times_reinforced > 0),
                    "reinforced_edges": sum(1 for e in self._edges.values() if e.times_reinforced > 0),
                    "unique_assets": len(set(n.asset_id for n in self._nodes.values())),
                    "unique_techniques": len(set(n.technique_id for n in self._nodes.values())),
                    "avg_pheromone_strength": sum(n.pheromone_strength for n in self._nodes.values()) / len(self._nodes) if self._nodes else 0
                },
                "activity_log": self.agent_activity_log
            }

    def extract_emergent_insights(self, asset_graph_node_ids: List[str]) -> Dict:
        """Extract emergent patterns from the shared attack graph.

        This method identifies high-level patterns that emerge from collective
        agent behavior, including:

        1. High-confidence techniques: Techniques reinforced by multiple agents
        2. Convergent paths: Sequences where 2+ agents share 2+ consecutive techniques
        3. Coverage gaps: Assets in the infrastructure with no attack deposits
        4. Technique clusters: Groups of techniques that co-occur frequently

        Args:
            asset_graph_node_ids: List of all asset IDs in the infrastructure

        Returns:
            Dictionary with emergent insights
        """
        with self._lock:
            # Apply decay before analysis
            self.apply_decay()

            # 1. High-confidence techniques (reinforced at least once)
            high_confidence_techniques = [
                {
                    "technique_id": node.technique_id,
                    "technique_name": node.technique_name,
                    "times_reinforced": node.times_reinforced,
                    "pheromone_strength": node.pheromone_strength,
                    "asset_id": node.asset_id,
                    "kill_chain_phase": node.kill_chain_phase,
                    "depositors": [node.deposited_by]  # First depositor
                }
                for node in self._nodes.values()
                if node.times_reinforced >= 1
            ]

            # 2. Convergent paths: Find sequences where multiple agents deposited same progression
            convergent_paths = self._find_convergent_paths()

            # 3. Coverage gaps: Assets with no deposits
            covered_assets = set(node.asset_id for node in self._nodes.values())
            coverage_gaps = [
                asset_id for asset_id in asset_graph_node_ids
                if asset_id not in covered_assets
            ]

            # 4. Technique clusters: Group techniques by co-occurrence
            technique_clusters = self._find_technique_clusters()

            return {
                "high_confidence_techniques": sorted(
                    high_confidence_techniques,
                    key=lambda t: (t["times_reinforced"], t["pheromone_strength"]),
                    reverse=True
                ),
                "convergent_paths": convergent_paths,
                "coverage_gaps": coverage_gaps,
                "technique_clusters": technique_clusters,
                "summary": {
                    "total_high_confidence_techniques": len(high_confidence_techniques),
                    "total_convergent_paths": len(convergent_paths),
                    "total_coverage_gaps": len(coverage_gaps),
                    "total_technique_clusters": len(technique_clusters),
                    "coverage_percentage": (
                        (len(covered_assets) / len(asset_graph_node_ids) * 100)
                        if asset_graph_node_ids else 0
                    )
                }
            }

    def _find_convergent_paths(self) -> List[Dict]:
        """Find attack path sequences where 2+ agents share 2+ consecutive techniques.

        A convergent path indicates that multiple agents independently discovered
        the same multi-step attack progression, suggesting a high-confidence
        attack path.

        Returns:
            List of convergent path dictionaries
        """
        convergent_paths = []

        # Build adjacency list from edges
        adjacency: Dict[str, List[str]] = {}
        for edge in self._edges.values():
            if edge.source_node_id not in adjacency:
                adjacency[edge.source_node_id] = []
            adjacency[edge.source_node_id].append(edge.target_node_id)

        # Find reinforced edges (deposited by multiple agents)
        reinforced_edges = [
            edge for edge in self._edges.values()
            if edge.times_reinforced >= 1
        ]

        # For each reinforced edge, try to extend to a path
        for edge in reinforced_edges:
            source_node = self._nodes.get(edge.source_node_id)
            target_node = self._nodes.get(edge.target_node_id)

            if not source_node or not target_node:
                continue

            # Check if this edge extends another reinforced edge
            path_techniques = [source_node.technique_id, target_node.technique_id]
            path_nodes = [source_node.node_id, target_node.node_id]

            # Try to extend forward
            current_node_id = target_node.node_id
            while current_node_id in adjacency:
                next_candidates = adjacency[current_node_id]
                extended = False

                for next_node_id in next_candidates:
                    edge_key = (current_node_id, next_node_id)
                    if edge_key in self._edge_index:
                        next_edge_id = self._edge_index[edge_key]
                        next_edge = self._edges[next_edge_id]

                        if next_edge.times_reinforced >= 1:
                            next_node = self._nodes[next_node_id]
                            path_techniques.append(next_node.technique_id)
                            path_nodes.append(next_node.node_id)
                            current_node_id = next_node_id
                            extended = True
                            break

                if not extended:
                    break

            # Only include paths with 2+ consecutive reinforced steps
            if len(path_techniques) >= 2:
                convergent_paths.append({
                    "technique_sequence": path_techniques,
                    "node_sequence": path_nodes,
                    "path_length": len(path_techniques),
                    "avg_pheromone": sum(
                        self._nodes[nid].pheromone_strength for nid in path_nodes
                    ) / len(path_nodes)
                })

        # Deduplicate and sort by length and pheromone
        seen = set()
        unique_paths = []
        for path in convergent_paths:
            key = tuple(path["technique_sequence"])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)

        unique_paths.sort(
            key=lambda p: (p["path_length"], p["avg_pheromone"]),
            reverse=True
        )

        return unique_paths

    def _find_technique_clusters(self) -> List[Dict]:
        """Find groups of techniques that frequently co-occur.

        Technique clustering reveals attack patterns where certain techniques
        are commonly used together across different attack paths.

        Returns:
            List of technique cluster dictionaries
        """
        # Build co-occurrence matrix
        co_occurrence: Dict[Tuple[str, str], int] = {}

        # For each edge, record technique co-occurrence
        for edge in self._edges.values():
            source_node = self._nodes.get(edge.source_node_id)
            target_node = self._nodes.get(edge.target_node_id)

            if not source_node or not target_node:
                continue

            # Canonical ordering to avoid duplicates
            tech_pair = tuple(sorted([source_node.technique_id, target_node.technique_id]))
            co_occurrence[tech_pair] = co_occurrence.get(tech_pair, 0) + 1

        # Filter to pairs that occur multiple times
        clusters = []
        for (tech1, tech2), count in co_occurrence.items():
            if count >= 2:  # Co-occur at least twice
                # Get technique names
                tech1_name = next(
                    (n.technique_name for n in self._nodes.values() if n.technique_id == tech1),
                    tech1
                )
                tech2_name = next(
                    (n.technique_name for n in self._nodes.values() if n.technique_id == tech2),
                    tech2
                )

                clusters.append({
                    "techniques": [tech1, tech2],
                    "technique_names": [tech1_name, tech2_name],
                    "co_occurrence_count": count
                })

        # Sort by co-occurrence count
        clusters.sort(key=lambda c: c["co_occurrence_count"], reverse=True)

        return clusters

    def seed_from_findings(self, findings: List[Any], initial_pheromone: Optional[float] = None) -> int:
        """Seed the shared graph with nodes from security findings.

        Replaces hard-coded incident patterns with finding-based seeding.
        For each CRITICAL or HIGH severity finding, deposit a pheromone node
        with strength proportional to severity and confidence.

        This guides the swarm toward confirmed security issues rather than
        pre-seeding specific incident patterns.

        Args:
            findings: List of SecurityFinding objects from SecurityAnalyser
            initial_pheromone: Optional override for initial pheromone strength

        Returns:
            Number of nodes seeded
        """
        severity_strength = {
            'CRITICAL': 2.5,
            'HIGH': 2.0,
            'MEDIUM': 1.5,
            'LOW': 1.0,
        }

        seeded = 0
        for finding in findings:
            # Handle both SecurityFinding objects and dicts
            if hasattr(finding, 'severity'):
                severity = finding.severity
                confidence = finding.confidence
                resource_id = finding.resource_id
                technique_id = finding.technique_id
                technique_name = finding.technique_name
                kill_chain_phase = finding.kill_chain_phase
                category = finding.category
                finding_id = finding.finding_id
            else:
                severity = finding.get('severity', 'MEDIUM')
                confidence = finding.get('confidence', 'MEDIUM')
                resource_id = finding.get('resource_id', '')
                technique_id = finding.get('technique_id', '')
                technique_name = finding.get('technique_name', '')
                kill_chain_phase = finding.get('kill_chain_phase', '')
                category = finding.get('category', '')
                finding_id = finding.get('finding_id', '')

            # Only seed CRITICAL or HIGH severity findings
            if severity not in ('CRITICAL', 'HIGH'):
                continue

            # Calculate pheromone strength based on severity and confidence
            if initial_pheromone is not None:
                strength = initial_pheromone
            else:
                strength = severity_strength.get(severity, 1.5)
                if confidence == 'HIGH':
                    strength *= 1.2

            # Deposit node with higher initial pheromone
            try:
                self.deposit_node(
                    asset_id=resource_id,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    kill_chain_phase=kill_chain_phase,
                    deposited_by=f'security_analyser:{finding_id}',
                    tags=['analyser_seeded', severity, category]
                )

                # Override pheromone strength for seeded nodes
                index_key = (resource_id, technique_id)
                if index_key in self._asset_technique_index:
                    node_id = self._asset_technique_index[index_key]
                    self._nodes[node_id].pheromone_strength = strength

                seeded += 1

            except Exception as e:
                logger.warning(f"Failed to seed finding {finding_id}: {e}")
                continue

        logger.info(f"Seeded {seeded} nodes from security findings")
        return seeded
