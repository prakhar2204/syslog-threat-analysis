"""
SysLog Threat Analysis - Evidence Graph

Backend-only graph representation of relationships between
security entities. No visualization — only data structure.

Node types: Event, Alert, Incident, IP, User, Service, Host
Edge types: Generated, Triggered, Related, Originated, Targeted, Succeeded, Failed
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    EVENT = "event"
    ALERT = "alert"
    INCIDENT = "incident"
    IP = "ip"
    USER = "user"
    SERVICE = "service"
    HOST = "host"


class EdgeType(str, Enum):
    GENERATED = "generated"
    TRIGGERED = "triggered"
    RELATED = "related"
    ORIGINATED = "originated"
    TARGETED = "targeted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class GraphNode:
    """A node in the evidence graph."""
    node_id: str
    node_type: NodeType
    label: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge connecting two nodes."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: dict = field(default_factory=dict)


class EvidenceGraph:
    """
    In-memory graph for evidence relationships.

    Uses adjacency lists for efficient traversal.
    No rendering — only relationship storage and query.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[GraphEdge]] = defaultdict(list)

    # -- Mutation --

    def add_node(self, node_id: str, node_type: NodeType, label: str = "", **metadata: object) -> GraphNode:
        """Add a node. Idempotent — returns existing node if present."""
        if node_id in self._nodes:
            return self._nodes[node_id]
        node = GraphNode(node_id=node_id, node_type=node_type, label=label, metadata=dict(metadata))
        self._nodes[node_id] = node
        return node

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, **metadata: object) -> GraphEdge:
        """Add a directed edge between two nodes."""
        edge = GraphEdge(source_id=source_id, target_id=target_id, edge_type=edge_type, metadata=dict(metadata))
        self._edges.append(edge)
        self._adjacency[source_id].append(edge)
        return edge

    # -- High-level helpers --

    def add_event(self, event_id: str, hostname: str = "", source_ip: Optional[str] = None,
                  username: Optional[str] = None, service: str = "") -> None:
        """Register an event and its relationships to IPs, users, hosts, services."""
        self.add_node(event_id, NodeType.EVENT, label=event_id)

        if hostname:
            host_id = f"host:{hostname}"
            self.add_node(host_id, NodeType.HOST, label=hostname)
            self.add_edge(event_id, host_id, EdgeType.ORIGINATED)

        if source_ip:
            ip_id = f"ip:{source_ip}"
            self.add_node(ip_id, NodeType.IP, label=source_ip)
            self.add_edge(event_id, ip_id, EdgeType.ORIGINATED)

        if username:
            user_id = f"user:{username}"
            self.add_node(user_id, NodeType.USER, label=username)
            self.add_edge(event_id, user_id, EdgeType.TARGETED)

        if service:
            svc_id = f"svc:{service}"
            self.add_node(svc_id, NodeType.SERVICE, label=service)
            self.add_edge(event_id, svc_id, EdgeType.RELATED)

    def add_alert(self, alert_id: str, event_id: str, rule_id: str) -> None:
        """Register an alert and its relationship to the triggering event."""
        self.add_node(alert_id, NodeType.ALERT, label=alert_id, rule_id=rule_id)
        self.add_edge(event_id, alert_id, EdgeType.GENERATED)

    def add_incident(self, incident_id: str, alert_ids: list[str], event_ids: list[str]) -> None:
        """Register an incident and its relationships to alerts and events."""
        self.add_node(incident_id, NodeType.INCIDENT, label=incident_id)
        for aid in alert_ids:
            self.add_edge(aid, incident_id, EdgeType.TRIGGERED)
        for eid in event_ids:
            self.add_edge(eid, incident_id, EdgeType.RELATED)

    # -- Query --

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> list[GraphEdge]:
        """Get all edges from a node, optionally filtered by type."""
        edges = self._adjacency.get(node_id, [])
        if edge_type:
            return [e for e in edges if e.edge_type == edge_type]
        return list(edges)

    def get_subgraph(self, node_id: str, depth: int = 2) -> dict:
        """Get a subgraph centered on a node up to given depth."""
        visited: set[str] = set()
        nodes: list[dict] = []
        edges: list[dict] = []

        def _traverse(nid: str, d: int) -> None:
            if d < 0 or nid in visited:
                return
            visited.add(nid)
            node = self._nodes.get(nid)
            if node:
                nodes.append({"id": node.node_id, "type": node.node_type.value, "label": node.label})
            for edge in self._adjacency.get(nid, []):
                edges.append({
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.edge_type.value,
                })
                _traverse(edge.target_id, d - 1)

        _traverse(node_id, depth)
        return {"nodes": nodes, "edges": edges}

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def clear(self) -> None:
        """Reset graph state."""
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()


# Global instance
evidence_graph = EvidenceGraph()
