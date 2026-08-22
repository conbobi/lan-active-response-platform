from typing import Dict, List, Tuple, Set, Any, Optional
from app.utils.dijkstra import dijkstra_shortest_path
from app.core.exceptions import PathNotFoundError


class PathFinder:
    """
    PathFinder service wrapper for graph pathfinding operations.
    """
    def __init__(self, graph: Dict[str, List[Dict[str, Any]]]):
        self.graph = graph

    def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        required_bandwidth: float = 0.0,
        exclude_links: Optional[Set[str]] = None
    ) -> Tuple[List[str], List[str], float]:
        """
        Find shortest path from source_id to target_id considering bandwidth constraint.
        
        Returns:
            Tuple of (node_path, link_ids, total_cost)
        """
        if exclude_links is None:
            exclude_links = set()

        # Build filtered graph excluding links that don't satisfy required bandwidth
        filtered_graph: Dict[str, List[Dict[str, Any]]] = {}
        for node, edges in self.graph.items():
            filtered_edges = []
            for edge in edges:
                available_cap = edge.get("available_capacity", edge.get("capacity", 1000.0))
                if available_cap >= required_bandwidth and edge.get("is_active", True):
                    filtered_edges.append(edge)
            filtered_graph[node] = filtered_edges

        nodes, links, cost = dijkstra_shortest_path(
            graph=filtered_graph,
            start_node=source_id,
            target_node=target_id,
            weight_key="cost",
            exclude_links=exclude_links
        )

        if not nodes or cost == float("inf"):
            raise PathNotFoundError(source_id, target_id)

        return nodes, links, cost
