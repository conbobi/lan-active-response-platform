import heapq
from typing import Dict, List, Tuple, Optional, Callable, Any, Set


def dijkstra_shortest_path(
    graph: Dict[str, List[Dict[str, Any]]],
    start_node: str,
    target_node: str,
    weight_key: str = "cost",
    exclude_links: Optional[Set[str]] = None
) -> Tuple[List[str], List[str], float]:
    """
    Find shortest path using Dijkstra algorithm.
    
    Args:
        graph: Dict mapping node_id -> list of neighbor dicts containing target node, link_id, cost, etc.
               e.g., {'agent_1': [{'node': 'agent_2', 'link_id': 'link_1_2', 'cost': 1.5, 'capacity': 100}]}
        start_node: Starting node ID
        target_node: Target node ID
        weight_key: Key in edge payload representing cost
        exclude_links: Set of link IDs to ignore during path search
        
    Returns:
        Tuple of (path_nodes, path_link_ids, total_cost)
    """
    if exclude_links is None:
        exclude_links = set()

    if start_node not in graph or target_node not in graph:
        return [], [], float("inf")

    if start_node == target_node:
        return [start_node], [], 0.0

    # Min-heap queue: (cumulative_cost, current_node, node_path, link_path)
    distances: Dict[str, float] = {node: float("inf") for node in graph}
    distances[start_node] = 0.0

    pq = [(0.0, start_node, [start_node], [])]

    while pq:
        curr_cost, curr_node, node_path, link_path = heapq.heappop(pq)

        if curr_cost > distances[curr_node]:
            continue

        if curr_node == target_node:
            return node_path, link_path, curr_cost

        for edge in graph.get(curr_node, []):
            neighbor = edge["node"]
            link_id = edge.get("link_id")
            cost = edge.get(weight_key, 1.0)

            if link_id in exclude_links or cost == float("inf"):
                continue

            new_cost = curr_cost + cost
            if new_cost < distances.get(neighbor, float("inf")):
                distances[neighbor] = new_cost
                heapq.heappush(
                    pq,
                    (new_cost, neighbor, node_path + [neighbor], link_path + ([link_id] if link_id else []))
                )

    return [], [], float("inf")
