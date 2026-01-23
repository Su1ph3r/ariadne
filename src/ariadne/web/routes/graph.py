"""Graph API routes."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ariadne.config import get_config
from ariadne.graph.store import GraphStore
from ariadne.graph.queries import GraphQueries
from ariadne.parsers.registry import ParserRegistry
from ariadne.web.routes.ingest import get_session_path

router = APIRouter()

_graph_stores: dict[str, GraphStore] = {}


class BuildGraphRequest(BaseModel):
    session_id: str


@router.post("/build")
async def build_graph(request: BuildGraphRequest) -> dict:
    """Build a knowledge graph from uploaded session data."""
    session_path = get_session_path(request.session_id)
    if not session_path:
        raise HTTPException(status_code=404, detail="Session not found")

    registry = ParserRegistry()
    store = GraphStore()

    entities = registry.parse_path(session_path)
    store.build_from_entities(entities)

    _graph_stores[request.session_id] = store

    return {
        "session_id": request.session_id,
        "stats": store.stats(),
    }


@router.get("/{session_id}/stats")
async def get_graph_stats(session_id: str) -> dict:
    """Get statistics about a built graph."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found. Call /build first.")

    return store.stats()


@router.get("/{session_id}/nodes")
async def get_nodes(session_id: str, type: str | None = None, limit: int = 100) -> dict:
    """Get nodes from the graph."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found")

    nodes = []
    for node_id, data in store.graph.nodes(data=True):
        if type and data.get("type") != type:
            continue

        nodes.append({
            "id": node_id,
            "type": data.get("type"),
            "label": data.get("label"),
            **{k: v for k, v in data.items() if k not in ["data", "type", "label"]},
        })

        if len(nodes) >= limit:
            break

    return {"nodes": nodes, "total": store.graph.number_of_nodes()}


@router.get("/{session_id}/edges")
async def get_edges(session_id: str, type: str | None = None, limit: int = 100) -> dict:
    """Get edges from the graph."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found")

    edges = []
    for source, target, data in store.graph.edges(data=True):
        if type and data.get("type") != type:
            continue

        edges.append({
            "source": source,
            "target": target,
            "type": data.get("type"),
            "weight": data.get("weight", 1.0),
        })

        if len(edges) >= limit:
            break

    return {"edges": edges, "total": store.graph.number_of_edges()}


@router.get("/{session_id}/visualization")
async def get_visualization_data(session_id: str) -> dict:
    """Get graph data formatted for visualization (Cytoscape.js format)."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found")

    nodes = []
    for node_id, data in store.graph.nodes(data=True):
        nodes.append({
            "data": {
                "id": node_id,
                "label": data.get("label", node_id)[:30],
                "type": data.get("type", "unknown"),
            }
        })

    edges = []
    for source, target, data in store.graph.edges(data=True):
        edges.append({
            "data": {
                "source": source,
                "target": target,
                "type": data.get("type", "related"),
            }
        })

    return {
        "elements": {
            "nodes": nodes,
            "edges": edges,
        }
    }


@router.get("/{session_id}/entry-points")
async def get_entry_points(session_id: str) -> dict:
    """Get potential entry points in the graph."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found")

    queries = GraphQueries(store.graph)
    entry_points = queries.find_entry_points()

    return {
        "entry_points": [
            {
                "id": ep,
                "label": store.graph.nodes[ep].get("label", ep),
                "type": store.graph.nodes[ep].get("type"),
            }
            for ep in entry_points
            if ep in store.graph.nodes
        ]
    }


@router.get("/{session_id}/targets")
async def get_targets(session_id: str) -> dict:
    """Get potential high-value targets in the graph."""
    store = _graph_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Graph not found")

    queries = GraphQueries(store.graph)
    targets = queries.find_crown_jewels()

    return {
        "targets": [
            {
                "id": t,
                "label": store.graph.nodes[t].get("label", t),
                "type": store.graph.nodes[t].get("type"),
            }
            for t in targets
            if t in store.graph.nodes
        ]
    }


def get_graph_store(session_id: str) -> GraphStore | None:
    """Get the graph store for a session (used by other routes)."""
    return _graph_stores.get(session_id)
