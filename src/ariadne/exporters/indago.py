"""Indago target format exporter."""

from __future__ import annotations

import json
from pathlib import Path

from ariadne.graph.store import GraphStore
from ariadne.models.asset import Service


HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}


def export_indago_targets(store: GraphStore, output_path: Path) -> Path:
    """Export HTTP endpoints from the graph as Indago-compatible targets.

    Args:
        store: Populated GraphStore with parsed entities.
        output_path: Path to write the export file.

    Returns:
        Path to the written file.
    """
    endpoints = []
    seen: set[tuple[str, str, int]] = set()

    target_base_url = ""
    for entity in store.get_all_entities():
        if isinstance(entity, Service) and entity.port in HTTP_PORTS:
            if not target_base_url:
                protocol = "https" if entity.ssl or entity.port == 443 else "http"
                host_id = entity.host_id or ""
                host_part = host_id.replace("host:", "") if host_id else "unknown"
                target_base_url = f"{protocol}://{host_part}"

            path = "/"
            method = "GET"
            key = (method, path, entity.port)
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "path": path,
                    "method": method,
                    "params": [],
                    "port": entity.port,
                    "protocol": entity.protocol,
                    "service_name": entity.name,
                })

    export_data = {
        "format": "indago-targets",
        "export_source": "ariadne",
        "target_base_url": target_base_url,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
    }

    output_path = Path(str(output_path))
    if not output_path.suffix:
        output_path = output_path.with_suffix(".json")

    output_path.write_text(json.dumps(export_data, indent=2))
    return output_path
