"""Attack path analysis API routes."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ariadne.config import get_config
from ariadne.engine.synthesizer import Synthesizer
from ariadne.web.routes.ingest import get_session_path

router = APIRouter()

_analysis_results: dict[str, dict] = {}


class SynthesizeRequest(BaseModel):
    session_id: str
    targets: list[str] | None = None
    entry_points: list[str] | None = None
    max_paths: int = 20


class PathDetailRequest(BaseModel):
    session_id: str
    path_id: str


@router.post("/synthesize")
async def synthesize_attack_paths(request: SynthesizeRequest) -> dict:
    """Synthesize attack paths from session data."""
    session_path = get_session_path(request.session_id)
    if not session_path:
        raise HTTPException(status_code=404, detail="Session not found")

    config = get_config()
    config.output.max_paths = request.max_paths

    synthesizer = Synthesizer(config)

    try:
        paths = synthesizer.analyze(
            session_path,
            targets=request.targets,
            entry_points=request.entry_points,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    result = {
        "session_id": request.session_id,
        "paths": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "probability": p.probability,
                "impact": p.impact,
                "length": p.length,
                "entry_point": p.entry_point_id,
                "target": p.target_id,
                "tactics": p.tactics_used,
                "steps": [
                    {
                        "order": s.order,
                        "action": s.action,
                        "description": s.description,
                        "source": s.source_asset_id,
                        "target": s.target_asset_id,
                        "probability": s.probability,
                        "technique": {
                            "id": s.technique.technique_id,
                            "name": s.technique.name,
                            "tactic": s.technique.tactic,
                        }
                        if s.technique
                        else None,
                    }
                    for s in p.steps
                ],
                "llm_analysis": p.llm_analysis,
            }
            for p in paths
        ],
        "stats": synthesizer.store.stats(),
        "summary": {
            "total_paths": len(paths),
            "critical_paths": sum(1 for p in paths if p.probability >= 0.7),
            "high_risk_paths": sum(1 for p in paths if 0.5 <= p.probability < 0.7),
            "avg_probability": sum(p.probability for p in paths) / len(paths) if paths else 0,
        },
    }

    _analysis_results[request.session_id] = result

    return result


@router.get("/{session_id}/paths")
async def get_paths(session_id: str) -> dict:
    """Get previously synthesized attack paths."""
    if session_id not in _analysis_results:
        raise HTTPException(status_code=404, detail="No analysis results found. Call /synthesize first.")

    return _analysis_results[session_id]


@router.get("/{session_id}/paths/{path_id}")
async def get_path_detail(session_id: str, path_id: str) -> dict:
    """Get detailed information about a specific attack path."""
    if session_id not in _analysis_results:
        raise HTTPException(status_code=404, detail="No analysis results found")

    results = _analysis_results[session_id]
    for path in results.get("paths", []):
        if path["id"] == path_id:
            return {"path": path}

    raise HTTPException(status_code=404, detail="Path not found")


@router.post("/{session_id}/validate")
async def validate_session(session_id: str) -> dict:
    """Validate session data before analysis."""
    session_path = get_session_path(session_id)
    if not session_path:
        raise HTTPException(status_code=404, detail="Session not found")

    config = get_config()
    synthesizer = Synthesizer(config)
    result = synthesizer.validate(session_path)

    return {
        "valid": result.valid,
        "file_count": result.file_count,
        "parsers": result.parsers,
        "errors": result.errors,
        "warnings": result.warnings,
    }


@router.get("/{session_id}/export")
async def export_results(session_id: str, format: str = "json") -> dict:
    """Export analysis results."""
    if session_id not in _analysis_results:
        raise HTTPException(status_code=404, detail="No analysis results found")

    results = _analysis_results[session_id]

    if format == "json":
        return results

    raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
