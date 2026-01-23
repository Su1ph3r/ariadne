"""Data ingestion API routes."""

import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from ariadne.parsers.registry import ParserRegistry

router = APIRouter()

_sessions: dict[str, Path] = {}


@router.post("/upload")
async def upload_files(files: list[UploadFile] = File(...)) -> dict:
    """Upload scan files for analysis.

    Returns a session ID that can be used to reference the uploaded files.
    """
    session_id = str(uuid4())
    session_dir = Path(tempfile.mkdtemp(prefix=f"ariadne_{session_id}_"))

    _sessions[session_id] = session_dir

    uploaded = []
    registry = ParserRegistry()

    for file in files:
        if not file.filename:
            continue

        file_path = session_dir / file.filename
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        parser = registry.find_parser(file_path)
        uploaded.append({
            "filename": file.filename,
            "size": len(content),
            "parser": parser.name if parser else None,
            "supported": parser is not None,
        })

    return {
        "session_id": session_id,
        "files": uploaded,
        "supported_count": sum(1 for f in uploaded if f["supported"]),
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str) -> dict:
    """Get information about an upload session."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session_dir = _sessions[session_id]
    files = list(session_dir.glob("*"))

    return {
        "session_id": session_id,
        "file_count": len(files),
        "files": [f.name for f in files],
    }


@router.delete("/session/{session_id}")
async def delete_session(session_id: str) -> dict:
    """Delete an upload session and its files."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session_dir = _sessions.pop(session_id)
    shutil.rmtree(session_dir, ignore_errors=True)

    return {"deleted": True}


@router.get("/parsers")
async def list_parsers() -> dict:
    """List available parsers."""
    registry = ParserRegistry()
    parsers = registry.list_parsers()

    return {
        "parsers": [
            {
                "name": p.name,
                "description": p.description,
                "file_patterns": p.file_patterns,
            }
            for p in parsers
        ]
    }


def get_session_path(session_id: str) -> Path | None:
    """Get the path for a session (used by other routes)."""
    return _sessions.get(session_id)
