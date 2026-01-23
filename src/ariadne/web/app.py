"""FastAPI application for the Ariadne web dashboard."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ariadne import __version__
from ariadne.config import get_config
from ariadne.web.routes import ingest, graph, analysis
from ariadne.web.exceptions import register_exception_handlers

app = FastAPI(
    title="Ariadne",
    description="AI-powered attack path synthesizer",
    version=__version__,
)

register_exception_handlers(app)

static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=templates_dir) if templates_dir.exists() else None

app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Render the main dashboard."""
    if templates:
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "version": __version__},
        )

    return HTMLResponse(content=_get_dashboard_html(), status_code=200)


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "healthy", "version": __version__}


@app.get("/api/config")
async def get_app_config() -> dict:
    """Get current configuration (non-sensitive)."""
    config = get_config()
    return {
        "llm_provider": config.llm.provider,
        "llm_model": config.llm.model,
        "parsers_enabled": config.parsers.enabled,
        "output_format": config.output.default_format,
    }


def _get_dashboard_html() -> str:
    """Get dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ariadne - Attack Path Synthesizer</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --accent-hover: #79b8ff;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
            --border-color: #30363d;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 2rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
        }
        .logo { font-size: 1.5rem; font-weight: bold; color: var(--accent); }
        .logo span { color: var(--text-secondary); font-weight: normal; font-size: 0.875rem; margin-left: 0.5rem; }
        nav { display: flex; gap: 1rem; }
        nav a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            transition: all 0.2s;
        }
        nav a:hover, nav a.active { color: var(--text-primary); background: var(--bg-tertiary); }
        main { padding: 2rem; }
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .card h2 { margin-bottom: 1rem; font-size: 1.25rem; }
        .upload-zone {
            border: 2px dashed var(--border-color);
            border-radius: 8px;
            padding: 3rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        .upload-zone:hover { border-color: var(--accent); background: var(--bg-tertiary); }
        .upload-zone.dragover { border-color: var(--success); background: rgba(63, 185, 80, 0.1); }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: var(--accent-hover); }
        .graph-container {
            width: 100%;
            height: 500px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }
        .stat {
            text-align: center;
            padding: 1rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
        }
        .stat .value { font-size: 2rem; font-weight: bold; color: var(--accent); }
        .stat .label { color: var(--text-secondary); font-size: 0.875rem; }
        #results { display: none; }
        #results.active { display: block; }
        .path-list { list-style: none; }
        .path-item {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: background 0.2s;
        }
        .path-item:hover { background: var(--bg-tertiary); }
        .path-item:last-child { border-bottom: none; }
        .path-name { font-weight: 600; }
        .path-prob { color: var(--warning); font-weight: bold; }
        .path-desc { color: var(--text-secondary); font-size: 0.875rem; margin-top: 0.25rem; }
    </style>
</head>
<body>
    <header>
        <div class="logo">Ariadne <span id="version"></span></div>
        <nav>
            <a href="#" class="active">Dashboard</a>
            <a href="#graph">Graph</a>
            <a href="#paths">Paths</a>
            <a href="/docs">API Docs</a>
        </nav>
    </header>
    <main class="container">
        <div class="card">
            <h2>Upload Recon Data</h2>
            <div class="upload-zone" id="dropzone">
                <p id="dropzoneText">Drag and drop scan files here or click to browse</p>
                <p style="color: var(--text-secondary); margin-top: 0.5rem; font-size: 0.875rem;">
                    Supports: Nmap XML, Nuclei JSON, BloodHound JSON
                </p>
                <input type="file" id="fileInput" multiple hidden accept=".xml,.json,.jsonl">
            </div>
            <div style="margin-top: 1rem; text-align: center;">
                <button class="btn btn-primary" id="analyzeBtn" disabled>Analyze Attack Paths</button>
            </div>
        </div>
        <div id="results">
            <div class="card">
                <h2>Summary</h2>
                <div class="stats" id="stats"></div>
            </div>
            <div class="card">
                <h2>Knowledge Graph</h2>
                <div class="graph-container" id="graphContainer">Graph visualization will appear here</div>
            </div>
            <div class="card">
                <h2>Attack Paths</h2>
                <ul class="path-list" id="pathList"></ul>
            </div>
        </div>
    </main>
    <script>
        document.getElementById('version').textContent = 'v0.1.0';

        const dropzone = document.getElementById('dropzone');
        const dropzoneText = document.getElementById('dropzoneText');
        const fileInput = document.getElementById('fileInput');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const results = document.getElementById('results');
        let uploadedFiles = [];

        dropzone.addEventListener('click', function() { fileInput.click(); });
        dropzone.addEventListener('dragover', function(e) {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });
        dropzone.addEventListener('dragleave', function() { dropzone.classList.remove('dragover'); });
        dropzone.addEventListener('drop', function(e) {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });
        fileInput.addEventListener('change', function(e) { handleFiles(e.target.files); });

        function handleFiles(files) {
            uploadedFiles = Array.from(files);
            dropzoneText.textContent = uploadedFiles.length + ' file(s) selected';
            analyzeBtn.disabled = uploadedFiles.length === 0;
        }

        analyzeBtn.addEventListener('click', async function() {
            analyzeBtn.disabled = true;
            analyzeBtn.textContent = 'Analyzing...';

            const formData = new FormData();
            uploadedFiles.forEach(function(f) { formData.append('files', f); });

            try {
                const uploadRes = await fetch('/api/ingest/upload', { method: 'POST', body: formData });
                const uploadData = await uploadRes.json();

                const analysisRes = await fetch('/api/analysis/synthesize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: uploadData.session_id })
                });
                const analysisData = await analysisRes.json();

                displayResults(analysisData);
            } catch (err) {
                alert('Analysis failed: ' + err.message);
            } finally {
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = 'Analyze Attack Paths';
            }
        });

        function displayResults(data) {
            results.classList.add('active');

            const statsEl = document.getElementById('stats');
            statsEl.replaceChildren();

            const statItems = [
                { value: data.stats?.total_nodes || 0, label: 'Nodes' },
                { value: data.stats?.total_edges || 0, label: 'Edges' },
                { value: data.paths?.length || 0, label: 'Attack Paths' },
                { value: data.stats?.findings || 0, label: 'Findings' }
            ];

            statItems.forEach(function(item) {
                const stat = document.createElement('div');
                stat.className = 'stat';
                const valueDiv = document.createElement('div');
                valueDiv.className = 'value';
                valueDiv.textContent = item.value;
                const labelDiv = document.createElement('div');
                labelDiv.className = 'label';
                labelDiv.textContent = item.label;
                stat.appendChild(valueDiv);
                stat.appendChild(labelDiv);
                statsEl.appendChild(stat);
            });

            const pathList = document.getElementById('pathList');
            pathList.replaceChildren();

            const paths = data.paths || [];
            if (paths.length === 0) {
                const li = document.createElement('li');
                li.className = 'path-item';
                li.textContent = 'No attack paths found';
                pathList.appendChild(li);
            } else {
                paths.forEach(function(p, i) {
                    const li = document.createElement('li');
                    li.className = 'path-item';

                    const nameDiv = document.createElement('div');
                    nameDiv.className = 'path-name';
                    nameDiv.textContent = (i + 1) + '. ' + p.name;

                    const probSpan = document.createElement('span');
                    probSpan.className = 'path-prob';
                    probSpan.textContent = Math.round(p.probability * 100) + '%';

                    const descDiv = document.createElement('div');
                    descDiv.className = 'path-desc';
                    descDiv.textContent = p.description;

                    li.appendChild(nameDiv);
                    li.appendChild(probSpan);
                    li.appendChild(descDiv);
                    pathList.appendChild(li);
                });
            }
        }
    </script>
</body>
</html>"""
