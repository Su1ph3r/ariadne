"""HTML report generator."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ariadne.models.attack_path import AttackPath
from ariadne.models.playbook import Playbook


class HtmlReporter:
    """Generate HTML reports from attack paths."""

    def __init__(self) -> None:
        try:
            self.env = Environment(
                loader=PackageLoader("ariadne.output", "templates"),
                autoescape=select_autoescape(["html", "xml"]),
            )
        except Exception:
            self.env = None

    def generate(
        self,
        paths: list[AttackPath],
        output_path: Path,
        stats: dict | None = None,
        playbooks: list[Playbook] | None = None,
    ) -> Path:
        """Generate an HTML report.

        Args:
            paths: List of attack paths to include
            output_path: Output file path
            stats: Optional graph statistics

        Returns:
            Path to generated report
        """
        output_file = output_path.with_suffix(".html")

        # Build playbook lookup
        playbook_map: dict[str, Playbook] = {}
        if playbooks:
            for pb in playbooks:
                playbook_map[pb.attack_path_id] = pb

        if self.env:
            try:
                template = self.env.get_template("report.html.j2")
                html = template.render(
                    paths=paths,
                    stats=stats or {},
                    generated_at=datetime.utcnow().isoformat(),
                    summary=self._generate_summary(paths),
                    playbook_map=playbook_map,
                )
            except Exception:
                html = self._generate_fallback_html(paths, stats, playbook_map)
        else:
            html = self._generate_fallback_html(paths, stats, playbook_map)

        with open(output_file, "w") as f:
            f.write(html)

        return output_file

    def _generate_summary(self, paths: list[AttackPath]) -> dict:
        """Generate summary statistics."""
        if not paths:
            return {"total_paths": 0}

        return {
            "total_paths": len(paths),
            "avg_probability": sum(p.probability for p in paths) / len(paths),
            "critical_count": sum(1 for p in paths if p.probability >= 0.7),
            "high_count": sum(1 for p in paths if 0.5 <= p.probability < 0.7),
        }

    def _render_playbook_html(self, playbook: Playbook) -> str:
        """Render a playbook section as HTML."""
        steps_html = ""
        for step in playbook.steps:
            cmds_html = ""
            for cmd in step.commands:
                root_badge = ' <span class="badge root">ROOT</span>' if cmd.requires_root else ""
                implant_badge = ' <span class="badge implant">IMPLANT</span>' if cmd.requires_implant else ""
                cmds_html += f"""
                    <div class="pb-command">
                        <span class="pb-tool">{escape(cmd.tool)}</span>{root_badge}{implant_badge}
                        <pre><code>{escape(cmd.command)}</code></pre>
                        <small>{escape(cmd.description)}</small>
                    </div>"""

            fallbacks_html = ""
            if step.fallback_commands:
                fb_cmds = ""
                for cmd in step.fallback_commands:
                    fb_cmds += f"""
                        <div class="pb-command">
                            <span class="pb-tool">{escape(cmd.tool)}</span>
                            <pre><code>{escape(cmd.command)}</code></pre>
                            <small>{escape(cmd.description)}</small>
                        </div>"""
                fallbacks_html = f'<div class="pb-fallbacks"><h6>Fallback Commands</h6>{fb_cmds}</div>'

            opsec_html = ""
            if step.opsec_notes:
                notes = "".join(f"<li>{escape(n)}</li>" for n in step.opsec_notes)
                opsec_html = f'<div class="pb-opsec"><h6>OPSEC Notes</h6><ul>{notes}</ul></div>'

            prereqs_html = ""
            if step.prerequisites:
                items = "".join(f"<li>{escape(p)}</li>" for p in step.prerequisites)
                prereqs_html = f'<div class="pb-prereqs"><h6>Prerequisites</h6><ul>{items}</ul></div>'

            sigs_html = ""
            if step.detection_signatures:
                items = "".join(f"<li>{escape(s)}</li>" for s in step.detection_signatures)
                sigs_html = f'<div class="pb-sigs"><h6>Detection Signatures</h6><ul>{items}</ul></div>'

            steps_html += f"""
                <div class="pb-step">
                    <div class="pb-step-header">Step {step.order + 1} <span class="pb-source">[{escape(step.source)}]</span></div>
                    {prereqs_html}
                    <div class="pb-commands"><h6>Commands</h6>{cmds_html}</div>
                    {opsec_html}
                    {fallbacks_html}
                    {sigs_html}
                    {f'<div class="pb-expected"><h6>Expected Output</h6><p>{escape(step.expected_output)}</p></div>' if step.expected_output else ""}
                </div>"""

        global_opsec = ""
        if playbook.global_opsec_notes:
            notes = "".join(f"<li>{escape(n)}</li>" for n in playbook.global_opsec_notes)
            global_opsec = f'<div class="pb-opsec"><h6>Global OPSEC Notes</h6><ul>{notes}</ul></div>'

        return f"""
            <div class="playbook-section">
                <details>
                    <summary>Operator Playbook <span class="pb-meta">Complexity: {escape(playbook.complexity)} | Est. Time: {escape(playbook.estimated_time)}{' | LLM Enhanced' if playbook.llm_enhanced else ''}</span></summary>
                    {global_opsec}
                    {steps_html}
                </details>
            </div>"""

    def _generate_fallback_html(
        self,
        paths: list[AttackPath],
        stats: dict | None,
        playbook_map: dict[str, Playbook] | None = None,
    ) -> str:
        """Generate HTML without Jinja2 templates."""
        summary = self._generate_summary(paths)
        playbook_map = playbook_map or {}

        paths_html = ""
        for i, path in enumerate(paths, 1):
            prob_class = "critical" if path.probability >= 0.7 else "high" if path.probability >= 0.5 else "medium"

            steps_html = ""
            for step in path.steps:
                technique_info = ""
                if step.technique:
                    technique_info = (
                        f'<span class="technique">'
                        f'[{escape(step.technique.technique_id)}]'
                        f'</span>'
                    )

                steps_html += f"""
                <div class="step">
                    <div class="step-order">{step.order + 1}</div>
                    <div class="step-content">
                        <strong>{escape(step.action)}</strong> {technique_info}
                        <p>{escape(step.description)}</p>
                        <small>Probability: {step.probability:.0%} | Detection Risk: {step.detection_risk:.0%}</small>
                    </div>
                </div>
                """

            playbook_html = ""
            playbook = playbook_map.get(path.id)
            if playbook:
                playbook_html = self._render_playbook_html(playbook)

            llm_html = ""
            if path.llm_analysis:
                llm_html = (
                    "<div class='llm-analysis'><h4>AI Analysis</h4>"
                    f"<p>{escape(path.llm_analysis)}</p></div>"
                )

            paths_html += f"""
            <div class="attack-path {prob_class}">
                <div class="path-header">
                    <h3>{i}. {escape(path.name)}</h3>
                    <span class="probability">{path.probability:.0%}</span>
                </div>
                <p class="description">{escape(path.description)}</p>
                <div class="steps">
                    {steps_html}
                </div>
                {llm_html}
                {playbook_html}
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ariadne Attack Path Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-critical: #f85149;
            --accent-high: #d29922;
            --accent-medium: #58a6ff;
            --accent-low: #3fb950;
            --border-color: #30363d;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }}

        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}

        header .subtitle {{
            color: var(--text-secondary);
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}

        .stat-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .stat-card.critical .value {{ color: var(--accent-critical); }}
        .stat-card.high .value {{ color: var(--accent-high); }}

        .attack-path {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}

        .attack-path.critical {{
            border-left: 4px solid var(--accent-critical);
        }}

        .attack-path.high {{
            border-left: 4px solid var(--accent-high);
        }}

        .attack-path.medium {{
            border-left: 4px solid var(--accent-medium);
        }}

        .path-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }}

        .path-header h3 {{
            font-size: 1.1rem;
        }}

        .probability {{
            font-size: 1.25rem;
            font-weight: bold;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            background: var(--bg-primary);
        }}

        .critical .probability {{ color: var(--accent-critical); }}
        .high .probability {{ color: var(--accent-high); }}
        .medium .probability {{ color: var(--accent-medium); }}

        .description {{
            padding: 1rem 1.5rem;
            color: var(--text-secondary);
        }}

        .steps {{
            padding: 1rem 1.5rem;
        }}

        .step {{
            display: flex;
            gap: 1rem;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .step:last-child {{
            border-bottom: none;
        }}

        .step-order {{
            width: 32px;
            height: 32px;
            background: var(--bg-tertiary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            flex-shrink: 0;
        }}

        .step-content {{
            flex: 1;
        }}

        .step-content small {{
            color: var(--text-secondary);
            display: block;
            margin-top: 0.25rem;
        }}

        .technique {{
            color: var(--accent-medium);
            font-size: 0.875rem;
            margin-left: 0.5rem;
        }}

        .llm-analysis {{
            padding: 1rem 1.5rem;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border-color);
        }}

        .llm-analysis h4 {{
            margin-bottom: 0.5rem;
            color: var(--accent-medium);
        }}

        .playbook-section {{
            border-top: 1px solid var(--border-color);
        }}

        .playbook-section details {{
            padding: 0;
        }}

        .playbook-section summary {{
            padding: 1rem 1.5rem;
            cursor: pointer;
            font-weight: bold;
            color: var(--accent-high);
            background: var(--bg-tertiary);
        }}

        .playbook-section summary:hover {{
            background: var(--bg-primary);
        }}

        .pb-meta {{
            font-weight: normal;
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-left: 1rem;
        }}

        .pb-step {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .pb-step-header {{
            font-weight: bold;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }}

        .pb-source {{
            font-weight: normal;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .pb-command {{
            margin: 0.5rem 0;
        }}

        .pb-tool {{
            display: inline-block;
            background: var(--accent-medium);
            color: var(--bg-primary);
            padding: 0.1rem 0.5rem;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-bottom: 0.25rem;
        }}

        .badge {{
            font-size: 0.7rem;
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
            margin-left: 0.25rem;
        }}

        .badge.root {{
            background: var(--accent-critical);
            color: #fff;
        }}

        .badge.implant {{
            background: var(--accent-high);
            color: var(--bg-primary);
        }}

        .pb-command pre {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 0.5rem 0.75rem;
            overflow-x: auto;
            margin: 0.25rem 0;
        }}

        .pb-command code {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85rem;
            color: var(--accent-low);
        }}

        .pb-command small {{
            color: var(--text-secondary);
            display: block;
        }}

        .pb-opsec {{
            background: rgba(210, 153, 34, 0.1);
            border-left: 3px solid var(--accent-high);
            padding: 0.5rem 1rem;
            margin: 0.5rem 0;
            border-radius: 0 4px 4px 0;
        }}

        .pb-opsec h6 {{
            color: var(--accent-high);
            margin-bottom: 0.25rem;
        }}

        .pb-opsec ul, .pb-prereqs ul, .pb-sigs ul {{
            margin: 0;
            padding-left: 1.25rem;
        }}

        .pb-opsec li, .pb-prereqs li, .pb-sigs li {{
            font-size: 0.875rem;
            margin-bottom: 0.1rem;
        }}

        .pb-prereqs {{
            margin: 0.5rem 0;
        }}

        .pb-prereqs h6 {{
            color: var(--accent-medium);
            margin-bottom: 0.25rem;
        }}

        .pb-sigs {{
            background: rgba(248, 81, 73, 0.1);
            border-left: 3px solid var(--accent-critical);
            padding: 0.5rem 1rem;
            margin: 0.5rem 0;
            border-radius: 0 4px 4px 0;
        }}

        .pb-sigs h6 {{
            color: var(--accent-critical);
            margin-bottom: 0.25rem;
        }}

        .pb-fallbacks {{
            margin: 0.5rem 0;
            padding: 0.5rem 1rem;
            border-left: 3px solid var(--text-secondary);
        }}

        .pb-fallbacks h6 {{
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }}

        .pb-expected {{
            margin: 0.5rem 0;
        }}

        .pb-expected h6 {{
            color: var(--accent-low);
            margin-bottom: 0.25rem;
        }}

        .pb-commands h6 {{
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Ariadne</h1>
            <p class="subtitle">Attack Path Analysis Report</p>
            <p class="subtitle">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="value">{summary['total_paths']}</div>
                <div class="label">Attack Paths</div>
            </div>
            <div class="stat-card critical">
                <div class="value">{summary.get('critical_count', 0)}</div>
                <div class="label">Critical Paths</div>
            </div>
            <div class="stat-card high">
                <div class="value">{summary.get('high_count', 0)}</div>
                <div class="label">High Risk Paths</div>
            </div>
            <div class="stat-card">
                <div class="value">{summary.get('avg_probability', 0):.0%}</div>
                <div class="label">Avg Probability</div>
            </div>
        </div>

        <main>
            {paths_html if paths_html else '<p style="text-align: center; color: var(--text-secondary);">No attack paths found.</p>'}
        </main>

        <footer>
            <p>Generated by Ariadne Attack Path Synthesizer v0.1.0</p>
            <p>Follow the thread through the labyrinth.</p>
        </footer>
    </div>
</body>
</html>"""
