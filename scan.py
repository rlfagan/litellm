#!/usr/bin/env python3
"""
claudescan - Analyze any GitHub or GitLab repository for AI components.
Usage: python scan.py <repo_url>
"""

import sys
import os
import re
import tempfile
import shutil
import subprocess
import webbrowser
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

import anthropic

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
             "dist", "build", ".next", "vendor", "target"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
             ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar",
             ".gz", ".pyc", ".min.js", ".min.css"}
AI_INDICATOR_FILES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "package.json", "go.mod", "Cargo.toml",
    "Gemfile", "composer.json", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".env.example", "Makefile",
}
AI_KEYWORDS = {
    "openai", "anthropic", "claude", "langchain", "llamaindex", "llama_index",
    "huggingface", "transformers", "torch", "tensorflow", "keras", "jax",
    "sklearn", "scikit", "spacy", "nltk", "gpt", "llm", "embedding",
    "pinecone", "weaviate", "chroma", "faiss", "qdrant", "milvus",
    "cohere", "gemini", "mistral", "ollama", "litellm", "openrouter",
    "together", "replicate", "groq", "perplexity", "vectorstore",
    "langsmith", "mlflow", "wandb",
}

# Model patterns to detect and highlight
MODEL_PATTERNS = [
    r'gpt-4[o\w\-\.]*',
    r'gpt-3\.5[o\w\-\.]*',
    r'claude-[\w\.\-]+',
    r'gemini-[\w\.\-]+',
    r'mistral-[\w\.\-]+',
    r'llama[\-_]?[\w\.\-]*',
    r'mixtral[\-_]?[\w\.\-]*',
    r'deepseek[\-_]?[\w\.\-]*',
    r'command[\-_]r[\w\.\-]*',
    r'titan[\-_][\w\.\-]+',
    r'nova[\-_][\w\.\-]+',
    r'sonar[\-_]?[\w\.\-]*',
    r'o1[\-\w]*',
    r'o3[\-\w]*',
    r'embed[\-_][\w\.\-]+',
    r'text[\-_]embedding[\-_][\w\.\-]+',
]

MAX_FILE_SIZE = 100_000
MAX_TOTAL_CHARS = 180_000


def clone_repo(url, target_dir):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print(f"Error: '{url}' is not a valid URL.", file=sys.stderr)
        return False
    print(f"Cloning {url} ...", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, target_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Clone failed:\n{result.stderr}", file=sys.stderr)
        return False
    print("Clone complete.\n", flush=True)
    return True


def find_model_references(repo_dir, repo_url):
    """Find all model name references in the codebase with file+line locations."""
    root = Path(repo_dir)
    refs = {}  # model_name -> list of {file, line, snippet, url}

    # Determine base URL for linking (GitHub/GitLab)
    parsed = urlparse(repo_url)
    base = repo_url.rstrip("/")
    is_github = "github.com" in parsed.netloc
    is_gitlab = "gitlab.com" in parsed.netloc

    def make_link(rel_path, line_no):
        if is_github:
            return f"{base}/blob/main/{rel_path}#L{line_no}"
        elif is_gitlab:
            return f"{base}/-/blob/main/{rel_path}#L{line_no}"
        return f"{base}/{rel_path}"

    combined_pattern = re.compile(
        "|".join(MODEL_PATTERNS), re.IGNORECASE
    )

    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if f.suffix.lower() in SKIP_EXTS:
            continue
        if f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            lines = f.read_text(errors="replace").splitlines()
            rel = str(f.relative_to(root))
            for i, line in enumerate(lines, 1):
                for m in combined_pattern.finditer(line):
                    model = m.group(0).lower().rstrip(".,;\"')")
                    if model not in refs:
                        refs[model] = []
                    refs[model].append({
                        "file": rel,
                        "line": i,
                        "snippet": line.strip()[:120],
                        "url": make_link(rel, i),
                    })
        except Exception:
            pass

    # Deduplicate: keep max 5 refs per model
    for model in refs:
        seen_files = set()
        deduped = []
        for r in refs[model]:
            key = (r["file"], r["line"])
            if key not in seen_files:
                seen_files.add(key)
                deduped.append(r)
        refs[model] = deduped[:5]

    return refs


def collect_repo_content(repo_dir):
    root = Path(repo_dir)
    chunks = []
    total = 0

    def has_ai_keyword(text):
        low = text.lower()
        return any(kw in low for kw in AI_KEYWORDS)

    for f in sorted(root.rglob("*")):
        if total > MAX_TOTAL_CHARS:
            break
        if not f.is_file():
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if f.name in AI_INDICATOR_FILES:
            try:
                text = f.read_text(errors="replace")
                rel = f.relative_to(root)
                chunk = f"\n\n### {rel}\n```\n{text[:8000]}\n```"
                chunks.append(chunk)
                total += len(chunk)
            except Exception:
                pass

    for f in sorted(root.rglob("*")):
        if total > MAX_TOTAL_CHARS:
            break
        if not f.is_file() or f.name in AI_INDICATOR_FILES:
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if f.suffix.lower() in SKIP_EXTS:
            continue
        if f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            text = f.read_text(errors="replace")
            if has_ai_keyword(text):
                rel = f.relative_to(root)
                chunk = f"\n\n### {rel}\n```\n{text[:6000]}\n```"
                chunks.append(chunk)
                total += len(chunk)
        except Exception:
            pass

    return "".join(chunks) if chunks else "(no relevant files found)"


def analyze_with_claude(repo_url, content):
    client = anthropic.Anthropic()

    system = """You are an expert AI/ML security and code analyst. Analyze repository files for AI components and produce a structured Markdown report.

Cover these categories (skip any with no findings):
1. **AI Frameworks & Libraries** - OpenAI, Anthropic, LangChain, LlamaIndex, HuggingFace, PyTorch, TensorFlow, LiteLLM, etc.
2. **LLM Integrations** - which models/APIs are called, how, and what for
3. **Embeddings & Vector Search** - embedding models, vector DBs (Pinecone, Chroma, FAISS, pgvector, etc.)
4. **AI Agents & Orchestration** - agent frameworks, tool use, memory, multi-agent
5. **ML Models** - trained models loaded from files, HuggingFace Hub, ONNX, etc.
6. **Prompt Engineering** - prompt templates, system prompts, few-shot examples (with file paths)
7. **AI Infrastructure** - MLflow, W&B, Ray, model serving, etc.
8. **Security Concerns** - known vulnerable AI libraries (e.g. LiteLLM CVEs), hardcoded keys, unsafe model deserialization

For each finding: what it is, where (file path), what it does.
Use markdown tables where appropriate.
End with a **Summary** bullet list of all AI components found."""

    user = f"Analyze this repository for AI components.\nURL: {repo_url}\n\nRepository file contents:\n{content}"

    print("Sending to Claude for analysis...\n", flush=True)

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": user}],
    ) as stream:
        result = []
        for text in stream.text_stream:
            print(text, end="", flush=True)
            result.append(text)
        print("\n")
        return "".join(result)


def build_model_section_md(model_refs):
    """Build a Markdown section for confirmed model references."""
    if not model_refs:
        return "\n## Confirmed Models in Codebase\n\n_No specific model names detected._\n"

    lines = ["\n## Confirmed Models in Codebase\n"]
    lines.append("The following model names were found directly in the source code:\n")

    for model in sorted(model_refs.keys()):
        refs = model_refs[model]
        lines.append(f"\n### `{model}`\n")
        lines.append("| File | Line | Code Snippet | Link |")
        lines.append("|------|------|-------------|------|")
        for r in refs:
            snippet = r["snippet"].replace("|", "\\|")
            lines.append(f"| `{r['file']}` | {r['line']} | `{snippet}` | [view]({r['url']}) |")

    return "\n".join(lines)


def build_model_section_html(model_refs):
    """Build an HTML section for confirmed model references."""
    if not model_refs:
        return "<p><em>No specific model names detected in codebase.</em></p>"

    html = []
    for model in sorted(model_refs.keys()):
        refs = model_refs[model]
        rows = ""
        for r in refs:
            snippet = r["snippet"].replace("<", "&lt;").replace(">", "&gt;")
            rows += f"""
            <tr>
              <td><code>{r['file']}</code></td>
              <td>{r['line']}</td>
              <td><code>{snippet}</code></td>
              <td><a href="{r['url']}" target="_blank">view →</a></td>
            </tr>"""
        html.append(f"""
        <div class="model-card">
          <div class="model-name">🤖 {model}</div>
          <table>
            <thead><tr><th>File</th><th>Line</th><th>Snippet</th><th>Link</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>""")

    return "\n".join(html)


def md_to_html_basic(md_text):
    """Very basic Markdown → HTML conversion for the report body."""
    import html as html_lib
    lines = md_text.split("\n")
    out = []
    in_table = False
    in_code = False
    in_list = False

    for line in lines:
        # Code blocks
        if line.strip().startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(html_lib.escape(line))
            continue

        # Tables
        if "|" in line and line.strip().startswith("|"):
            if not in_table:
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append('<table class="report-table"><tbody>')
                in_table = True
            if re.match(r"^\|[\s\-|]+\|$", line.strip()):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            is_header = out and out[-1] == '<table class="report-table"><tbody>'
            tag = "th" if is_header else "td"
            row = "".join(f"<{tag}>{inline_md(c)}</{tag}>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            continue
        else:
            if in_table:
                out.append("</tbody></table>")
                in_table = False

        # Headings
        if line.startswith("#### "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h4>{inline_md(line[5:])}</h4>")
        elif line.startswith("### "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h3>{inline_md(line[4:])}</h3>")
        elif line.startswith("## "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h2>{inline_md(line[3:])}</h2>")
        elif line.startswith("# "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h1>{inline_md(line[2:])}</h1>")
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline_md(line[2:])}</li>")
        elif line.strip() == "":
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<br>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{inline_md(line)}</p>")

    if in_table:
        out.append("</tbody></table>")
    if in_list:
        out.append("</ul>")

    return "\n".join(out)


def inline_md(text):
    """Convert inline markdown (bold, code, links) to HTML."""
    import html as html_lib
    text = html_lib.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2" target="_blank">\1</a>', text)
    return text


def write_markdown(output_path, repo_url, report_md, model_refs):
    repo_name = Path(urlparse(repo_url).path).name
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    header = f"# AI Component Scan: {repo_name}\n\n**Repo:** {repo_url}  \n**Scanned:** {ts}\n\n---\n"
    model_section = build_model_section_md(model_refs)
    full = header + report_md + "\n\n---\n" + model_section
    Path(output_path).write_text(full)
    print(f"Markdown report: {output_path}")


def write_html(output_path, repo_url, report_md, model_refs):
    repo_name = Path(urlparse(repo_url).path).name
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    report_html = md_to_html_basic(report_md)
    model_html = build_model_section_html(model_refs)
    model_count = len(model_refs)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Scan: {repo_name}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
    --model: #7ee787; --model-bg: #0f2a0f;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }}
  .header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 24px 40px; }}
  .header h1 {{ font-size: 1.6rem; color: var(--accent); }}
  .header .meta {{ color: var(--muted); font-size: 0.9rem; margin-top: 6px; }}
  .header a {{ color: var(--accent); }}
  .badges {{ display: flex; gap: 12px; margin-top: 12px; flex-wrap: wrap; }}
  .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; }}
  .badge-model {{ background: var(--model-bg); color: var(--model); border: 1px solid var(--model); }}
  .badge-warn {{ background: #2d1a00; color: var(--yellow); border: 1px solid var(--yellow); }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}
  .section-label {{ font-size: 0.75rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin: 32px 0 16px; }}
  .report-body h1 {{ font-size: 1.5rem; color: var(--accent); margin: 28px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  .report-body h2 {{ font-size: 1.2rem; color: var(--text); margin: 24px 0 10px; }}
  .report-body h3 {{ font-size: 1rem; color: var(--accent); margin: 18px 0 8px; }}
  .report-body p {{ margin-bottom: 10px; color: var(--text); }}
  .report-body ul {{ margin: 8px 0 12px 24px; }}
  .report-body li {{ margin-bottom: 4px; }}
  .report-body code {{ background: #1c2128; color: #79c0ff; padding: 2px 6px; border-radius: 4px; font-size: 0.88em; font-family: 'SF Mono', Monaco, monospace; }}
  .report-body pre {{ background: #1c2128; border: 1px solid var(--border); border-radius: 6px; padding: 16px; overflow-x: auto; margin: 12px 0; }}
  .report-body pre code {{ background: none; color: #e6edf3; padding: 0; }}
  .report-body a {{ color: var(--accent); }}
  .report-body strong {{ color: #f0f6fc; }}
  table.report-table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.9rem; }}
  table.report-table th, table.report-table td {{ padding: 8px 12px; border: 1px solid var(--border); text-align: left; }}
  table.report-table th {{ background: #1c2128; color: var(--muted); font-weight: 600; }}
  table.report-table tr:hover {{ background: #1c2128; }}
  .models-section {{ margin-top: 40px; }}
  .models-section h2 {{ font-size: 1.3rem; color: var(--model); margin-bottom: 20px; border-bottom: 1px solid var(--model-bg); padding-bottom: 8px; }}
  .model-card {{ background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--model); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
  .model-name {{ background: var(--model-bg); color: var(--model); font-family: 'SF Mono', Monaco, monospace; font-size: 1rem; font-weight: 700; padding: 10px 16px; }}
  .model-card table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  .model-card th {{ background: #111; color: var(--muted); padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  .model-card td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; color: var(--text); vertical-align: top; word-break: break-word; }}
  .model-card tr:last-child td {{ border-bottom: none; }}
  .model-card a {{ color: var(--accent); text-decoration: none; }}
  .model-card a:hover {{ text-decoration: underline; }}
  .model-card code {{ color: #79c0ff; background: #1c2128; padding: 1px 5px; border-radius: 3px; font-size: 0.82em; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; padding: 32px; border-top: 1px solid var(--border); margin-top: 40px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 AI Component Scan</h1>
  <div class="meta">
    <a href="{repo_url}" target="_blank">{repo_url}</a> &nbsp;·&nbsp; Scanned {ts}
  </div>
  <div class="badges">
    <span class="badge badge-model">🤖 {model_count} models confirmed in codebase</span>
    <span class="badge badge-warn">⚠️ Check Security Concerns section</span>
  </div>
</div>

<div class="container">

  <div class="section-label">Analysis Report</div>
  <div class="report-body">
    {report_html}
  </div>

  <div class="models-section">
    <h2>🤖 Confirmed Models in Codebase</h2>
    <p style="color:var(--muted); margin-bottom:20px; font-size:0.9rem;">
      The following model names were detected directly in source files with links to exact locations.
    </p>
    {model_html}
  </div>

</div>

<footer>Generated by claudescan &nbsp;·&nbsp; Powered by Claude Opus 4.6</footer>
</body>
</html>"""

    Path(output_path).write_text(html)
    print(f"HTML report:     {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan.py <github-or-gitlab-url>")
        print("Example: python scan.py https://github.com/rlfagan/litellm")
        sys.exit(1)

    repo_url = sys.argv[1].rstrip("/")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    repo_name = Path(urlparse(repo_url).path).name.replace(".git", "")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(os.getcwd()) / "reports"
    out_dir.mkdir(exist_ok=True)

    tmp_dir = tempfile.mkdtemp(prefix="claudescan_")
    repo_dir = os.path.join(tmp_dir, repo_name)

    try:
        if not clone_repo(repo_url, repo_dir):
            sys.exit(1)

        print("Scanning for model references in codebase...", flush=True)
        model_refs = find_model_references(repo_dir, repo_url)
        print(f"Found {len(model_refs)} distinct model names.\n", flush=True)

        print("Collecting AI-relevant files...", flush=True)
        content = collect_repo_content(repo_dir)
        print(f"Collected {len(content):,} chars.\n", flush=True)
        print("=" * 70)

        report_md = analyze_with_claude(repo_url, content)

        print("=" * 70)
        print("\nWriting reports...", flush=True)

        md_path = out_dir / f"{repo_name}_{ts}.md"
        html_path = out_dir / f"{repo_name}_{ts}.html"

        write_markdown(str(md_path), repo_url, report_md, model_refs)
        write_html(str(html_path), repo_url, report_md, model_refs)

        print(f"\nOpening HTML report in browser...")
        webbrowser.open(f"file://{html_path.absolute()}")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
