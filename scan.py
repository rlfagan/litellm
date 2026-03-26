#!/usr/bin/env python3
"""
claudescan - Analyze any GitHub or GitLab repository for AI components.
Usage: python scan.py <repo_url>
"""

import sys
import os
import tempfile
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

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


def collect_repo_content(repo_dir):
    root = Path(repo_dir)
    chunks = []
    total = 0

    def has_ai_keyword(text):
        low = text.lower()
        return any(kw in low for kw in AI_KEYWORDS)

    # Priority 1: known config/dependency files
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

    # Priority 2: source files mentioning AI keywords
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

    system = """You are an expert AI/ML security and code analyst. Analyze repository files for AI components and produce a structured report.

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


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan.py <github-or-gitlab-url>")
        print("Example: python scan.py https://github.com/rlfagan/litellm")
        sys.exit(1)

    repo_url = sys.argv[1].rstrip("/")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    tmp_dir = tempfile.mkdtemp(prefix="claudescan_")
    repo_name = Path(urlparse(repo_url).path).name.replace(".git", "")
    repo_dir = os.path.join(tmp_dir, repo_name)

    try:
        if not clone_repo(repo_url, repo_dir):
            sys.exit(1)

        print("Collecting AI-relevant files...", flush=True)
        content = collect_repo_content(repo_dir)
        print(f"Collected {len(content):,} chars from repo.\n", flush=True)
        print("=" * 70)

        analyze_with_claude(repo_url, content)

        print("=" * 70)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
