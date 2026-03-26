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
import asyncio
from pathlib import Path
from urllib.parse import urlparse

from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage, SystemMessage


SYSTEM_PROMPT = """You are an expert AI/ML code analyst. Your job is to analyze a cloned repository and identify every AI component it contains.

After reading the codebase, produce a structured report covering:

1. **AI Frameworks & Libraries** — e.g., OpenAI SDK, Anthropic SDK, LangChain, LlamaIndex, Hugging Face Transformers, PyTorch, TensorFlow, JAX, scikit-learn, spaCy, NLTK, etc.
2. **LLM Integrations** — which models or APIs are called (GPT-4, Claude, Gemini, Llama, Mistral, etc.), how they are invoked, and what they are used for
3. **Embedding & Vector Search** — embedding models, vector databases (Pinecone, Weaviate, Chroma, FAISS, pgvector, etc.)
4. **AI Agents & Orchestration** — agent frameworks, tool use, function calling, multi-agent setups, memory systems
5. **ML Models** — any trained models (loaded from files, HuggingFace Hub, ONNX, etc.)
6. **Prompt Engineering** — prompt templates, system prompts, few-shot examples (note file locations)
7. **AI Infrastructure** — MLflow, Weights & Biases, Ray, Kubeflow, model serving, etc.
8. **Configuration & API Keys** — which AI service keys/endpoints are configured (env vars, config files)

For each component found, note:
- What it is
- Where it appears (file path and approximate line numbers if possible)
- What it is used for in the project

Be thorough — check requirements files, pyproject.toml, package.json, Cargo.toml, go.mod, source code, config files, Dockerfiles, and CI configs.

If no AI components are found, say so clearly.

End with a **Summary** section listing all AI components found in a concise bullet list.
"""


def clone_repo(url: str, target_dir: str) -> bool:
    """Clone a git repository to target_dir. Returns True on success."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print(f"Error: '{url}' does not look like a valid URL.", file=sys.stderr)
        return False

    print(f"Cloning {url} ...", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, target_dir],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Error cloning repo:\n{result.stderr}", file=sys.stderr)
        return False
    print("Clone complete.\n", flush=True)
    return True


async def analyze_repo(repo_dir: str, repo_url: str) -> str:
    """Run the Claude agent on the cloned repo and return the report."""
    prompt = (
        f"Analyze the repository cloned to the current directory.\n"
        f"Original URL: {repo_url}\n\n"
        "Examine the codebase thoroughly and produce a detailed report of all AI components found. "
        "Start by listing files with Glob to get an overview, then read relevant files."
    )

    options = ClaudeAgentOptions(
        cwd=repo_dir,
        allowed_tools=["Glob", "Read", "Grep"],
        system_prompt=SYSTEM_PROMPT,
        permission_mode="default",
        max_turns=50,
    )

    result_text = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, ResultMessage):
            result_text = message.result
        elif isinstance(message, SystemMessage) and message.subtype == "init":
            session_id = message.data.get("session_id", "")
            print(f"Session: {session_id}\n", flush=True)

    return result_text


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan.py <github-or-gitlab-url>")
        print("Example: python scan.py https://github.com/anthropics/anthropic-sdk-python")
        sys.exit(1)

    repo_url = sys.argv[1].rstrip("/")

    # Check for ANTHROPIC_API_KEY
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    tmp_dir = tempfile.mkdtemp(prefix="claudescan_")
    repo_name = Path(urlparse(repo_url).path).name.replace(".git", "")
    repo_dir = os.path.join(tmp_dir, repo_name)

    try:
        if not clone_repo(repo_url, repo_dir):
            sys.exit(1)

        print("Analyzing repository for AI components...\n", flush=True)
        print("=" * 70)

        report = asyncio.run(analyze_repo(repo_dir, repo_url))

        print(report)
        print("=" * 70)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
