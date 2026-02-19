"""
Ollama local LLM explainer — privacy-first, zero data leaves your machine.

Connects to a locally running Ollama instance. No API keys required.
Supports any model Ollama supports: llama3, codellama, mistral, phi, etc.

Requires: Ollama running locally (https://ollama.ai)
    ollama serve   # Start the server
    ollama pull llama3   # Download a model

No pip dependency needed — uses standard httpx/urllib.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from querysense.explainer.protocol import ExplanationResult, Explainer

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior database performance engineer. Explain database query
performance findings in clear, actionable language.

Rules:
- Be concise (2-3 sentences max)
- Focus on "why" and "how to fix"
- Reference specific columns, tables, and indexes
- Give concrete recommendations, never say "it depends"
"""


@dataclass
class OllamaExplainer(Explainer):
    """
    Privacy-first local LLM explainer using Ollama.

    All processing happens locally — your queries and schema never leave
    your machine. Perfect for regulated environments (HIPAA, SOC2, PCI).

    Example:
        # Make sure Ollama is running: ollama serve
        explainer = OllamaExplainer(model="llama3")
        result = await explainer.explain_one(finding)

        # Use a code-specific model:
        explainer = OllamaExplainer(model="codellama:13b")

        # Custom Ollama host:
        explainer = OllamaExplainer(
            model="mistral",
            base_url="http://gpu-server:11434",
        )
    """

    model: str = "llama3"
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 60.0  # Local models can be slower
    max_tokens: int = 300
    temperature: float = 0.3

    async def explain_one(self, finding: "Finding") -> ExplanationResult:
        """Explain a finding using local Ollama model."""
        start = time.monotonic()

        try:
            response = await self._call_ollama(finding)
            latency = (time.monotonic() - start) * 1000

            return ExplanationResult(
                finding_id=getattr(finding, "id", ""),
                explanation=response.strip(),
                latency_ms=latency,
            )

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return ExplanationResult(
                finding_id=getattr(finding, "id", ""),
                explanation=None,
                error=str(e),
                latency_ms=latency,
            )

    async def _call_ollama(self, finding: "Finding") -> str:
        """Make an async HTTP call to the Ollama API."""
        url = f"{self.base_url.rstrip('/')}/api/chat"

        user_content = self._format_finding(finding)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": self.temperature,
            },
        }

        # Try httpx first (async), fall back to urllib
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
        except ImportError:
            # Fallback to synchronous urllib
            import urllib.request
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "")

    def _format_finding(self, finding: "Finding") -> str:
        """Format a finding into a prompt."""
        parts = [f"Database finding: {getattr(finding, 'title', 'Unknown')}"]

        desc = getattr(finding, "description", "")
        if desc:
            parts.append(f"Description: {desc}")

        sql = getattr(finding, "sql", "")
        if sql:
            parts.append(f"SQL: {sql}")

        severity = getattr(finding, "severity", "")
        if severity:
            parts.append(f"Severity: {severity}")

        parts.append(
            "Explain this finding in 2-3 sentences. "
            "Why is it happening and what should the developer do?"
        )
        return "\n".join(parts)


async def check_ollama(base_url: str = "http://localhost:11434") -> dict[str, Any]:
    """
    Check if Ollama is running and list available models.

    Returns:
        {"available": True, "models": ["llama3", "codellama", ...]}
        or {"available": False, "error": "..."}
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return {"available": True, "models": models}
    except ImportError:
        import urllib.request
        try:
            req = urllib.request.Request(f"{base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                models = [m["name"] for m in data.get("models", [])]
                return {"available": True, "models": models}
        except Exception as e:
            return {"available": False, "error": str(e)}
    except Exception as e:
        return {"available": False, "error": str(e)}
