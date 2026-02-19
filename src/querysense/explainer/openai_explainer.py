"""
OpenAI LLM explainer (OPTIONAL).

Supports GPT-4o, GPT-4o-mini, and any OpenAI-compatible API.

Requires: pip install openai
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

# ── System prompt for query optimization ────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior database performance engineer. Your job is to explain
database query performance findings in clear, actionable language.

Guidelines:
- Be concise (2-3 sentences max)
- Focus on the "why" and "how to fix"
- Reference specific columns, tables, and indexes
- Avoid jargon unless the user asks for depth
- Never say "it depends" — give a concrete recommendation
"""


@dataclass
class OpenAIExplainer(Explainer):
    """
    OpenAI-based explainer.

    Works with GPT-4o, GPT-4o-mini, or any OpenAI-compatible API
    (Azure OpenAI, Together AI, OpenRouter, etc.).

    Example:
        explainer = OpenAIExplainer(api_key="sk-...")
        result = await explainer.explain_one(finding)

        # Or with Azure OpenAI:
        explainer = OpenAIExplainer(
            api_key="...",
            base_url="https://myinstance.openai.azure.com/",
            model="gpt-4o",
        )
    """

    api_key: str
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    max_tokens: int = 300
    temperature: float = 0.3
    timeout_seconds: float = 30.0

    _client: Any = None

    async def _get_client(self) -> Any:
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError:
                raise RuntimeError(
                    "openai package required.\n"
                    "Install with: pip install openai"
                )
            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = AsyncOpenAI(**kwargs)
        return self._client

    async def explain_one(self, finding: "Finding") -> ExplanationResult:
        """Explain a single finding using OpenAI."""
        start = time.monotonic()

        try:
            client = await self._get_client()

            # Build user prompt from finding
            user_content = self._format_finding(finding)

            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )

            explanation = response.choices[0].message.content or ""
            latency = (time.monotonic() - start) * 1000

            return ExplanationResult(
                finding_id=getattr(finding, "id", ""),
                explanation=explanation.strip(),
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
