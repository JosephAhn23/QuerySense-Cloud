"""
Claude LLM explainer (OPTIONAL).

Only use this when deterministic suggestions aren't enough.
The analyzer works perfectly without any LLM.

Requires: pip install anthropic
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


@dataclass
class ClaudeExplainer(Explainer):
    """
    Simple Claude-based explainer.
    
    Use sparingly - deterministic suggestions are usually better.
    
    Example:
        # Only if you really need LLM explanations
        explainer = ClaudeExplainer(api_key="...")
        result = await explainer.explain_one(finding)
    """
    
    api_key: str
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 300
    timeout_seconds: float = 30.0
    
    _client: Any = None
    
    async def _get_client(self) -> Any:
        """Get or create the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:
                raise ImportError(
                    "anthropic package required. Install with: pip install anthropic"
                ) from e
            
            self._client = anthropic.AsyncAnthropic(
                api_key=self.api_key,
                timeout=self.timeout_seconds,
            )
        return self._client
    
    async def explain_one(self, finding: "Finding") -> ExplanationResult:
        """
        Get LLM explanation for a finding.
        
        Consider: Do you actually need this? The finding already has
        a deterministic suggestion. LLM adds latency and cost.
        """
        start_time = time.perf_counter()
        finding_id = f"{finding.rule_id}:{finding.context.path}"
        
        try:
            client = await self._get_client()
            
            prompt = self._build_prompt(finding)
            
            response = await client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            
            explanation = response.content[0].text
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            return ExplanationResult(
                finding_id=finding_id,
                explanation=explanation,
                latency_ms=latency_ms,
            )
        
        except Exception as e:
            logger.warning("Claude API error: %s", e)
            return ExplanationResult(
                finding_id=finding_id,
                explanation=None,
                error=str(e),
            )
    
    def _build_prompt(self, finding: "Finding") -> str:
        """Build a simple prompt."""
        ctx = finding.context
        
        return f"""You are a PostgreSQL performance expert.

Explain this query performance issue to a developer in 2-3 sentences.

Issue: {finding.title}
Description: {finding.description}
Table: {ctx.relation_name or 'unknown'}
Rows: {ctx.actual_rows or 'unknown'}
Filter: {ctx.filter or 'none'}

The analyzer already suggested: {finding.suggestion or 'None'}

Add any additional context that would help a developer understand WHY this matters.
Keep it brief and actionable."""