"""
Alerting integrations for QuerySense.

Provides Slack, PagerDuty, and email notification channels for plan
regression events detected by `querysense watch` or CI/CD pipelines.

Usage:
    from querysense.alerting import SlackAlert, PagerDutyAlert, AlertDispatcher

    dispatcher = AlertDispatcher()
    dispatcher.add_channel(SlackAlert(webhook_url="https://hooks.slack.com/..."))
    dispatcher.add_channel(PagerDutyAlert(routing_key="..."))

    await dispatcher.send(regression_verdict)
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from querysense.baseline import RegressionVerdict

logger = logging.getLogger(__name__)


# ── Alert Channel Protocol ─────────────────────────────────────────────


@dataclass(frozen=True)
class AlertPayload:
    """Normalized alert payload sent to all channels."""

    query_id: str
    severity: str  # "critical", "high", "medium", "low"
    danger_score: int
    summary: str
    structural_changes: list[str] = field(default_factory=list)
    cost_change: str = ""
    plausible_causes: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "querysense watch"
    hostname: str = ""

    @classmethod
    def from_verdict(cls, verdict: "RegressionVerdict", hostname: str = "") -> "AlertPayload":
        """Create an AlertPayload from a RegressionVerdict."""
        return cls(
            query_id=verdict.query_id,
            severity=verdict.severity.value,
            danger_score=verdict.danger_score,
            summary=verdict.rationale or f"Plan regression on {verdict.query_id}",
            structural_changes=list(verdict.structural_changes),
            cost_change=verdict.cost_change_summary,
            plausible_causes=list(verdict.plausible_causes),
            recommended_actions=list(verdict.recommended_actions),
            hostname=hostname,
        )


class AlertChannel(ABC):
    """Base class for alert channels."""

    @abstractmethod
    def send(self, payload: AlertPayload) -> bool:
        """
        Send an alert. Returns True if successful.

        Implementations should not raise exceptions — log and return False.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this channel."""
        ...


# ── Slack ──────────────────────────────────────────────────────────────


class SlackAlert(AlertChannel):
    """Send alerts to Slack via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        self.webhook_url = webhook_url
        self.channel = channel

    @property
    def name(self) -> str:
        return "Slack"

    def send(self, payload: AlertPayload) -> bool:
        severity_emoji = {
            "critical": ":red_circle:",
            "high": ":large_orange_circle:",
            "medium": ":large_yellow_circle:",
            "low": ":white_circle:",
        }
        emoji = severity_emoji.get(payload.severity, ":grey_question:")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Plan Regression: {payload.query_id}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{payload.severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Danger Score:*\n{payload.danger_score}/100"},
                    {"type": "mrkdwn", "text": f"*Source:*\n{payload.source}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{payload.timestamp[:19]}"},
                ],
            },
        ]

        if payload.summary:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{payload.summary[:500]}"},
            })

        if payload.structural_changes:
            changes_text = "\n".join(f"• {c}" for c in payload.structural_changes[:5])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Changes:*\n{changes_text}"},
            })

        if payload.cost_change:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Cost:* {payload.cost_change}"},
            })

        if payload.recommended_actions:
            actions_text = "\n".join(f"• {a}" for a in payload.recommended_actions[:3])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Actions:*\n{actions_text}"},
            })

        blocks.append({"type": "divider"})

        slack_payload: dict[str, Any] = {"blocks": blocks}
        if self.channel:
            slack_payload["channel"] = self.channel

        return self._post(slack_payload)

    def _post(self, data: dict[str, Any]) -> bool:
        try:
            body = json.dumps(data).encode("utf-8")
            req = Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (URLError, OSError) as e:
            logger.error("Slack alert failed: %s", e)
            return False


# ── PagerDuty ──────────────────────────────────────────────────────────


class PagerDutyAlert(AlertChannel):
    """Send alerts to PagerDuty via Events API v2."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key

    @property
    def name(self) -> str:
        return "PagerDuty"

    def send(self, payload: AlertPayload) -> bool:
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        }

        pd_payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"querysense-{payload.query_id}-{payload.timestamp[:10]}",
            "payload": {
                "summary": (
                    f"[QuerySense] {payload.severity.upper()} plan regression "
                    f"on {payload.query_id} (danger: {payload.danger_score}/100)"
                ),
                "source": payload.hostname or "querysense",
                "severity": severity_map.get(payload.severity, "warning"),
                "component": "database",
                "group": "query-performance",
                "class": "plan-regression",
                "custom_details": {
                    "query_id": payload.query_id,
                    "danger_score": payload.danger_score,
                    "structural_changes": payload.structural_changes,
                    "cost_change": payload.cost_change,
                    "plausible_causes": payload.plausible_causes,
                    "recommended_actions": payload.recommended_actions,
                },
            },
        }

        try:
            body = json.dumps(pd_payload).encode("utf-8")
            req = Request(
                self.EVENTS_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status in (200, 202)
        except (URLError, OSError) as e:
            logger.error("PagerDuty alert failed: %s", e)
            return False


# ── Email (SMTP) ───────────────────────────────────────────────────────


class EmailAlert(AlertChannel):
    """Send alerts via SMTP email."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        from_addr: str = "querysense@localhost",
        to_addrs: list[str] | None = None,
        use_tls: bool = True,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    @property
    def name(self) -> str:
        return "Email"

    def send(self, payload: AlertPayload) -> bool:
        if not self.to_addrs:
            logger.warning("Email alert: no recipients configured")
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText

            subject = (
                f"[QuerySense] {payload.severity.upper()} regression: {payload.query_id}"
            )

            body_lines = [
                f"Plan Regression Detected",
                f"========================",
                f"",
                f"Query: {payload.query_id}",
                f"Severity: {payload.severity.upper()}",
                f"Danger Score: {payload.danger_score}/100",
                f"Time: {payload.timestamp}",
                f"Source: {payload.source}",
                f"",
                f"Summary: {payload.summary}",
            ]

            if payload.cost_change:
                body_lines.append(f"Cost: {payload.cost_change}")

            if payload.structural_changes:
                body_lines.append("")
                body_lines.append("Structural Changes:")
                for c in payload.structural_changes:
                    body_lines.append(f"  - {c}")

            if payload.recommended_actions:
                body_lines.append("")
                body_lines.append("Recommended Actions:")
                for a in payload.recommended_actions:
                    body_lines.append(f"  - {a}")

            body_lines.append("")
            body_lines.append("-- QuerySense (https://github.com/JosephAhn23/Query-Sense)")

            msg = MIMEText("\n".join(body_lines))
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                if self.use_tls:
                    server.starttls()
                if self.username:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())

            return True
        except Exception as e:
            logger.error("Email alert failed: %s", e)
            return False


# ── Generic Webhook ───────────────────────────────────────────────


class WebhookAlert(AlertChannel):
    """
    Send alerts to any HTTP endpoint via POST.

    Sends a JSON payload to the configured URL with all alert details.
    Works with Zapier, Make, n8n, custom APIs, or any webhook-compatible service.

    The payload includes:
    - event: "querysense.regression"
    - severity, danger_score, query_id
    - Full alert details (causes, actions, changes)

    Usage:
        alert = WebhookAlert(
            url="https://hooks.example.com/querysense",
            headers={"Authorization": "Bearer xxx"},
        )
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "Webhook"

    def send(self, payload: AlertPayload) -> bool:
        body = {
            "event": "querysense.regression",
            "query_id": payload.query_id,
            "severity": payload.severity,
            "danger_score": payload.danger_score,
            "summary": payload.summary,
            "cost_change": payload.cost_change,
            "structural_changes": payload.structural_changes,
            "plausible_causes": payload.plausible_causes,
            "recommended_actions": payload.recommended_actions,
            "timestamp": payload.timestamp,
            "source": payload.source,
            "hostname": payload.hostname,
        }

        try:
            encoded = json.dumps(body).encode("utf-8")
            req_headers = {"Content-Type": "application/json", **self.headers}
            req = Request(
                self.url,
                data=encoded,
                headers=req_headers,
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (URLError, OSError) as e:
            logger.error("Webhook alert failed (%s): %s", self.url, e)
            return False


# ── Discord ────────────────────────────────────────────────────────────


class DiscordAlert(AlertChannel):
    """Send alerts to Discord via webhook.

    Discord webhooks accept a JSON payload with embeds for rich formatting.
    Supports color-coded severity, structured fields, and action links.

    Usage:
        alert = DiscordAlert(
            webhook_url="https://discord.com/api/webhooks/12345/abcdef"
        )
    """

    def __init__(self, webhook_url: str, username: str = "QuerySense") -> None:
        self.webhook_url = webhook_url
        self.username = username

    @property
    def name(self) -> str:
        return "Discord"

    def send(self, payload: AlertPayload) -> bool:
        severity_colors = {
            "critical": 0xDC2626,  # Red
            "high": 0xF97316,     # Orange
            "medium": 0xEAB308,   # Yellow
            "low": 0x22C55E,      # Green
        }
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "⚪",
        }

        color = severity_colors.get(payload.severity, 0x6B7280)
        emoji = severity_emoji.get(payload.severity, "❓")

        fields: list[dict[str, Any]] = [
            {"name": "Severity", "value": f"{emoji} {payload.severity.upper()}", "inline": True},
            {"name": "Danger Score", "value": f"{payload.danger_score}/100", "inline": True},
            {"name": "Source", "value": payload.source, "inline": True},
        ]

        if payload.cost_change:
            fields.append({"name": "Cost Change", "value": payload.cost_change, "inline": True})

        if payload.structural_changes:
            changes = "\n".join(f"• {c}" for c in payload.structural_changes[:5])
            fields.append({"name": "Structural Changes", "value": changes[:1024], "inline": False})

        if payload.plausible_causes:
            causes = "\n".join(f"• {c}" for c in payload.plausible_causes[:3])
            fields.append({"name": "Possible Causes", "value": causes[:1024], "inline": False})

        if payload.recommended_actions:
            actions = "\n".join(f"• {a}" for a in payload.recommended_actions[:3])
            fields.append({"name": "Recommended Actions", "value": actions[:1024], "inline": False})

        embed = {
            "title": f"Plan Regression: {payload.query_id}",
            "description": payload.summary[:2048],
            "color": color,
            "fields": fields,
            "timestamp": payload.timestamp,
            "footer": {"text": "QuerySense • Free PostgreSQL Query Analyzer"},
        }

        discord_payload = {
            "username": self.username,
            "embeds": [embed],
        }

        try:
            body = json.dumps(discord_payload).encode("utf-8")
            req = Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                # Discord returns 204 No Content on success
                return resp.status in (200, 204)
        except (URLError, OSError) as e:
            logger.error("Discord alert failed: %s", e)
            return False


# ── Microsoft Teams ────────────────────────────────────────────────────


class TeamsAlert(AlertChannel):
    """Send alerts to Microsoft Teams via incoming webhook.

    Uses the Adaptive Card format for rich rendering in Teams.

    Usage:
        alert = TeamsAlert(
            webhook_url="https://outlook.office.com/webhook/..."
        )
    """

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "Teams"

    def send(self, payload: AlertPayload) -> bool:
        severity_colors = {
            "critical": "attention",
            "high": "warning",
            "medium": "accent",
            "low": "good",
        }
        color = severity_colors.get(payload.severity, "default")

        facts = [
            {"title": "Severity", "value": payload.severity.upper()},
            {"title": "Danger Score", "value": f"{payload.danger_score}/100"},
            {"title": "Source", "value": payload.source},
        ]
        if payload.cost_change:
            facts.append({"title": "Cost Change", "value": payload.cost_change})

        sections: list[dict[str, Any]] = [
            {
                "activityTitle": f"Plan Regression: {payload.query_id}",
                "activitySubtitle": payload.timestamp[:19],
                "facts": facts,
                "text": payload.summary[:500],
            }
        ]

        if payload.recommended_actions:
            actions_text = "\n\n".join(f"- {a}" for a in payload.recommended_actions[:3])
            sections.append({
                "activityTitle": "Recommended Actions",
                "text": actions_text,
            })

        teams_payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": {"critical": "DC2626", "high": "F97316", "medium": "EAB308", "low": "22C55E"}.get(
                payload.severity, "6B7280"
            ),
            "summary": f"QuerySense: {payload.severity.upper()} regression on {payload.query_id}",
            "sections": sections,
        }

        try:
            body = json.dumps(teams_payload).encode("utf-8")
            req = Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except (URLError, OSError) as e:
            logger.error("Teams alert failed: %s", e)
            return False


# ── Dispatcher ─────────────────────────────────────────────────────────


class AlertDispatcher:
    """
    Fan-out dispatcher that sends alerts to multiple channels.

    Channels are called sequentially; failures are logged but don't
    stop other channels from being attempted.
    """

    def __init__(self) -> None:
        self._channels: list[AlertChannel] = []

    def add_channel(self, channel: AlertChannel) -> None:
        """Register an alert channel."""
        self._channels.append(channel)
        logger.info("Registered alert channel: %s", channel.name)

    def send(self, payload: AlertPayload) -> dict[str, bool]:
        """
        Send alert to all channels.

        Returns:
            Dict mapping channel name to success boolean.
        """
        results: dict[str, bool] = {}
        for channel in self._channels:
            try:
                ok = channel.send(payload)
                results[channel.name] = ok
                if ok:
                    logger.info("Alert sent via %s for %s", channel.name, payload.query_id)
                else:
                    logger.warning("Alert failed via %s for %s", channel.name, payload.query_id)
            except Exception as e:
                logger.error("Alert channel %s raised: %s", channel.name, e)
                results[channel.name] = False
        return results

    def send_verdict(
        self, verdict: "RegressionVerdict", hostname: str = ""
    ) -> dict[str, bool]:
        """Convenience: send from a RegressionVerdict."""
        payload = AlertPayload.from_verdict(verdict, hostname=hostname)
        return self.send(payload)

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    @property
    def channel_names(self) -> list[str]:
        return [c.name for c in self._channels]
