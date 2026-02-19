"""
Server-rendered web routes for QuerySense Cloud.

Uses Jinja2 templates + HTMX for a modern, low-JS experience.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Cookie, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import querysense as qs
from querysense.cloud.auth import (
    SessionData,
    generate_api_key,
    get_user_by_email,
    hash_password,
    verify_password,
)
from querysense.cloud.database import get_session
from querysense.cloud.models import (
    APIKey,
    Analysis,
    Plan,
    ShareLink,
    User,
    Workspace,
)
from querysense.cloud.services import analyze_plan, compare_plans_service, compute_plan_insights, get_summary_counts
from querysense.cloud.tiers import get_limits, tier_from_string
from querysense.cloud.usage import (
    check_plan_limit,
    get_monthly_api_calls,
    get_today_plan_count,
    get_workspace_tier,
    increment_plan_count,
)

web_router = APIRouter()


# ── Helpers ────────────────────────────────────────────────────────────


def _get_session_manager() -> Any:
    from querysense.cloud.app import get_session_manager

    return get_session_manager()


def _templates() -> Any:
    from querysense.cloud.app import get_templates

    return get_templates()


async def _current_session(
    session_token: str | None = Cookie(default=None, alias="qs_session"),
) -> SessionData | None:
    if not session_token:
        return None
    sm = _get_session_manager()
    return sm.verify_session(session_token)


async def _require_auth(
    session: SessionData | None = Depends(_current_session),
) -> SessionData:
    if session is None:
        raise _redirect_to_login()
    return session


def _redirect_to_login() -> Exception:
    """Return an exception that results in a redirect to /login."""
    from fastapi import HTTPException

    raise HTTPException(status_code=303, headers={"Location": "/login"})


# ── Public pages ───────────────────────────────────────────────────────


@web_router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData | None = Depends(_current_session),
) -> HTMLResponse:
    """Landing page / Dashboard."""
    templates = _templates()

    if session is None:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "user": None,
            "recent_plans": [],
            "stats": {"total_plans": 0, "total_findings": 0, "critical": 0},
        })

    # Authenticated dashboard
    user_result = await db.execute(select(User).where(User.id == session.user_id))
    user = user_result.scalar_one_or_none()

    plans_q = (
        select(Plan)
        .where(Plan.workspace_id == session.workspace_id)
        .options(selectinload(Plan.analyses))
        .order_by(Plan.created_at.desc())
        .limit(10)
    )
    plans_result = await db.execute(plans_q)
    plans = plans_result.scalars().all()

    count_q = select(func.count()).select_from(
        select(Plan.id).where(Plan.workspace_id == session.workspace_id).subquery()
    )
    total_plans = (await db.execute(count_q)).scalar_one()

    recent_plans = []
    total_findings = 0
    total_critical = 0
    for p in plans:
        latest = max(p.analyses, key=lambda a: a.analyzed_at) if p.analyses else None
        tags = json.loads(p.tags) if p.tags else []
        recent_plans.append({
            "id": p.id,
            "title": p.title,
            "created_at": p.created_at.strftime("%Y-%m-%d %H:%M"),
            "findings_count": latest.findings_count if latest else 0,
            "critical_count": latest.critical_count if latest else 0,
            "warning_count": latest.warning_count if latest else 0,
            "tags": tags,
        })
        if latest:
            total_findings += latest.findings_count
            total_critical += latest.critical_count

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "recent_plans": recent_plans,
        "stats": {
            "total_plans": total_plans,
            "total_findings": total_findings,
            "critical": total_critical,
        },
    })


@web_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    templates = _templates()
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@web_router.post("/login", response_model=None)
async def login_submit(
    request: Request,
    db: AsyncSession = Depends(get_session),
    email: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse | HTMLResponse:
    templates = _templates()

    user = await get_user_by_email(db, email)
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password",
        })

    # Get first workspace
    ws_result = await db.execute(
        select(Workspace).where(Workspace.owner_id == user.id).limit(1)
    )
    workspace = ws_result.scalar_one_or_none()
    if workspace is None:
        workspace = Workspace(name="Default", owner_id=user.id)
        db.add(workspace)
        await db.flush()

    sm = _get_session_manager()
    token = sm.create_session(user.id, workspace.id)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("qs_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
    return response


@web_router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    templates = _templates()
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@web_router.post("/register", response_model=None)
async def register_submit(
    request: Request,
    db: AsyncSession = Depends(get_session),
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(...),
) -> RedirectResponse | HTMLResponse:
    templates = _templates()

    existing = await get_user_by_email(db, email)
    if existing is not None:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "An account with this email already exists",
        })

    if len(password) < 8:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Password must be at least 8 characters",
        })

    user = User(
        email=email,
        password_hash=hash_password(password),
        display_name=display_name,
    )
    db.add(user)
    await db.flush()

    workspace = Workspace(name=f"{display_name}'s Workspace", owner_id=user.id)
    db.add(workspace)
    await db.flush()

    sm = _get_session_manager()
    token = sm.create_session(user.id, workspace.id)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie("qs_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
    return response


@web_router.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("qs_session")
    return response


# ── Authenticated pages ────────────────────────────────────────────────


@web_router.get("/plans", response_class=HTMLResponse)
async def plans_list(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
) -> HTMLResponse:
    """Plan library page."""
    templates = _templates()
    per_page = 20
    offset = (page - 1) * per_page

    query = select(Plan).where(Plan.workspace_id == session.workspace_id)
    if search:
        query = query.where(Plan.title.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    query = (
        query.options(selectinload(Plan.analyses))
        .order_by(Plan.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    rows = (await db.execute(query)).scalars().all()

    plans = []
    for p in rows:
        latest = max(p.analyses, key=lambda a: a.analyzed_at) if p.analyses else None
        tags = json.loads(p.tags) if p.tags else []
        plans.append({
            "id": p.id,
            "title": p.title,
            "created_at": p.created_at.strftime("%Y-%m-%d %H:%M"),
            "findings_count": latest.findings_count if latest else 0,
            "critical_count": latest.critical_count if latest else 0,
            "warning_count": latest.warning_count if latest else 0,
            "info_count": latest.info_count if latest else 0,
            "tags": tags,
        })

    total_pages = max(1, (total + per_page - 1) // per_page)

    return templates.TemplateResponse("plans/list.html", {
        "request": request,
        "plans": plans,
        "search": search or "",
        "page": page,
        "total_pages": total_pages,
        "total": total,
    })


@web_router.get("/plans/upload", response_class=HTMLResponse)
async def upload_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    templates = _templates()
    return templates.TemplateResponse("plans/upload.html", {
        "request": request,
        "error": None,
    })


@web_router.post("/plans/upload", response_model=None)
async def upload_submit(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
    title: str = Form(default="Untitled Plan"),
    plan_json: str = Form(...),
    sql_text: str = Form(default=""),
    tags: str = Form(default=""),
) -> RedirectResponse | HTMLResponse:
    """Handle plan upload and redirect to detail page."""
    templates = _templates()

    # Enforce daily plan limit
    try:
        await check_plan_limit(db, session.workspace_id)
    except Exception:
        return templates.TemplateResponse("plans/upload.html", {
            "request": request,
            "error": "Daily plan limit reached. Upgrade your plan at /pricing for unlimited analysis.",
        })

    # Parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    # Analyze
    try:
        result, result_json = analyze_plan(plan_json, sql_text or None)
    except Exception as exc:
        return templates.TemplateResponse("plans/upload.html", {
            "request": request,
            "error": f"Failed to analyze plan: {exc}",
        })

    counts = get_summary_counts(result_json)

    # Store plan
    plan = Plan(
        workspace_id=session.workspace_id,
        title=title,
        plan_json=plan_json,
        sql_text=sql_text or None,
        tags=json.dumps(tag_list) if tag_list else None,
        uploaded_by=session.user_id,
    )
    db.add(plan)
    await db.flush()

    # Store analysis
    analysis = Analysis(
        plan_id=plan.id,
        result_json=result_json,
        evidence_level=result.evidence_level.value,
        findings_count=counts["findings_count"],
        critical_count=counts["critical_count"],
        warning_count=counts["warning_count"],
        info_count=counts["info_count"],
        querysense_version=qs.__version__,
    )
    db.add(analysis)
    await db.flush()

    # Track usage
    await increment_plan_count(db, session.workspace_id)

    return RedirectResponse(url=f"/plans/{plan.id}", status_code=303)


@web_router.get("/plans/{plan_id}", response_class=HTMLResponse)
async def plan_detail(
    request: Request,
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Plan analysis detail page."""
    templates = _templates()

    result = await db.execute(
        select(Plan)
        .where(Plan.id == plan_id, Plan.workspace_id == session.workspace_id)
        .options(selectinload(Plan.analyses), selectinload(Plan.share_links))
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        return templates.TemplateResponse("plans/detail.html", {
            "request": request,
            "plan": None,
            "analysis": None,
            "share_links": [],
            "error": "Plan not found",
        })

    latest = max(plan.analyses, key=lambda a: a.analyzed_at) if plan.analyses else None
    analysis_data = json.loads(latest.result_json) if latest else None
    tags = json.loads(plan.tags) if plan.tags else []

    share_links = [
        {
            "token": sl.token,
            "created_at": sl.created_at.strftime("%Y-%m-%d %H:%M"),
            "expires_at": sl.expires_at.strftime("%Y-%m-%d") if sl.expires_at else "Never",
        }
        for sl in plan.share_links
    ]

    # Compute deep plan insights for UI visualization
    plan_insights = compute_plan_insights(plan.plan_json)

    # Generate human-friendly ELI5 explanations for each finding
    eli5_explanations: dict[str, dict[str, str]] = {}
    if analysis_data and analysis_data.get("findings"):
        try:
            from querysense.explainer import HumanExplainer
            explainer = HumanExplainer()
            for i, finding in enumerate(analysis_data["findings"]):
                # Create a lightweight object for the explainer
                class _F:
                    pass
                f = _F()
                f.rule_id = finding.get("rule_id", "")
                f.suggestion = finding.get("suggestion", "")
                f.metrics = finding.get("metrics", {})
                f.impact_score = finding.get("impact_score", 0)
                f.context = None
                eli5_explanations[str(i)] = explainer.translate_to_dict(f)
        except Exception:
            pass  # Graceful degradation if explainer fails

    return templates.TemplateResponse("plans/detail.html", {
        "request": request,
        "plan": {
            "id": plan.id,
            "title": plan.title,
            "plan_json": plan.plan_json,
            "sql_text": plan.sql_text,
            "tags": tags,
            "created_at": plan.created_at.strftime("%Y-%m-%d %H:%M"),
        },
        "analysis": analysis_data,
        "insights": plan_insights,
        "eli5": eli5_explanations,
        "share_links": share_links,
        "error": None,
    })


@web_router.post("/plans/{plan_id}/share")
async def create_share_web(
    plan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> RedirectResponse:
    """Create a share link and redirect back to plan detail."""
    # Verify ownership
    result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == session.workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        return RedirectResponse(url="/plans", status_code=303)

    token = secrets.token_urlsafe(24)
    link = ShareLink(
        plan_id=plan_id,
        token=token,
        created_by=session.user_id,
    )
    db.add(link)
    await db.flush()

    return RedirectResponse(url=f"/plans/{plan_id}", status_code=303)


@web_router.get("/plans/{plan_id}/compare", response_model=None)
async def compare_page(
    request: Request,
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
    other_id: str | None = Query(default=None),
) -> HTMLResponse | RedirectResponse:
    """Before/after comparison page."""
    templates = _templates()

    # Get current plan
    result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == session.workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        return RedirectResponse(url="/plans", status_code=303)

    # Get all other plans for the dropdown
    other_plans_q = (
        select(Plan)
        .where(Plan.workspace_id == session.workspace_id, Plan.id != plan_id)
        .order_by(Plan.created_at.desc())
        .limit(50)
    )
    other_plans_result = await db.execute(other_plans_q)
    other_plans = [
        {"id": p.id, "title": p.title, "created_at": p.created_at.strftime("%Y-%m-%d %H:%M")}
        for p in other_plans_result.scalars().all()
    ]

    comparison = None
    other_plan_title = None
    error = None

    if other_id:
        other_result = await db.execute(
            select(Plan).where(Plan.id == other_id, Plan.workspace_id == session.workspace_id)
        )
        other_plan = other_result.scalar_one_or_none()
        if other_plan is None:
            error = "Comparison plan not found"
        else:
            other_plan_title = other_plan.title
            try:
                comparison = compare_plans_service(
                    plan.plan_json, other_plan.plan_json,
                    plan.sql_text, other_plan.sql_text,
                )
            except Exception as exc:
                error = f"Comparison failed: {exc}"

    return templates.TemplateResponse("plans/compare.html", {
        "request": request,
        "plan": {"id": plan.id, "title": plan.title},
        "other_plans": other_plans,
        "selected_other_id": other_id,
        "other_plan_title": other_plan_title,
        "comparison": comparison,
        "error": error,
    })


# ── Share page (public) ───────────────────────────────────────────────


@web_router.get("/share/{token}", response_class=HTMLResponse)
async def share_page(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Public share page — no auth required."""
    templates = _templates()

    result = await db.execute(
        select(ShareLink)
        .where(ShareLink.token == token)
        .options(selectinload(ShareLink.plan).selectinload(Plan.analyses))
    )
    link = result.scalar_one_or_none()

    if link is None:
        return templates.TemplateResponse("share/view.html", {
            "request": request,
            "error": "Share link not found",
            "plan": None,
            "analysis": None,
        })

    if link.expires_at is not None and datetime.now(timezone.utc) > link.expires_at:
        return templates.TemplateResponse("share/view.html", {
            "request": request,
            "error": "This share link has expired",
            "plan": None,
            "analysis": None,
        })

    plan = link.plan
    latest = max(plan.analyses, key=lambda a: a.analyzed_at) if plan.analyses else None
    analysis_data = json.loads(latest.result_json) if latest else None

    return templates.TemplateResponse("share/view.html", {
        "request": request,
        "error": None,
        "plan": {
            "title": plan.title,
            "sql_text": plan.sql_text,
            "created_at": plan.created_at.strftime("%Y-%m-%d %H:%M"),
        },
        "analysis": analysis_data,
    })


# ── Settings pages ────────────────────────────────────────────────────


@web_router.get("/settings/api-keys", response_class=HTMLResponse)
async def api_keys_page(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    templates = _templates()

    result = await db.execute(
        select(APIKey)
        .where(APIKey.workspace_id == session.workspace_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()

    key_list = [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "is_active": k.is_active,
            "created_at": k.created_at.strftime("%Y-%m-%d %H:%M"),
            "last_used_at": k.last_used_at.strftime("%Y-%m-%d %H:%M") if k.last_used_at else "Never",
        }
        for k in keys
    ]

    return templates.TemplateResponse("settings/api_keys.html", {
        "request": request,
        "keys": key_list,
        "new_key": None,
    })


@web_router.post("/settings/api-keys")
async def create_api_key_web(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
    name: str = Form(...),
) -> HTMLResponse:
    templates = _templates()

    raw_key, key_hash, prefix = generate_api_key()

    api_key = APIKey(
        workspace_id=session.workspace_id,
        key_hash=key_hash,
        prefix=prefix,
        name=name,
        created_by=session.user_id,
    )
    db.add(api_key)
    await db.flush()

    # Re-fetch all keys for the page
    result = await db.execute(
        select(APIKey)
        .where(APIKey.workspace_id == session.workspace_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()

    key_list = [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "is_active": k.is_active,
            "created_at": k.created_at.strftime("%Y-%m-%d %H:%M"),
            "last_used_at": k.last_used_at.strftime("%Y-%m-%d %H:%M") if k.last_used_at else "Never",
        }
        for k in keys
    ]

    return templates.TemplateResponse("settings/api_keys.html", {
        "request": request,
        "keys": key_list,
        "new_key": raw_key,
    })


@web_router.post("/settings/api-keys/{key_id}/revoke")
async def revoke_api_key_web(
    key_id: str,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> RedirectResponse:
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.workspace_id == session.workspace_id)
    )
    api_key = result.scalar_one_or_none()
    if api_key is not None:
        api_key.is_active = False
        db.add(api_key)

    return RedirectResponse(url="/settings/api-keys", status_code=303)


# ── Watch page ─────────────────────────────────────────────────────────


@web_router.get("/watch", response_class=HTMLResponse)
async def watch_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Plan regression watch dashboard."""
    templates = _templates()
    return templates.TemplateResponse("watch.html", {
        "request": request,
        "watch_stats": {
            "queries_monitored": 0,
            "regressions_24h": 0,
            "alert_channels": 0,
        },
    })


# ── Regressions page ──────────────────────────────────────────────────


@web_router.get("/regressions", response_class=HTMLResponse)
async def regressions_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Plan regressions dashboard."""
    templates = _templates()
    return templates.TemplateResponse("regressions.html", {
        "request": request,
        "regression_stats": {
            "active": 0,
            "resolved": 0,
            "locked": 0,
            "avg_danger": 0,
        },
    })


# ── Upgrade page ───────────────────────────────────────────────────────


@web_router.get("/upgrade", response_class=HTMLResponse)
async def upgrade_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Upgrade validation dashboard."""
    templates = _templates()

    from querysense.upgrade import VERSION_KNOWLEDGE_BASE

    version_changes = []
    seen_pairs: set[tuple[int, int]] = set()
    for change in VERSION_KNOWLEDGE_BASE:
        pair = (change.from_version, change.to_version)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            version_changes.append({
                "from": change.from_version,
                "to": change.to_version,
                "changes": [
                    {
                        "title": c.title,
                        "description": c.description,
                        "risk_level": c.risk_level,
                    }
                    for c in VERSION_KNOWLEDGE_BASE
                    if c.from_version == pair[0] and c.to_version == pair[1]
                ],
            })

    return templates.TemplateResponse("upgrade.html", {
        "request": request,
        "version_changes": version_changes,
    })


# ── Compliance page ───────────────────────────────────────────────────


@web_router.get("/compliance", response_class=HTMLResponse)
async def compliance_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Compliance enforcement dashboard."""
    templates = _templates()
    return templates.TemplateResponse("compliance.html", {
        "request": request,
    })


@web_router.get("/causal", response_class=HTMLResponse)
async def causal_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Causal root-cause analysis page."""
    templates = _templates()
    return templates.TemplateResponse("causal.html", {
        "request": request,
    })


# ── Rewrite page ──────────────────────────────────────────────────


@web_router.get("/rewrite", response_class=HTMLResponse)
async def rewrite_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """SQL rewrite page — automated query optimization."""
    templates = _templates()
    return templates.TemplateResponse("rewrite.html", {
        "request": request,
        "sql": "",
        "plan_json": "",
        "result": None,
    })


@web_router.post("/rewrite", response_class=HTMLResponse)
async def rewrite_submit(
    request: Request,
    sql: str = Form(default=""),
    plan_json: str = Form(default=""),
) -> HTMLResponse:
    """HTMX endpoint: rewrite SQL and return result fragment."""
    templates = _templates()

    if not sql.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 dark:bg-yellow-900/20 '
            'border border-yellow-200 dark:border-yellow-800 p-4">'
            '<p class="text-sm text-yellow-700 dark:text-yellow-400">'
            "Please enter a SQL query to optimize.</p></div>"
        )

    from querysense.rewriter import rewrite_query

    # If EXPLAIN plan provided, analyze it first for finding-guided rewrites
    findings = None
    if plan_json.strip():
        try:
            result_obj, _ = analyze_plan(plan_json, sql)
            findings = list(result_obj.findings)
        except Exception:
            pass  # Proceed without findings

    rewrite_result = rewrite_query(sql, findings)

    return templates.TemplateResponse("partials/rewrite_result.html", {
        "request": request,
        "result": rewrite_result,
    })


# ── SVG Plan Visualization ────────────────────────────────────────


@web_router.get("/api/plans/{plan_id}/svg", response_class=HTMLResponse)
async def plan_svg(
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Return SVG visualization of a query plan."""
    from querysense.viz.svg_plan import render_plan_svg

    result = await db.execute(
        select(Plan)
        .where(Plan.id == plan_id, Plan.workspace_id == session.workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        return HTMLResponse(
            '<svg width="300" height="60">'
            '<text x="10" y="30" font-size="14" fill="#ef4444">Plan not found</text>'
            '</svg>',
            status_code=404,
        )

    svg = render_plan_svg(plan.plan_json)
    return HTMLResponse(svg, media_type="image/svg+xml")


# ── Migration Safety & Rollback (Web UI) ─────────────────────────


@web_router.get("/migrations", response_class=HTMLResponse)
async def migrations_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Migration safety checker and rollback generator page."""
    templates = _templates()
    return templates.TemplateResponse("migrations.html", {
        "request": request,
        "active_page": "migrations",
    })


@web_router.post("/migrations/check", response_class=HTMLResponse)
async def migrations_check_htmx(
    request: Request,
    sql: str = Form(default=""),
    generate_rollback: bool = Form(default=False),
) -> HTMLResponse:
    """HTMX endpoint: check migration SQL for safety risks."""
    templates = _templates()

    if not sql.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 dark:bg-yellow-900/20 '
            'border border-yellow-200 dark:border-yellow-800 p-4">'
            '<p class="text-sm text-yellow-700 dark:text-yellow-400">'
            "Please enter migration SQL to check.</p></div>"
        )

    from querysense.migration_safety import check_and_report
    from querysense.rollback import generate_smart_rollback

    report = check_and_report(sql)
    rollback_plan = None
    if generate_rollback:
        rollback_plan = generate_smart_rollback(sql)

    return templates.TemplateResponse("partials/migration_result.html", {
        "request": request,
        "report": report,
        "rollback_plan": rollback_plan,
    })


# ── Schema Drift Detection (Web UI) ─────────────────────────────


@web_router.get("/schema/drift", response_class=HTMLResponse)
async def schema_drift_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Schema drift detection and comparison page."""
    templates = _templates()
    return templates.TemplateResponse("schema_drift.html", {
        "request": request,
        "active_page": "schema_drift",
    })


@web_router.post("/schema/compare", response_class=HTMLResponse)
async def schema_compare_htmx(
    request: Request,
    source_sql: str = Form(default=""),
    target_sql: str = Form(default=""),
    generate_fix: bool = Form(default=False),
) -> HTMLResponse:
    """HTMX endpoint: compare two schema DDLs and detect drift."""
    import re

    templates = _templates()

    if not source_sql.strip() or not target_sql.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 dark:bg-yellow-900/20 '
            'border border-yellow-200 dark:border-yellow-800 p-4">'
            '<p class="text-sm text-yellow-700 dark:text-yellow-400">'
            "Please paste DDL in both source and target fields.</p></div>"
        )

    def _parse_objects(ddl: str) -> dict:
        """Simple DDL parser that extracts tables, columns, indexes, constraints."""
        objects: dict = {"tables": {}, "indexes": {}, "constraints": {}}
        ddl_upper = ddl.upper()
        ddl_clean = ddl.strip()

        # Parse CREATE TABLE
        table_pattern = re.compile(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.+?)\)\s*;",
            re.IGNORECASE | re.DOTALL,
        )
        for m in table_pattern.finditer(ddl_clean):
            tbl_name = m.group(1).lower()
            cols_text = m.group(2)
            columns: dict = {}
            for line in cols_text.split(","):
                line = line.strip()
                if not line:
                    continue
                # Skip constraints
                if re.match(r"^(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT)", line, re.IGNORECASE):
                    cname = re.search(r"CONSTRAINT\s+(\w+)", line, re.IGNORECASE)
                    if cname:
                        objects["constraints"][cname.group(1).lower()] = {
                            "table": tbl_name, "definition": line.strip()
                        }
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    col_name = parts[0].lower()
                    col_type = " ".join(parts[1:]).lower()
                    # Remove trailing comma artifacts
                    col_type = col_type.rstrip(",").strip()
                    columns[col_name] = col_type
            objects["tables"][tbl_name] = columns

        # Parse CREATE INDEX
        idx_pattern = re.compile(
            r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+ON\s+(\w+)",
            re.IGNORECASE,
        )
        for m in idx_pattern.finditer(ddl_clean):
            idx_name = m.group(1).lower()
            on_table = m.group(2).lower()
            objects["indexes"][idx_name] = {"table": on_table}

        return objects

    source_objs = _parse_objects(source_sql)
    target_objs = _parse_objects(target_sql)

    drift_items: list[dict] = []

    # Compare tables and columns
    for tbl_name, src_cols in source_objs["tables"].items():
        if tbl_name not in target_objs["tables"]:
            drift_items.append({
                "drift_type": "missing",
                "object_type": "table",
                "name": tbl_name,
                "impact": "Entire table missing in target",
                "description": f"Table '{tbl_name}' exists in source but not in target.",
            })
            continue

        tgt_cols = target_objs["tables"][tbl_name]

        # Columns missing in target
        for col, ctype in src_cols.items():
            if col not in tgt_cols:
                drift_items.append({
                    "drift_type": "missing",
                    "object_type": "column",
                    "name": f"{tbl_name}.{col}",
                    "impact": "Column missing in target",
                    "description": f"Column '{col}' ({ctype}) in '{tbl_name}' is missing from target.",
                })
            elif tgt_cols[col] != ctype:
                drift_items.append({
                    "drift_type": "changed",
                    "object_type": "column",
                    "name": f"{tbl_name}.{col}",
                    "from_value": ctype,
                    "to_value": tgt_cols[col],
                    "impact": "Type changed",
                    "description": f"Column type differs for '{tbl_name}.{col}'.",
                })

        # Columns extra in target
        for col, ctype in tgt_cols.items():
            if col not in src_cols:
                drift_items.append({
                    "drift_type": "extra",
                    "object_type": "column",
                    "name": f"{tbl_name}.{col}",
                    "impact": "Extra column in target",
                    "description": f"Column '{col}' ({ctype}) in '{tbl_name}' exists only in target. Likely a dev leftover.",
                })

    # Tables extra in target
    for tbl_name in target_objs["tables"]:
        if tbl_name not in source_objs["tables"]:
            drift_items.append({
                "drift_type": "extra",
                "object_type": "table",
                "name": tbl_name,
                "impact": "Extra table in target",
                "description": f"Table '{tbl_name}' exists in target but not in source.",
            })

    # Compare indexes
    for idx_name, idx_data in source_objs["indexes"].items():
        if idx_name not in target_objs["indexes"]:
            drift_items.append({
                "drift_type": "missing",
                "object_type": "index",
                "name": idx_name,
                "impact": f"Missing index on {idx_data['table']}",
                "description": f"Index '{idx_name}' on '{idx_data['table']}' exists in source but not in target. Queries may be slower.",
            })
    for idx_name, idx_data in target_objs["indexes"].items():
        if idx_name not in source_objs["indexes"]:
            drift_items.append({
                "drift_type": "extra",
                "object_type": "index",
                "name": idx_name,
                "impact": f"Extra index on {idx_data['table']}",
                "description": f"Index '{idx_name}' on '{idx_data['table']}' exists only in target.",
            })

    # Generate fix SQL
    fix_sql = ""
    if generate_fix and drift_items:
        fix_lines: list[str] = ["-- Auto-generated fix SQL", "-- Review carefully before applying\n"]
        for item in drift_items:
            if item["drift_type"] == "missing" and item["object_type"] == "index":
                # Find original CREATE INDEX in source_sql
                pat = re.compile(
                    rf"(CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(item['name'])}\s+.+?;)",
                    re.IGNORECASE | re.DOTALL,
                )
                m = pat.search(source_sql)
                if m:
                    fix_lines.append(f"-- Add missing index: {item['name']}")
                    fix_lines.append(m.group(1))
                    fix_lines.append("")
            elif item["drift_type"] == "extra" and item["object_type"] == "column":
                parts = item["name"].split(".", 1)
                if len(parts) == 2:
                    fix_lines.append(f"-- Remove extra column: {item['name']}")
                    fix_lines.append(f"ALTER TABLE {parts[0]} DROP COLUMN IF EXISTS {parts[1]};")
                    fix_lines.append("")
            elif item["drift_type"] == "extra" and item["object_type"] == "index":
                fix_lines.append(f"-- Remove extra index: {item['name']}")
                fix_lines.append(f"DROP INDEX IF EXISTS {item['name']};")
                fix_lines.append("")
            elif item["drift_type"] == "missing" and item["object_type"] == "column":
                parts = item["name"].split(".", 1)
                if len(parts) == 2 and parts[0] in source_objs["tables"]:
                    col_type = source_objs["tables"][parts[0]].get(parts[1], "TEXT")
                    fix_lines.append(f"-- Add missing column: {item['name']}")
                    fix_lines.append(f"ALTER TABLE {parts[0]} ADD COLUMN {parts[1]} {col_type.upper()};")
                    fix_lines.append("")

        fix_sql = "\n".join(fix_lines) if len(fix_lines) > 2 else ""

    return templates.TemplateResponse("partials/schema_drift_result.html", {
        "request": request,
        "drift_items": drift_items,
        "fix_sql": fix_sql,
    })


# ── HTMX API endpoints ────────────────────────────────────────────


@web_router.post("/api/compliance/check", response_class=HTMLResponse)
async def compliance_check_htmx(
    request: Request,
    sql: str = Form(default=""),
    regulations: list[str] = Form(default=[]),
) -> HTMLResponse:
    """HTMX endpoint: run compliance check and return HTML fragment."""
    templates = _templates()

    if not sql.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 border border-yellow-200 p-4 mt-4">'
            '<p class="text-sm text-yellow-700">Please enter a SQL query to check.</p>'
            "</div>"
        )

    if not regulations:
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 border border-yellow-200 p-4 mt-4">'
            '<p class="text-sm text-yellow-700">Please select at least one regulation.</p>'
            "</div>"
        )

    try:
        from querysense.compliance import (
            ColumnClassification,
            ComplianceEngine,
            DataClassification,
            TableClassification,
        )

        # Create engine with default table classifications for demo
        default_tables: dict[str, TableClassification] = {
            "patients": TableClassification(
                name="patients",
                classification=DataClassification.RESTRICTED,
                regulations=("HIPAA",),
                columns={
                    "diagnosis": ColumnClassification(name="diagnosis", pii=True),
                    "ssn": ColumnClassification(name="ssn", pii=True),
                    "patient_name": ColumnClassification(name="patient_name", pii=True),
                },
            ),
            "payments": TableClassification(
                name="payments",
                classification=DataClassification.RESTRICTED,
                regulations=("PCI-DSS", "SOX"),
                columns={
                    "card_number": ColumnClassification(name="card_number", pii=True),
                    "cardholder_name": ColumnClassification(name="cardholder_name", pii=True),
                },
            ),
            "users": TableClassification(
                name="users",
                classification=DataClassification.CONFIDENTIAL,
                regulations=("GDPR",),
                columns={
                    "email": ColumnClassification(name="email", pii=True),
                    "phone": ColumnClassification(name="phone", pii=True),
                    "first_name": ColumnClassification(name="first_name", pii=True),
                    "last_name": ColumnClassification(name="last_name", pii=True),
                },
            ),
        }

        engine = ComplianceEngine(
            tables=default_tables,
            regulations=list(regulations),
        )
        violations = engine.check_query(sql.strip())

        # Build response HTML
        if not violations:
            return HTMLResponse(
                '<div class="rounded-xl bg-green-50 border border-green-200 p-5 mt-4 flex items-center">'
                '<svg class="w-6 h-6 text-green-500 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
                '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
                '<div>'
                '<p class="text-sm font-semibold text-green-800">No violations found</p>'
                f'<p class="text-xs text-green-600">Checked against: {", ".join(regulations)}</p>'
                "</div></div>"
            )

        # Build violations HTML
        html = '<div class="mt-4 space-y-3">'
        html += (
            f'<div class="flex items-center justify-between mb-2">'
            f'<p class="text-sm font-semibold text-gray-900">{len(violations)} violation(s) found</p>'
            f'<span class="text-xs text-gray-400">Regulations: {", ".join(regulations)}</span>'
            f"</div>"
        )

        for v in violations:
            severity_class = "badge-critical" if v.severity == "critical" else (
                "badge-warning" if v.severity == "warning" else "badge-info"
            )
            border_class = "border-red-500" if v.severity == "critical" else (
                "border-yellow-500" if v.severity == "warning" else "border-blue-500"
            )
            bg_class = "bg-red-50" if v.severity == "critical" else (
                "bg-yellow-50" if v.severity == "warning" else "bg-blue-50"
            )

            html += (
                f'<div class="rounded-lg border {border_class} border-l-4 {bg_class} p-4">'
                f'<div class="flex items-center justify-between">'
                f'<span class="{severity_class} inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold">{v.severity.upper()}</span>'
                f'<span class="text-xs text-gray-400">{v.regulation} &middot; {v.violation_type.value}</span>'
                f"</div>"
                f'<p class="text-sm text-gray-900 mt-2 font-medium">{v.message}</p>'
            )
            if v.remediation:
                html += f'<p class="text-xs text-gray-500 mt-1">{v.remediation}</p>'
            html += "</div>"

        html += "</div>"
        return HTMLResponse(html)

    except ImportError:
        return HTMLResponse(
            '<div class="rounded-lg bg-red-50 border border-red-200 p-4 mt-4">'
            '<p class="text-sm text-red-700">Compliance module not available.</p>'
            "</div>"
        )
    except Exception as exc:
        return HTMLResponse(
            f'<div class="rounded-lg bg-red-50 border border-red-200 p-4 mt-4">'
            f'<p class="text-sm text-red-700">Error: {exc}</p>'
            f"</div>"
        )


@web_router.post("/api/ir/causal", response_class=HTMLResponse)
async def causal_analysis_htmx(
    request: Request,
    plan_json: str = Form(default=""),
    engine: str = Form(default=""),
) -> HTMLResponse:
    """HTMX endpoint: run causal root-cause analysis and return HTML fragment."""
    if not plan_json.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 border border-yellow-200 p-4 mt-4">'
            '<p class="text-sm text-yellow-700">Please paste an EXPLAIN JSON plan.</p>'
            "</div>"
        )

    try:
        import json as _json
        raw_plan = _json.loads(plan_json.strip())
    except _json.JSONDecodeError as exc:
        return HTMLResponse(
            f'<div class="rounded-lg bg-red-50 border border-red-200 p-4 mt-4">'
            f'<p class="text-sm text-red-700">Invalid JSON: {exc}</p>'
            f"</div>"
        )

    try:
        from querysense.ir.unified import UnifiedAnalyzer

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        report = analyzer.analyze_raw(
            raw_plan, engine=engine or None, sql=None
        )

        ir_plan = report.ir_plan
        causal = report.causal_report

        # Build capabilities badges
        cap_html = "".join(
            f'<span class="inline-flex items-center px-2 py-0.5 rounded text-xs '
            f'font-medium bg-blue-100 text-blue-800 mr-1 mb-1">{c}</span>'
            for c in sorted(report.capabilities)[:12]
        )

        # Build summary card
        html = (
            f'<div class="mt-4 space-y-4">'
            f'<div class="rounded-xl bg-gray-50 border border-gray-200 p-5">'
            f'<div class="flex items-center justify-between mb-3">'
            f'<h3 class="text-sm font-semibold text-gray-900">IR Translation</h3>'
            f'<span class="text-xs text-gray-500">{ir_plan.engine}</span>'
            f"</div>"
            f'<div class="grid grid-cols-3 gap-4 text-center">'
            f'<div><p class="text-2xl font-bold text-gray-900">{ir_plan.node_count}</p>'
            f'<p class="text-xs text-gray-500">Nodes</p></div>'
            f'<div><p class="text-2xl font-bold text-gray-900">{len(report.capabilities)}</p>'
            f'<p class="text-xs text-gray-500">Capabilities</p></div>'
            f'<div><p class="text-2xl font-bold text-gray-900">'
            f'{report.plan_fingerprint.get("structure", "N/A")[:8]}</p>'
            f'<p class="text-xs text-gray-500">Structure Hash</p></div>'
            f"</div>"
            f'<div class="mt-3 flex flex-wrap">{cap_html}</div>'
            f"</div>"
        )

        # Build causal analysis results
        if not causal.has_findings:
            html += (
                '<div class="rounded-xl bg-green-50 border border-green-200 p-5">'
                '<div class="flex items-center">'
                '<svg class="w-5 h-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
                '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" '
                'd="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
                '<p class="text-sm font-semibold text-green-800">'
                "No root-cause hypotheses matched the evidence.</p>"
                "</div></div>"
            )
        else:
            html += '<div class="space-y-3">'
            html += (
                f'<h3 class="text-sm font-semibold text-gray-900">'
                f'{len(causal.ranked)} Root Cause(s) Identified</h3>'
            )

            for rh in causal.ranked[:5]:
                conf = rh.confidence
                if conf >= 0.7:
                    bar_color = "bg-red-500"
                    badge_class = "bg-red-100 text-red-800"
                elif conf >= 0.4:
                    bar_color = "bg-yellow-500"
                    badge_class = "bg-yellow-100 text-yellow-800"
                else:
                    bar_color = "bg-blue-500"
                    badge_class = "bg-blue-100 text-blue-800"

                html += (
                    f'<div class="rounded-lg border border-gray-200 p-4">'
                    f'<div class="flex items-center justify-between mb-2">'
                    f'<div class="flex items-center">'
                    f'<span class="text-lg font-bold text-gray-400 mr-3">#{rh.rank}</span>'
                    f'<span class="text-sm font-semibold text-gray-900">'
                    f"{rh.hypothesis.title}</span></div>"
                    f'<span class="inline-flex items-center px-2.5 py-0.5 rounded-full '
                    f'text-xs font-bold {badge_class}">{conf:.0%}</span>'
                    f"</div>"
                    f'<div class="w-full bg-gray-200 rounded-full h-1.5 mb-2">'
                    f'<div class="{bar_color} h-1.5 rounded-full" '
                    f'style="width: {conf*100:.0f}%"></div></div>'
                    f'<p class="text-xs text-gray-600">{rh.explanation[:120]}</p>'
                )
                if rh.result.remediation:
                    html += (
                        f'<div class="mt-2 bg-green-50 rounded p-2">'
                        f'<p class="text-xs text-green-800">'
                        f'<strong>Fix:</strong> {rh.result.remediation[:150]}</p></div>'
                    )
                html += "</div>"

            html += "</div>"

        if causal.skipped:
            html += (
                f'<p class="text-xs text-gray-400 mt-2">'
                f'{len(causal.skipped)} hypotheses skipped (insufficient evidence)</p>'
            )

        html += "</div>"
        return HTMLResponse(html)

    except Exception as exc:
        return HTMLResponse(
            f'<div class="rounded-lg bg-red-50 border border-red-200 p-4 mt-4">'
            f'<p class="text-sm text-red-700">Analysis error: {exc}</p>'
            f"</div>"
        )


@web_router.get("/api/watch/feed", response_class=HTMLResponse)
async def watch_feed_htmx(request: Request) -> HTMLResponse:
    """HTMX endpoint: return latest watch feed items."""
    from datetime import datetime

    now = datetime.now().strftime("%H:%M:%S")
    html = (
        f'<div class="px-4 py-3 slide-in">'
        f'<div class="flex items-start justify-between">'
        f'<div class="flex-1">'
        f'<p class="text-xs text-gray-400">{now}</p>'
        f'<p class="text-sm text-gray-700 mt-0.5">Heartbeat - monitoring active</p>'
        f"</div>"
        f'<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">OK</span>'
        f"</div></div>"
        f'<div class="px-4 py-3">'
        f'<div class="flex items-start justify-between">'
        f'<div class="flex-1">'
        f'<p class="text-xs text-gray-400">Awaiting data...</p>'
        f'<p class="text-sm text-gray-500 mt-0.5">Connect a database to start watching</p>'
        f"</div></div></div>"
    )
    return HTMLResponse(html)


# ── Pricing page (public) ─────────────────────────────────────────────


@web_router.get("/pricing", response_class=HTMLResponse)
async def pricing_page(request: Request) -> HTMLResponse:
    """Public pricing page showing all tiers."""
    templates = _templates()
    return templates.TemplateResponse("pricing.html", {"request": request})


# ── Billing & Usage page ──────────────────────────────────────────────


@web_router.get("/settings/billing", response_class=HTMLResponse)
async def billing_page(
    request: Request,
    db: AsyncSession = Depends(get_session),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Billing and usage page showing current tier, limits, and usage stats."""
    templates = _templates()

    tier, limits = await get_workspace_tier(db, session.workspace_id)

    # Get usage stats
    plans_today = await get_today_plan_count(db, session.workspace_id)
    api_calls_month = await get_monthly_api_calls(db, session.workspace_id)

    # Count stored plans
    stored_count_q = select(func.count()).select_from(
        select(Plan.id).where(Plan.workspace_id == session.workspace_id).subquery()
    )
    stored_plans = (await db.execute(stored_count_q)).scalar_one()

    return templates.TemplateResponse("settings/billing.html", {
        "request": request,
        "tier": tier.value,
        "limits": limits,
        "usage": {
            "plans_today": plans_today,
            "api_calls_month": api_calls_month,
            "stored_plans": stored_plans,
        },
    })


# ── Lock Monitoring (Web UI) ────────────────────────────────────────


@web_router.get("/locks", response_class=HTMLResponse)
async def locks_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Lock monitoring dashboard — blocking chains and deadlock detection."""
    templates = _templates()
    return templates.TemplateResponse("locks.html", {
        "request": request,
        "active_page": "locks",
    })


@web_router.post("/locks/analyze", response_class=HTMLResponse)
async def locks_analyze_htmx(
    request: Request,
    dsn: str = Form(default=""),
) -> HTMLResponse:
    """HTMX endpoint: analyze locks on a live database."""
    templates = _templates()

    if not dsn.strip():
        return HTMLResponse(
            '<div class="rounded-lg bg-yellow-50 dark:bg-yellow-900/20 '
            'border border-yellow-200 dark:border-yellow-800 p-4">'
            '<p class="text-sm text-yellow-700 dark:text-yellow-400">'
            "Please provide a PostgreSQL connection string.</p></div>"
        )

    try:
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            from querysense.lock_monitor import LockMonitor

            monitor = LockMonitor()
            queries = monitor.get_catalog_queries()

            blocking_rows = await conn.fetch(queries["blocking"])
            blocking_data = [dict(r) for r in blocking_rows]

            dist_rows = await conn.fetch(queries["distribution"])
            dist_data = [dict(r) for r in dist_rows]

            report = monitor.analyze_from_data(blocking_data, dist_data)
        finally:
            await conn.close()

        return templates.TemplateResponse("partials/lock_results.html", {
            "request": request,
            "report": report.to_dict(),
        })

    except ImportError:
        return HTMLResponse(
            '<div class="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 p-4">'
            '<p class="text-sm text-red-700">asyncpg required. Install: pip install asyncpg</p></div>'
        )
    except Exception as exc:
        return HTMLResponse(
            f'<div class="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 p-4">'
            f'<p class="text-sm text-red-700">Error: {exc}</p></div>'
        )


# ── Table Growth (Web UI) ──────────────────────────────────────────


@web_router.get("/growth", response_class=HTMLResponse)
async def growth_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Table growth dashboard — size trends, bloat, projections."""
    from querysense.table_growth import TableGrowthTracker

    templates = _templates()
    tracker = TableGrowthTracker()
    report = tracker.generate_report(days=30)

    return templates.TemplateResponse("growth.html", {
        "request": request,
        "active_page": "growth",
        "report": report.to_dict(),
    })


# ── CP-SAT Index Advisor ──────────────────────────────────────────────

@web_router.get("/index", response_class=HTMLResponse)
async def index_advisor_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """CP-SAT index advisor page."""
    templates = _templates()
    return templates.TemplateResponse("index_advisor.html", {
        "request": request,
        "active_page": "index_advisor",
    })


@web_router.post("/index/advise", response_class=HTMLResponse)
async def index_advise_htmx(
    request: Request,
    dsn: str = Form(...),
    max_indexes: int = Form(8),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Run the full CP-SAT index advisor pipeline (HTMX endpoint)."""
    import asyncio

    templates = _templates()

    try:
        from querysense.index.advisor_pipeline import IndexAdvisorPipeline
    except ImportError:
        return templates.TemplateResponse("partials/index_advisor_results.html", {
            "request": request,
            "result": {},
            "error": "Google OR-Tools is not installed. Run: pip install ortools",
        })

    try:
        pipeline = IndexAdvisorPipeline(
            max_indexes_per_table=max_indexes,
            use_hypopg=True,
        )
        result = await pipeline.advise(dsn, schema="public")
        result_dict = result.to_dict()
    except Exception as exc:
        return templates.TemplateResponse("partials/index_advisor_results.html", {
            "request": request,
            "result": {},
            "error": str(exc),
        })

    return templates.TemplateResponse("partials/index_advisor_results.html", {
        "request": request,
        "result": result_dict,
    })


# ── HA Cluster Monitor ─────────────────────────────────────────────────

@web_router.get("/ha", response_class=HTMLResponse)
async def ha_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """HA cluster monitoring page."""
    templates = _templates()
    return templates.TemplateResponse("ha.html", {
        "request": request,
        "active_page": "ha",
    })


@web_router.post("/ha/analyze", response_class=HTMLResponse)
async def ha_analyze_htmx(
    request: Request,
    dsn: str = Form(...),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Analyze HA cluster (HTMX endpoint)."""
    templates = _templates()
    try:
        from querysense.patroni_monitor import PatroniMonitor
        monitor = PatroniMonitor()
        report = await monitor.analyze(dsn)
        return templates.TemplateResponse("partials/ha_results.html", {
            "request": request,
            "report": report.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/ha_results.html", {
            "request": request,
            "report": {},
            "error": str(exc),
        })


# ── Advisor Framework ──────────────────────────────────────────────────

@web_router.get("/advisor", response_class=HTMLResponse)
async def advisor_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Advisor framework page."""
    templates = _templates()
    return templates.TemplateResponse("advisor.html", {
        "request": request,
        "active_page": "advisor",
    })


@web_router.post("/advisor/run", response_class=HTMLResponse)
async def advisor_run_htmx(
    request: Request,
    dsn: str = Form(...),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Run advisor checks (HTMX endpoint)."""
    templates = _templates()
    try:
        from querysense.advisor_framework import AdvisorRunner, Severity
        runner = AdvisorRunner(respect_intervals=False)
        report = await runner.run_all(dsn, min_severity=Severity.DEBUG)
        return templates.TemplateResponse("partials/advisor_results.html", {
            "request": request,
            "report": report.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/advisor_results.html", {
            "request": request,
            "report": {},
            "error": str(exc),
        })


# ── BUFFERS I/O Heatmap ────────────────────────────────────────────────


@web_router.get("/buffers", response_class=HTMLResponse)
async def buffers_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """BUFFERS I/O Heatmap page."""
    templates = _templates()
    return templates.TemplateResponse("buffers.html", {
        "request": request,
        "active_page": "buffers",
    })


@web_router.post("/buffers/analyze", response_class=HTMLResponse)
async def buffers_analyze_htmx(
    request: Request,
    plan_json: str = Form(...),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Analyze plan BUFFERS data (HTMX endpoint)."""
    templates = _templates()
    try:
        from querysense.analysis.buffers import BufferHeatmap

        data = json.loads(plan_json)
        heatmap = BufferHeatmap()
        report = heatmap.analyze(data)

        return templates.TemplateResponse("partials/buffers_results.html", {
            "request": request,
            "report": report.to_dict(),
            "has_data": report.has_buffer_data,
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/buffers_results.html", {
            "request": request,
            "report": {},
            "has_data": False,
            "error": str(exc),
        })


@web_router.post("/buffers/diff", response_class=HTMLResponse)
async def buffers_diff_htmx(
    request: Request,
    before_json: str = Form(...),
    after_json: str = Form(...),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Compare two plans' BUFFERS data (HTMX endpoint)."""
    templates = _templates()
    try:
        from querysense.analysis.buffers import BufferDiff

        before = json.loads(before_json)
        after = json.loads(after_json)
        differ = BufferDiff()
        report = differ.compare(before, after)

        return templates.TemplateResponse("partials/buffers_diff_results.html", {
            "request": request,
            "report": report.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/buffers_diff_results.html", {
            "request": request,
            "report": {},
            "error": str(exc),
        })


# ── Index Design Advisor ───────────────────────────────────────────────


@web_router.get("/index-design", response_class=HTMLResponse)
async def index_design_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Index Design Advisor page."""
    templates = _templates()
    return templates.TemplateResponse("index_design.html", {
        "request": request,
        "active_page": "index-design",
    })


@web_router.post("/index-design/analyze", response_class=HTMLResponse)
async def index_design_htmx(
    request: Request,
    table: str = Form(...),
    columns: str = Form(...),
    where_columns: str = Form(""),
    range_columns: str = Form(""),
    order_columns: str = Form(""),
    select_columns: str = Form(""),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Design an optimal index (HTMX endpoint)."""
    templates = _templates()
    try:
        from querysense.analysis.index_design import IndexDesignAdvisor

        advisor = IndexDesignAdvisor()

        col_list = [c.strip() for c in columns.split(",") if c.strip()]
        where_list = [c.strip() for c in where_columns.split(",") if c.strip()]
        range_list = [c.strip() for c in range_columns.split(",") if c.strip()]
        select_list = [c.strip() for c in select_columns.split(",") if c.strip()]

        order_dict: dict[str, str] = {}
        for part in order_columns.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                col, direction = part.split(":", 1)
                order_dict[col.strip()] = direction.strip().upper()
            else:
                order_dict[part] = "ASC"

        result = advisor.design(
            table=table,
            columns=col_list,
            order=order_dict,
            where_columns=where_list,
            range_columns=range_list,
            select_columns=select_list,
        )

        return templates.TemplateResponse("partials/index_design_results.html", {
            "request": request,
            "result": result.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/index_design_results.html", {
            "request": request,
            "result": {},
            "error": str(exc),
        })


# ── Workbook routes ──────────────────────────────────────────────────────


@router.get("/workbook", response_class=HTMLResponse)
async def workbook_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Query Tuning Workbook dashboard."""
    templates = _templates()
    from querysense.workbook_interactive import WorkbookManager

    mgr = WorkbookManager()
    workbooks = mgr.list_workbooks()
    return templates.TemplateResponse("workbook.html", {
        "request": request,
        "workbooks": [w.to_dict() for w in workbooks],
        "session": session,
    })


@router.post("/workbook/create", response_class=HTMLResponse)
async def workbook_create(
    request: Request,
    sql: str = Form(...),
    name: str = Form(""),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Create a new workbook (HTMX)."""
    templates = _templates()
    try:
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb_id = mgr.init(sql, name)
        wb = mgr._get_workbook(wb_id)
        workbooks = mgr.list_workbooks()
        return templates.TemplateResponse("partials/workbook_list.html", {
            "request": request,
            "workbooks": [w.to_dict() for w in workbooks],
            "success": f"Workbook '{wb['name']}' created (ID: {wb_id})",
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/workbook_list.html", {
            "request": request,
            "workbooks": [],
            "error": str(exc),
        })


# ── Cost Model Audit routes ─────────────────────────────────────────────


@router.get("/cost-model", response_class=HTMLResponse)
async def cost_model_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Cost Model Calibrator page."""
    templates = _templates()
    return templates.TemplateResponse("cost_model.html", {
        "request": request,
        "session": session,
    })


@router.post("/cost-model/audit", response_class=HTMLResponse)
async def cost_model_audit(
    request: Request,
    dsn: str = Form(...),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Run cost model audit (HTMX)."""
    templates = _templates()
    try:
        from querysense.audit.cost_model import CostModelAuditor

        auditor = CostModelAuditor()
        report = await auditor.audit(dsn)
        return templates.TemplateResponse("partials/cost_model_results.html", {
            "request": request,
            "report": report.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/cost_model_results.html", {
            "request": request,
            "report": {},
            "error": str(exc),
        })


# ── Dependencies Audit routes ───────────────────────────────────────────


@router.get("/dependencies", response_class=HTMLResponse)
async def dependencies_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Column Dependency Detector page."""
    templates = _templates()
    return templates.TemplateResponse("dependencies.html", {
        "request": request,
        "session": session,
    })


@router.post("/dependencies/analyze", response_class=HTMLResponse)
async def dependencies_analyze(
    request: Request,
    dsn: str = Form(...),
    table: str = Form(...),
    columns: str = Form(...),
    schema: str = Form("public"),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Analyze column dependencies (HTMX)."""
    templates = _templates()
    try:
        from querysense.audit.dependencies import ColumnDependencyDetector

        col_list = [c.strip() for c in columns.split(",") if c.strip()]
        detector = ColumnDependencyDetector()
        report = await detector.analyze(dsn, table, col_list, schema)
        return templates.TemplateResponse("partials/dependencies_results.html", {
            "request": request,
            "report": report.to_dict(),
        })
    except Exception as exc:
        return templates.TemplateResponse("partials/dependencies_results.html", {
            "request": request,
            "report": {},
            "error": str(exc),
        })


# ── PII Obfuscation routes ──────────────────────────────────────────────


@router.get("/obfuscate", response_class=HTMLResponse)
async def obfuscate_page(
    request: Request,
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """PII Obfuscation page."""
    templates = _templates()
    return templates.TemplateResponse("obfuscate.html", {
        "request": request,
        "session": session,
    })


@router.post("/obfuscate/run", response_class=HTMLResponse)
async def obfuscate_run(
    request: Request,
    text: str = Form(...),
    mode: str = Form("query"),
    salt: str = Form(""),
    session: SessionData = Depends(_require_auth),
) -> HTMLResponse:
    """Run PII obfuscation (HTMX)."""
    templates = _templates()
    try:
        from querysense.security.pii_obfuscator import PIIObfuscator

        obfuscator = PIIObfuscator(salt=salt, deterministic=bool(salt))

        if mode == "plan":
            import json as _json
            plan = _json.loads(text)
            safe_plan, report = obfuscator.obfuscate_plan_with_report(plan)
            return templates.TemplateResponse("partials/obfuscate_results.html", {
                "request": request,
                "mode": "plan",
                "original": text[:500],
                "obfuscated": _json.dumps(safe_plan, indent=2)[:2000],
                "report": report.to_dict(),
            })
        else:
            safe = obfuscator.obfuscate_query(text)
            return templates.TemplateResponse("partials/obfuscate_results.html", {
                "request": request,
                "mode": "query",
                "original": text,
                "obfuscated": safe,
                "report": {},
            })
    except Exception as exc:
        return templates.TemplateResponse("partials/obfuscate_results.html", {
            "request": request,
            "error": str(exc),
        })
