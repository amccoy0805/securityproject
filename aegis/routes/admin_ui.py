"""Server-rendered admin console.

This is intentionally lightweight: a few Jinja templates with Tailwind CDN +
HTMX-style JS sprinkles. It keeps the deployment to a single container with no
front-end build pipeline. For larger installs, swap this out for a SPA that
talks to ``/admin/api/*``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select

from ..auth import (
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    AuthContext,
    issue_session_token,
    optional_admin_user,
    require_admin_user,
)
from ..config import get_settings
from ..db import session_scope
from ..models import ApiKey, AuditEvent, Policy, ProviderCredential, User
from ..security import verify_password

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["admin-ui"])


@router.get("/", response_class=HTMLResponse)
async def landing(request: Request, ctx: AuthContext | None = Depends(optional_admin_user)) -> HTMLResponse:
    if ctx and ctx.user:
        return RedirectResponse("/admin", status_code=302)
    return templates.TemplateResponse("landing.html", {"request": request})


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    async with session_scope() as session:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user or not user.is_active or not verify_password(password, user.password_hash):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Invalid email or password."},
                status_code=401,
            )
        token = issue_session_token(user.id, user.tenant_id)
        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=get_settings().session_cookie_secure,
        )
        return resp


@router.post("/logout")
async def logout() -> RedirectResponse:
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/admin", response_class=HTMLResponse)
async def admin_home(
    request: Request, ctx: AuthContext = Depends(require_admin_user)
) -> HTMLResponse:
    async with session_scope() as session:
        recent = (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == ctx.tenant.id)
                .order_by(desc(AuditEvent.created_at))
                .limit(10)
            )
        ).scalars().all()
        keys = (
            await session.execute(
                select(ApiKey).where(ApiKey.tenant_id == ctx.tenant.id).order_by(desc(ApiKey.created_at))
            )
        ).scalars().all()
        policies = (
            await session.execute(
                select(Policy).where(Policy.tenant_id == ctx.tenant.id).order_by(Policy.priority)
            )
        ).scalars().all()
        creds = (
            await session.execute(
                select(ProviderCredential).where(ProviderCredential.tenant_id == ctx.tenant.id)
            )
        ).scalars().all()
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "ctx": ctx,
            "recent": recent,
            "keys": keys,
            "policies": policies,
            "creds": creds,
        },
    )


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request, ctx: AuthContext = Depends(require_admin_user)
) -> HTMLResponse:
    async with session_scope() as session:
        events = (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == ctx.tenant.id)
                .order_by(desc(AuditEvent.created_at))
                .limit(200)
            )
        ).scalars().all()
    return templates.TemplateResponse(
        "audit.html", {"request": request, "ctx": ctx, "events": events}
    )


@router.get("/admin/playground", response_class=HTMLResponse)
async def playground(
    request: Request, ctx: AuthContext = Depends(require_admin_user)
) -> HTMLResponse:
    return templates.TemplateResponse("playground.html", {"request": request, "ctx": ctx})


@router.get("/admin/event/{event_id}", response_class=HTMLResponse)
async def event_detail(
    event_id: str, request: Request, ctx: AuthContext = Depends(require_admin_user)
) -> HTMLResponse:
    async with session_scope() as session:
        event = await session.get(AuditEvent, event_id)
        if not event or event.tenant_id != ctx.tenant.id:
            raise HTTPException(404, "Event not found.")
    return templates.TemplateResponse(
        "event.html", {"request": request, "ctx": ctx, "event": event}
    )
