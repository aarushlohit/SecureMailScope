"""
SecureMailScope - FastAPI Web Server
"""
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from securemailscope.core.config import config, BASE_DIR
from securemailscope.api.routes import router as api_router
from securemailscope.api.ws import ws_manager
from securemailscope.api.auth import _as_aware_utc, _token_hash, _utc_now
from securemailscope.core.security import verify_access_token
from securemailscope.db.models import AuthSessionModel, InvestigationModel, UserModel
from securemailscope.db.session import SessionLocal, init_db

import logging
logger = logging.getLogger("securemailscope.api")

app = FastAPI(
    title=config.app_name,
    version=config.version,
    description="Agentic Cryptographic Forensics for Secure Email Communications (SIH26159 - NTRO)"
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "HTTP Error", "detail": exc.detail, "code": f"HTTP_{exc.status_code}"}
        )
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An internal forensic processing error occurred.",
            "code": "INTERNAL_SERVER_ERROR"
        }
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = BASE_DIR / "securemailscope" / "web" / "static"
templates_dir = BASE_DIR / "securemailscope" / "web" / "templates"
assets_dir = BASE_DIR / "assets"

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
templates = Jinja2Templates(directory=str(templates_dir))

app.include_router(api_router)


# 1. Marketing Landing Page
@app.get("/")
def render_landing(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="landing.html",
        context={"app_name": config.app_name, "version": config.version}
    )


# 2. Authentication Pages
@app.get("/login")
def render_login(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"app_name": config.app_name, "version": config.version}
    )


@app.get("/signup")
def render_signup(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="signup.html",
        context={"app_name": config.app_name, "version": config.version}
    )


# 3. Investigation App Shell & Console
@app.get("/app")
@app.get("/app/{rest_of_path:path}")
def render_app(request: Request, rest_of_path: str = ""):
    from securemailscope.api.auth import get_current_user_optional, get_or_create_default_user, _create_persisted_session
    db = SessionLocal()
    token = None
    try:
        user = get_current_user_optional(authorization=None, request=request, db=db)
        if not user:
            default_user = get_or_create_default_user(db)
            token = _create_persisted_session(default_user, db, request)
    finally:
        db.close()

    response = templates.TemplateResponse(
        request=request,
        name="app.html",
        context={
            "app_name": config.app_name,
            "version": config.version,
            "initial_route": f"/app/{rest_of_path}",
            "auto_token": token or ""
        }
    )
    if token:
        response.set_cookie(
            key="securemailscope_token",
            value=token,
            httponly=False,
            samesite="lax",
            max_age=30 * 24 * 3600
        )
    return response


@app.websocket("/ws/{investigation_id}")
async def websocket_endpoint(websocket: WebSocket, investigation_id: str):
    token = websocket.query_params.get("token")
    auth_header = websocket.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = websocket.cookies.get("securemailscope_token")

    payload = verify_access_token(token or "")
    if not payload or "sub" not in payload or "sid" not in payload:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        init_db()
        db = SessionLocal()
        try:
            session = db.query(AuthSessionModel).filter_by(
                session_id=payload["sid"],
                token_hash=_token_hash(token),
                user_id=payload["sub"],
            ).first()
            user = db.query(UserModel).filter_by(user_id=payload["sub"], is_active=True).first()
            owned_inv = db.query(InvestigationModel).filter_by(
                investigation_id=investigation_id,
                user_id=payload["sub"],
            ).first()
            now = _utc_now()
            if (
                not session
                or not user
                or not owned_inv
                or session.revoked_at is not None
                or _as_aware_utc(session.expires_at) <= now
            ):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            session.last_used_at = now
            db.commit()
        finally:
            db.close()
    except Exception:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await ws_manager.connect(websocket, investigation_id)
    try:
        while True:
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, investigation_id)


def start_server(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_server()
