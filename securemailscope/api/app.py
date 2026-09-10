"""
SecureMailScope - FastAPI Web Server
"""
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from securemailscope.core.config import config, BASE_DIR
from securemailscope.api.routes import router as api_router
from securemailscope.api.ws import ws_manager

app = FastAPI(
    title=config.app_name,
    version=config.version,
    description="Agentic Cryptographic Forensics for Secure Email Communications (SIH26159 - NTRO)"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    return templates.TemplateResponse(
        request=request,
        name="app.html",
        context={"app_name": config.app_name, "version": config.version, "initial_route": f"/app/{rest_of_path}"}
    )


@app.websocket("/ws/{investigation_id}")
async def websocket_endpoint(websocket: WebSocket, investigation_id: str):
    await ws_manager.connect(websocket, investigation_id)
    try:
        while True:
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, investigation_id)


def start_server(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_server()
