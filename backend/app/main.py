import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .routers import auth, engagements, scans, export, agents, webhooks, settings

app = FastAPI(
    title="SubNex",
    description="SubNex - Where your assets hide, SubNex finds.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(engagements.router)
app.include_router(scans.router)
app.include_router(agents.router)
app.include_router(export.router)
app.include_router(webhooks.router)
app.include_router(settings.router)


# Built UI bundle. Served from the host's ./frontend/dist (mounted read-only),
# or baked into the image at /app/static. Dynamic checks per request so a fresh
# `npm run build` on the host is visible without restarting the container.
_STATIC_DIR = Path(os.environ.get("FRONTEND_DIST", "/app/static"))
_SPA_INDEX = _STATIC_DIR / "index.html"


@app.on_event("startup")
async def _startup():
    from .services.migrations import run_migrations
    run_migrations()
    from seed import seed_users
    await seed_users()
    from .websocket import manager
    manager.start_relay()


@app.get("/")
async def root():
    if _SPA_INDEX.exists():
        return FileResponse(_SPA_INDEX)
    return {"message": "SubNex API", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/assets/{asset_path:path}", include_in_schema=False)
async def asset(asset_path: str):
    candidate = (_STATIC_DIR / "assets" / asset_path).resolve()
    base = (_STATIC_DIR / "assets").resolve()
    if base not in candidate.parents or not candidate.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(candidate)


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    if full_path.startswith(("api", "assets")):
        raise HTTPException(status_code=404)
    if not _SPA_INDEX.exists():
        raise HTTPException(status_code=404)
    return FileResponse(_SPA_INDEX)