from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth, engagements, scans, export, agents, webhooks

app = FastAPI(
    title="Network Asset Discovery Platform",
    description="Professional-grade network asset discovery tool for penetration testing engagements.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(engagements.router)
app.include_router(scans.router)
app.include_router(agents.router)
app.include_router(export.router)
app.include_router(webhooks.router)


@app.on_event("startup")
async def _start_ws_relay():
    from .websocket import manager
    manager.start_relay()


@app.get("/")
async def root():
    return {"message": "Network Asset Discovery Platform API", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}
