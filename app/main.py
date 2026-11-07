"""TrustVault — FastAPI application factory."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .database import engine, Base
from .security import NotAuthenticatedException
from .routers import auth, documents, sharing, audit

# Absolute paths relative to this file — works from any working directory
_HERE = Path(__file__).parent
STATIC_DIR = _HERE / "static"
TEMPLATES_DIR = _HERE / "templates"


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all DB tables and ensure upload directory exists on startup."""
    Base.metadata.create_all(bind=engine)
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


# ─── App factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# Static files (CSS, JS, images) — served publicly
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Jinja2 templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ─── Routers ──────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(sharing.router)
app.include_router(audit.router)


# ─── Root redirect ────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/documents", status_code=302)


# ─── Exception handlers ───────────────────────────────────────────────────────

@app.exception_handler(NotAuthenticatedException)
async def not_authenticated_handler(request: Request, exc: NotAuthenticatedException):
    """Redirect unauthenticated users to login page."""
    return RedirectResponse(url="/auth/login", status_code=303)


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "errors/403.html", {"request": request, "current_user": None}, status_code=403
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "errors/404.html", {"request": request, "current_user": None}, status_code=404
    )
