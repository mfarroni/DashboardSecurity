from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.database import init_db
from app.api import assets, feed, cve, dashboard, syslog, imports, auth, settings as settings_api


MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    print(f"Security Dashboard started on {settings.database_url}")
    yield
    # Shutdown
    print("Security Dashboard shutting down")


app = FastAPI(
    title="Security Dashboard - FeedHub + Perimetro CVE",
    description="Dashboard di sicurezza per vulnerability management e correlazione CVE",
    version="1.0.0",
    lifespan=lifespan,
)

# 50MB Max Upload Size Guard Middleware
@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        if int(content_length) > MAX_UPLOAD_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Dimensione del file eccede il limite massimo di 50MB"}
            )
    return await call_next(request)

# CORS hardening: Restricted to explicit trusted origins
allowed_origins_list = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Make templates available globally
app.state.templates = templates


# Include routers
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(feed.router, prefix="/api/feed", tags=["Feed"])
app.include_router(cve.router, prefix="/api/cve", tags=["CVE"])
app.include_router(syslog.router, prefix="/api/syslog", tags=["Syslog"])
app.include_router(imports.router, prefix="/api/import", tags=["Import"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["Settings"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "security-dashboard"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )