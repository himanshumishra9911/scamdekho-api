import logging
from pathlib import Path
from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import router as v1_router
from app.api.analytics import router as analytics_router
from app.api.feedback import router as feedback_router
from app.services.cache_service import setup_cache_ttl_index
from app.services.website_screenshot import setup_screenshot_cache_index
from app.services.partner_api_service import (
    seed_default_partner_keys,
    setup_partner_api_indexes,
)
from app.api.paypal_email_checker import router as paypal_email_router
from app.api.paypal_link_checker import router as paypal_link_router
from app.api.paypal_invoice_checker import router as paypal_invoice_router
from app.api.partner_url_check import router as partner_url_check_router
from app.services.scam_db_service import run_all_syncs
from app.services.security import require_admin
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.api.public_sitemaps import router as public_sitemaps_router
from app.api.public_pages import router as public_pages_router
from app.api.listing_pages import router as listing_router

logger = logging.getLogger(__name__)

app = FastAPI(title="ScamDekho API")
app.state.limiter = Limiter(key_func=get_remote_address)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.include_router(listing_router)

scheduler = AsyncIOScheduler()

# ================= CORS CONFIG =================
origins = [
    "https://scamdekho.in",
    "https://www.scamdekho.in",
    "https://scamdekho-api.onrender.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= STARTUP =================
@app.on_event("startup")
async def startup():
    await setup_cache_ttl_index()
    await setup_screenshot_cache_index()
    await setup_partner_api_indexes()
    await seed_default_partner_keys()

    # Scam DB initial sync
    try:
        await run_all_syncs()
        logger.info("Initial scam DB sync complete")
    except Exception as e:
        logger.error(f"Initial sync failed (non-fatal): {e}")

    # Daily sync
    scheduler.add_job(
        run_all_syncs,
        trigger="cron",
        hour=2,
        minute=0,
        id="daily_scam_db_sync",
        replace_existing=True,
    )
    scheduler.start()

# ================= SHUTDOWN =================
@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown()

# ================= ROUTES =================
app.include_router(v1_router, prefix="/api/v1")
app.include_router(partner_url_check_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/analytics")
app.include_router(feedback_router, prefix="/feedback")

# PayPal Tools Routes (NEW)
app.include_router(paypal_email_router)
app.include_router(paypal_link_router)
app.include_router(paypal_invoice_router)
app.include_router(public_sitemaps_router)
app.include_router(public_pages_router)

@app.get("/dashboard", dependencies=[Depends(require_admin)])
@app.get("/dashboard/", dependencies=[Depends(require_admin)])
def dashboard():
    dashboard_path = Path("app/static/dashboard.html")
    extension_path = Path("app/static/partner_dashboard_extension.js")
    try:
        html = dashboard_path.read_text(encoding="utf-8")
        extension = extension_path.read_text(encoding="utf-8")
        if "partner_dashboard_extension.js" not in html:
            html = html.replace(
                "</body>",
                f"<script data-source=\"partner_dashboard_extension.js\">\n{extension}\n</script>\n</body>",
            )
        return HTMLResponse(html)
    except Exception:
        return FileResponse(dashboard_path)

@app.get("/")
def root():
    return {"status": "ScamDekho backend running"}
