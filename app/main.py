from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import router as v1_router
from app.api.analytics import router as analytics_router
from app.api.feedback import router as feedback_router
from app.services.cache_service import setup_cache_ttl_index
from app.services.website_screenshot import setup_screenshot_cache_index

app = FastAPI(title="ScamDekho API")

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
    await setup_cache_ttl_index()          # URL result cache TTL index
    await setup_screenshot_cache_index()   # Screenshot cache TTL index

# ================= ROUTES =================
app.include_router(v1_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/analytics")
app.include_router(feedback_router, prefix="/feedback")

@app.get("/dashboard")
@app.get("/dashboard/")
def dashboard():
    return FileResponse("app/static/dashboard.html")

@app.get("/")
def root():
    return {"status": "ScamDekho backend running"}
