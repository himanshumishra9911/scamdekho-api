from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import router as v1_router
from app.api.analytics import router as analytics_router


app = FastAPI(title="ScamDekho API")


# ================= CORS FIX (VERY IMPORTANT) =================
# Allows frontend (localhost:5500 / any port) to call this API

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # allow all (dev friendly)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ============================================================


# API routes
app.include_router(v1_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/analytics")


# Static dashboard (optional)
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="dashboard")


@app.get("/")
def root():
    return {"status": "ScamDekho backend running"}
