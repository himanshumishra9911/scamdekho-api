from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import router as v1_router
from app.api.analytics import router as analytics_router
from app.api.feedback import router as feedback_router


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
    allow_origins=origins,   # only allowed frontends
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ===============================================

# API routes
app.include_router(v1_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/analytics")
app.include_router(feedback_router, prefix="/feedback")


# Static dashboard (optional)
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="dashboard")

@app.get("/")
def root():
    return {"status": "ScamDekho backend running"}
