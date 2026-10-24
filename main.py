from datetime import datetime, timezone
from threading import Lock

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="IO Technex Smart EMS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://io-technex.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Temporary in-memory storage for prototype testing.
# Data is lost if the service restarts.
storage_lock = Lock()
latest_meters = []


class TelemetryPayload(BaseModel):
    data_source: str = "SIMULATED"
    meters: list[dict]


@app.get("/")
def home():
    return {
        "message": "IO Technex Smart EMS API is running",
        "data_source": "SIMULATED"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/api/v1/telemetry")
def receive_telemetry(payload: TelemetryPayload):
    global latest_meters

    if not payload.meters:
        raise HTTPException(
            status_code=400,
            detail="At least one meter reading is required"
        )

    with storage_lock:
        latest_meters = payload.meters

    return {
        "status": "success",
        "message": "Telemetry received",
        "count": len(payload.meters),
        "data_source": payload.data_source
    }


@app.get("/api/v1/telemetry")
def get_telemetry():
    with storage_lock:
        meters = list(latest_meters)

    return {
        "data_source": (
            "SIMULATED"
            if not meters
            else "NODE_RED"
        ),
        "count": len(meters),
        "meters": meters
    }
