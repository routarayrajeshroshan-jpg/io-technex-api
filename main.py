from datetime import datetime, timezone
import random

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="IO Technex Smart EMS API",
    version="1.0.0"
)

# Allow your existing Vercel website to call this API.
# We will restrict this to your website's domain for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://io-technex.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "IO Technex Smart EMS API is running",
        "data_source": "SIMULATED"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/v1/telemetry")
def get_telemetry():
    meters = []

    for index, meter_id in enumerate([35, 36, 37, 38, 39]):
        meters.append({
            "slave_id": meter_id,
            "meter_name": f"PM800-{meter_id}",
            "voltage": round(random.uniform(410, 425), 2),
            "current": round(random.uniform(5, 25), 2),
            "energy_kwh": round(
                1000 + index * 500 + random.uniform(0, 5), 2
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data_source": "SIMULATED"
        })

    return {
        "data_source": "SIMULATED",
        "count": len(meters),
        "meters": meters
    }
