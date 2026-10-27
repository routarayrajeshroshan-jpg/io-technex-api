import os
import hmac
from datetime import date, datetime, timezone, timedelta
from threading import Lock
from functools import lru_cache
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

from influxdb_client import InfluxDBClient

import jwt
from jwt import PyJWKClient
from supabase import create_client, Client
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ConfigDict


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
# Set these environment variables in Render. Never hard-code secrets.
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]
NODE_RED_API_KEY = os.environ["NODE_RED_API_KEY"]

# InfluxDB 2.x settings. Configure these in Render Environment.
INFLUXDB_URL = os.getenv("INFLUXDB_URL", "https://us-east-1-1.aws.cloud2.influxdata.com").rstrip("/")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG", "asianpaints")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "asianpaints_utility_smartems")
INFLUXDB_TOKEN = os.getenv("x2QrYtwF01-MNmxKF2A93aexkvwIHLV_lXWT-0f2iS_xKjuoVle0zWfu4p2Z_I4UYyeI7itglCzAbqKizFGnpw==", "")
ANALYTICS_TIMEZONE = os.getenv("ANALYTICS_TIMEZONE", "Asia/Kolkata")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------
app = FastAPI(
    title="IO Technex Smart EMS API",
    version="1.0.0",
    description="API for IO Technex Smart EMS customer, factory, meter, and telemetry data.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://io-technex.vercel.app",
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# --------------------------------------------------
# TEMPORARY TELEMETRY STORAGE
# --------------------------------------------------
# NOTE: This is in-memory storage. Readings are lost when the API restarts
# and are not shared across multiple API instances. Move telemetry to a
# persistent database before production use.
storage_lock = Lock()
# Key is (factory_id, slave_id), so the same Modbus ID can exist in
# different factories without one factory's readings replacing another's.
latest_meters: dict[tuple[str, int], dict[str, Any]] = {}


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------
security = HTTPBearer(auto_error=False)
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"


@lru_cache(maxsize=1)
def get_jwks_client() -> PyJWKClient:
    return PyJWKClient(JWKS_URL, cache_keys=True)


def require_customer(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Login required")

    try:
        token = credentials.credentials
        signing_key = get_jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            audience="authenticated",
            issuer=f"{SUPABASE_URL}/auth/v1",
            options={"require": ["exp", "sub", "iss", "aud"]},
        )
        return claims
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login token",
        )


def require_admin(
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    try:
        result = (
            supabase.table("profiles")
            .select("role")
            .eq("id", user_id)
            .maybe_single()
            .execute()
        )
        profile = result.data

        if not profile or profile.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

        return claims
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Unable to verify admin permissions",
        )


def require_node_red(
    x_api_key: str = Header(default="", alias="X-API-Key"),
) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, NODE_RED_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid telemetry credential")


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------
def get_assigned_factories(user_id: str) -> list[str]:
    try:
        result = (
            supabase.table("factory_users")
            .select("factory_id")
            .eq("user_id", user_id)
            .execute()
        )
        return [str(row["factory_id"]) for row in (result.data or [])]
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to verify factory access")


def get_factory_meter_map(factory_ids: list[str]) -> dict[str, set[int]]:
    """Return {factory_id: {assigned slave IDs}} for only the supplied factories."""
    if not factory_ids:
        return {}

    try:
        result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id")
            .in_("factory_id", factory_ids)
            .execute()
        )
        mapping: dict[str, set[int]] = {factory_id: set() for factory_id in factory_ids}
        for row in result.data or []:
            mapping.setdefault(str(row["factory_id"]), set()).add(int(row["slave_id"]))
        return mapping
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to retrieve assigned meters")


def validate_uuid(value: str, field_name: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}")


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------
class CreateCustomerRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class CreateFactoryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=200)
    customer_user_id: str = Field(min_length=1, max_length=100)


class RegisterMeterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    factory_id: str = Field(min_length=1, max_length=100)
    slave_id: int = Field(ge=1, le=247)
    meter_name: str = Field(min_length=1, max_length=120)


class MeterReading(BaseModel):
    model_config = ConfigDict(extra="allow")
    slave_id: int = Field(ge=1, le=247)


class TelemetryPayload(BaseModel):
    # Required to prevent readings from different factories being mixed.
    factory_id: str = Field(min_length=1, max_length=100)
    data_source: str = Field(default="NODE_RED", min_length=1, max_length=40)
    meters: list[MeterReading] = Field(min_length=1, max_length=500)


# --------------------------------------------------
# HEALTH ENDPOINTS
# --------------------------------------------------
@app.get("/")
def home() -> dict[str, str]:
    return {"message": "IO Technex Smart EMS API is running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


# --------------------------------------------------
# ADMIN: VERIFY ACCESS
# --------------------------------------------------
@app.get("/api/v1/admin/check")
def admin_check(claims: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
    return {
        "status": "success",
        "message": "Admin access verified",
        "user_id": str(claims.get("sub", "")),
    }


# --------------------------------------------------
# ADMIN: DASHBOARD STATISTICS
# --------------------------------------------------
@app.get("/api/v1/admin/stats")
def admin_stats(
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    try:
        customers_result = (
            supabase.table("profiles")
            .select("id", count="exact")
            .eq("role", "customer")
            .limit(1)
            .execute()
        )

        factories_result = (
            supabase.table("factories")
            .select("id", count="exact")
            .limit(1)
            .execute()
        )

        meters_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id", count="exact")
            .limit(10000)
            .execute()
        )

        # Online here means a registered meter has a reading in API memory.
        # This does not yet enforce a recent last-seen time threshold.
        registered_keys = {
            (str(row["factory_id"]), int(row["slave_id"]))
            for row in (meters_result.data or [])
        }

        with storage_lock:
            readings = list(latest_meters.values())

        online_cutoff = datetime.now(timezone.utc) - timedelta(seconds=120)
        online_keys = set()
        for reading in readings:
            key = (str(reading.get("factory_id")), int(reading.get("slave_id", 0)))
            last_seen = reading.get("last_seen")
            try:
                seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            except (TypeError, ValueError):
                continue
            if key in registered_keys and seen_at >= online_cutoff:
                online_keys.add(key)

        return {
            "total_customers": customers_result.count or 0,
            "total_factories": factories_result.count or 0,
            "registered_meters": meters_result.count or 0,
            "online_meters": len(online_keys),
        }
    except HTTPException:
        raise
    except Exception as error:
        print(f"Dashboard statistics error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve dashboard statistics",
        )


# --------------------------------------------------
# ADMIN: CREATE CUSTOMER
# --------------------------------------------------
@app.get("/api/v1/admin/customers")
def list_customers(
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List customer profiles and match email addresses from Supabase Auth."""
    try:
        profiles_result = (
            supabase.table("profiles")
            .select("id, full_name, role, created_at")
            .eq("role", "customer")
            .order("created_at", desc=True)
            .execute()
        )
        profiles = profiles_result.data or []

        # profiles does not store email, so retrieve it from Supabase Auth.
        auth_result = supabase.auth.admin.list_users()
        auth_users = getattr(auth_result, "users", auth_result)
        email_by_id = {
            str(getattr(auth_user, "id", "")): getattr(auth_user, "email", None)
            for auth_user in (auth_users or [])
        }

        customers = [
            {**profile, "email": email_by_id.get(str(profile.get("id")))}
            for profile in profiles
        ]
        return {"customers": customers, "count": len(customers)}
    except Exception as error:
        print(f"List customers error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve customers. Check Supabase configuration.",
        )


@app.post("/api/v1/admin/customers", status_code=201)
def create_customer(
    request: CreateCustomerRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    email = request.email.strip().lower()
    full_name = request.full_name.strip()

    if not email or "@" not in email or not full_name:
        raise HTTPException(status_code=400, detail="A valid email and customer name are required")

    try:
        result = supabase.auth.admin.create_user(
            {
                "email": email,
                "password": request.password,
                "email_confirm": True,
                "user_metadata": {"full_name": full_name},
            }
        )
        user = result.user

        if not user:
            raise HTTPException(status_code=500, detail="Customer account creation failed")

        try:
            (
                supabase.table("profiles")
                .upsert(
                    {
                        "id": user.id,
                        "full_name": full_name,
                        "role": "customer",
                    }
                )
                .execute()
            )
        except Exception:
            # Compensate for partial creation so an auth account is not silently left
            # without the corresponding profile. If deletion fails, inspect Supabase.
            try:
                supabase.auth.admin.delete_user(user.id)
            except Exception:
                pass
            raise HTTPException(
                status_code=500,
                detail="Customer account was created but profile setup failed; check Supabase",
            )

        return {
            "status": "success",
            "message": "Customer account created. Share the initial password securely and ask the customer to change it after signing in.",
            "customer": {
                "id": user.id,
                "email": user.email,
                "full_name": full_name,
                "role": "customer",
            },
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to create customer. Check whether the email already exists and verify Supabase configuration.",
        )


# --------------------------------------------------
# ADMIN: LIST FACTORIES WITH ASSIGNED CUSTOMER
# --------------------------------------------------
@app.get("/api/v1/admin/factories")
def list_factories(
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List factories and include the first assigned customer's details."""
    try:
        factories_result = (
            supabase.table("factories")
            .select("id, name, location, created_at")
            .order("created_at", desc=True)
            .execute()
        )
        factories = factories_result.data or []

        if not factories:
            return {"factories": [], "count": 0}

        factory_ids = [str(factory["id"]) for factory in factories]
        assignments_result = (
            supabase.table("factory_users")
            .select("factory_id, user_id")
            .in_("factory_id", factory_ids)
            .execute()
        )
        assignments = assignments_result.data or []
        user_ids = list({str(row["user_id"]) for row in assignments if row.get("user_id")})

        profile_by_id: dict[str, dict[str, Any]] = {}
        if user_ids:
            profiles_result = (
                supabase.table("profiles")
                .select("id, full_name, role")
                .in_("id", user_ids)
                .execute()
            )
            profile_by_id = {
                str(profile["id"]): profile
                for profile in (profiles_result.data or [])
            }

        # Email is managed by Supabase Auth, not the profiles table.
        auth_result = supabase.auth.admin.list_users()
        auth_users = getattr(auth_result, "users", auth_result)
        email_by_id = {
            str(getattr(auth_user, "id", "")): getattr(auth_user, "email", None)
            for auth_user in (auth_users or [])
        }

        assignments_by_factory: dict[str, list[dict[str, Any]]] = {}
        for assignment in assignments:
            factory_key = str(assignment.get("factory_id", ""))
            user_key = str(assignment.get("user_id", ""))
            profile = profile_by_id.get(user_key, {})
            assignments_by_factory.setdefault(factory_key, []).append({
                "id": user_key,
                "full_name": profile.get("full_name") or "Unnamed customer",
                "email": email_by_id.get(user_key),
            })

        output = []
        for factory in factories:
            item = dict(factory)
            assigned = assignments_by_factory.get(str(factory.get("id")), [])
            item["customers"] = assigned
            item["customer"] = assigned[0] if assigned else None
            output.append(item)

        return {"factories": output, "count": len(output)}
    except Exception as error:
        print(f"List factories error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve factories. Check factories, factory_users, profiles, and Supabase Auth configuration.",
        )


# --------------------------------------------------
# ADMIN: CREATE FACTORY AND ASSIGN CUSTOMER
# --------------------------------------------------
@app.post("/api/v1/admin/factories", status_code=201)
def create_factory(
    request: CreateFactoryRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    name = request.name.strip()
    location = request.location.strip()
    customer_user_id = request.customer_user_id.strip()

    if not name or not location or not customer_user_id:
        raise HTTPException(
            status_code=400,
            detail="Factory name, location, and customer user ID are required",
        )

    factory_id: str | None = None

    try:
        profile_result = (
            supabase.table("profiles")
            .select("id, role")
            .eq("id", customer_user_id)
            .maybe_single()
            .execute()
        )
        profile = profile_result.data

        if not profile or profile.get("role") != "customer":
            raise HTTPException(status_code=400, detail="A valid customer account is required")

        factory_result = (
            supabase.table("factories")
            .insert({"name": name, "location": location})
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=500, detail="Factory creation failed")

        factory = factory_result.data[0]
        factory_id = str(factory["id"])

        try:
            (
                supabase.table("factory_users")
                .insert({"factory_id": factory_id, "user_id": customer_user_id})
                .execute()
            )
        except Exception:
            # Best-effort cleanup. For strict atomicity, use a Supabase SQL RPC
            # transaction for both inserts.
            try:
                supabase.table("factories").delete().eq("id", factory_id).execute()
            except Exception:
                pass
            raise HTTPException(
                status_code=500,
                detail="Factory assignment failed. Check the customer and factory_users table.",
            )

        return {
            "status": "success",
            "message": "Factory created and customer assigned",
            "factory": {
                "id": factory_id,
                "name": factory.get("name", name),
                "location": factory.get("location", location),
            },
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to create factory or assign customer",
        )


# --------------------------------------------------
# ADMIN: REGISTER METER TO FACTORY
# --------------------------------------------------
@app.post("/api/v1/admin/meters", status_code=201)
def register_meter(
    request: RegisterMeterRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    factory_id = validate_uuid(request.factory_id.strip(), "factory ID")
    meter_name = request.meter_name.strip()
    slave_id = request.slave_id

    if not meter_name:
        raise HTTPException(status_code=400, detail="Meter name is required")

    try:
        factory_result = (
            supabase.table("factories")
            .select("id")
            .eq("id", factory_id)
            .maybe_single()
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")

        result = (
            supabase.table("factory_meters")
            .insert(
                {
                    "factory_id": factory_id,
                    "slave_id": slave_id,
                    "meter_name": meter_name,
                }
            )
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=500, detail="Meter registration returned no record")

        return {
            "status": "success",
            "message": "Meter registered",
            "meter": result.data[0],
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to register meter. Check for a duplicate slave ID in this factory.",
        )


# --------------------------------------------------
# ADMIN: LIST REGISTERED METERS WITH LATEST TELEMETRY
# --------------------------------------------------
@app.get("/api/v1/admin/meters")
def list_admin_meters(
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Return registered meters, factory details, and recent in-memory readings."""
    try:
        meter_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id, meter_name")
            .order("slave_id")
            .execute()
        )
        registered = meter_result.data or []
        if not registered:
            return {"meters": [], "count": 0}

        factory_ids = list({str(row["factory_id"]) for row in registered})
        factory_result = (
            supabase.table("factories")
            .select("id, name, location")
            .in_("id", factory_ids)
            .execute()
        )
        factory_by_id = {
            str(factory["id"]): factory for factory in (factory_result.data or [])
        }

        with storage_lock:
            readings_by_key = dict(latest_meters)

        now = datetime.now(timezone.utc)
        online_cutoff = now - timedelta(seconds=120)
        output = []
        for row in registered:
            factory_id = str(row["factory_id"])
            slave_id = int(row["slave_id"])
            reading = readings_by_key.get((factory_id, slave_id), {})
            last_seen = reading.get("last_seen")
            try:
                seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
                is_online = seen_at >= online_cutoff
            except (TypeError, ValueError):
                is_online = False

            factory = factory_by_id.get(factory_id, {})
            item = {
                "factory_id": factory_id,
                "factory_name": factory.get("name", "Unknown factory"),
                "factory_location": factory.get("location", ""),
                "slave_id": slave_id,
                "meter_name": row.get("meter_name") or f"Meter {slave_id}",
                "status": "online" if is_online else "offline",
                "last_seen": last_seen,
                "data_source": reading.get("data_source"),
            }
            # Include only known telemetry values, avoiding internal metadata duplication.
            for key, value in reading.items():
                if key not in {"factory_id", "slave_id", "meter_name", "last_seen", "data_source"}:
                    item[key] = value
            output.append(item)

        return {"meters": output, "count": len(output)}
    except HTTPException:
        raise
    except Exception as error:
        print(f"List meters error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve meters. Check factory_meters and factories tables.",
        )


# --------------------------------------------------
# RECEIVE NODE-RED TELEMETRY
# --------------------------------------------------
@app.post("/api/v1/telemetry", status_code=202)
def receive_telemetry(
    payload: TelemetryPayload,
    _: None = Depends(require_node_red),
) -> dict[str, Any]:
    factory_id = validate_uuid(payload.factory_id.strip(), "factory ID")

    # Only accept telemetry for a factory and meters already registered in Supabase.
    try:
        factory_result = (
            supabase.table("factories")
            .select("id")
            .eq("id", factory_id)
            .maybe_single()
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")

        registered_result = (
            supabase.table("factory_meters")
            .select("slave_id")
            .eq("factory_id", factory_id)
            .execute()
        )
        registered_ids = {
            int(row["slave_id"]) for row in (registered_result.data or [])
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to validate factory meter assignments")

    if not registered_ids:
        raise HTTPException(status_code=400, detail="No meters are registered to this factory")

    seen_ids: set[int] = set()
    normalized_readings: list[dict[str, Any]] = []

    for reading_model in payload.meters:
        reading = reading_model.model_dump()
        slave_id = int(reading["slave_id"])

        if slave_id not in registered_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Slave ID {slave_id} is not registered to this factory",
            )
        if slave_id in seen_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate slave ID {slave_id} in this telemetry payload",
            )

        seen_ids.add(slave_id)
        reading["factory_id"] = factory_id
        reading["data_source"] = payload.data_source
        reading["last_seen"] = datetime.now(timezone.utc).isoformat()
        normalized_readings.append(reading)

    with storage_lock:
        for reading in normalized_readings:
            key = (factory_id, int(reading["slave_id"]))
            latest_meters[key] = reading

    return {
        "status": "success",
        "message": "Telemetry received",
        "factory_id": factory_id,
        "count": len(normalized_readings),
        "data_source": payload.data_source,
    }


# --------------------------------------------------
# CUSTOMER: RETURN ONLY ASSIGNED FACTORY METERS
# --------------------------------------------------
@app.get("/api/v1/telemetry")
def get_telemetry(
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    factory_ids = get_assigned_factories(user_id)
    if not factory_ids:
        return {
            "data_source": "SIMULATED",
            "count": 0,
            "factories": [],
            "meters": [],
        }

    # Fetch registered meter names from Supabase. Do not rely on the
    # telemetry payload to contain the customer-facing meter name.
    try:
        registered_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id, meter_name")
            .in_("factory_id", factory_ids)
            .order("slave_id")
            .execute()
        )
        registered_meters = registered_result.data or []

        factory_result = (
            supabase.table("factories")
            .select("id, name, location")
            .in_("id", factory_ids)
            .execute()
        )
        factory_by_id = {
            str(factory["id"]): factory
            for factory in (factory_result.data or [])
        }
    except Exception as error:
        print(f"Customer meter metadata error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve registered meter names",
        )

    with storage_lock:
        stored_readings = dict(latest_meters)

    now = datetime.now(timezone.utc)
    online_cutoff = now - timedelta(seconds=120)
    output: list[dict[str, Any]] = []

    # Return every meter registered to the customer's assigned factories,
    # including meters that have not sent telemetry yet.
    for registered in registered_meters:
        factory_id = str(registered["factory_id"])
        slave_id = int(registered["slave_id"])
        reading = stored_readings.get((factory_id, slave_id), {})
        factory = factory_by_id.get(factory_id, {})
        last_seen = reading.get("last_seen")

        try:
            seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            is_online = seen_at >= online_cutoff
        except (TypeError, ValueError):
            is_online = False

        item: dict[str, Any] = {
            "factory_id": factory_id,
            "factory_name": factory.get("name") or "Unknown factory",
            "factory_location": factory.get("location") or "",
            "site": factory.get("name") or "Unknown factory",
            "slave_id": slave_id,
            "meter_name": registered.get("meter_name") or f"Meter {slave_id}",
            "status": "online" if is_online else "offline",
            "online": is_online,
            "last_seen": last_seen,
            "data_source": reading.get("data_source"),
        }

        # Add the latest reading values without allowing telemetry to
        # override registered identity or factory assignment.
        for key, value in reading.items():
            if key not in {
                "factory_id", "slave_id", "meter_name",
                "last_seen", "data_source", "status", "online",
            }:
                item[key] = value

        output.append(item)

    data_source = next(
        (meter.get("data_source") for meter in output if meter.get("data_source")),
        "SIMULATED",
    )

    return {
        "data_source": data_source,
        "count": len(output),
        "factories": factory_ids,
        "meters": output,
    }

# --------------------------------------------------
# CUSTOMER: HISTORICAL ENERGY ANALYTICS (InfluxDB 2.x)
# --------------------------------------------------
def _influx_client() -> InfluxDBClient:
    if not INFLUXDB_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Energy analytics is not configured. Set INFLUXDB_TOKEN in Render.",
        )
    return InfluxDBClient(
        url=INFLUXDB_URL,
        token=INFLUXDB_TOKEN,
        org=INFLUXDB_ORG,
        timeout=15000,
    )


@app.get("/api/v1/analytics/energy")
def get_energy_analytics(
    days: int = 30,
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    """Return daily cumulative-energy deltas for the signed-in customer's meters."""
    if days < 1 or days > 90:
        raise HTTPException(status_code=400, detail="days must be between 1 and 90")

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    factory_ids = get_assigned_factories(user_id)
    if not factory_ids:
        return {
            "timezone": ANALYTICS_TIMEZONE, "unit": "kWh", "days": days,
            "totals": {"today_kwh": 0, "yesterday_kwh": 0, "month_kwh": 0},
            "daily": [], "meters": [], "note": "No factories are assigned to this customer.",
        }

    try:
        registered_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id, meter_name")
            .in_("factory_id", factory_ids)
            .order("slave_id")
            .execute()
        )
        registered_meters = registered_result.data or []
    except Exception as error:
        print(f"Analytics meter lookup error: {error}")
        raise HTTPException(status_code=503, detail="Unable to retrieve registered meters")

    if not registered_meters:
        return {
            "timezone": ANALYTICS_TIMEZONE, "unit": "kWh", "days": days,
            "totals": {"today_kwh": 0, "yesterday_kwh": 0, "month_kwh": 0},
            "daily": [], "meters": [], "note": "No meters are registered to assigned factories.",
        }

    # The current Influx schema has slave_id as a tag but does not show factory_id.
    # If IDs repeat across factories, add factory_id as an Influx tag to avoid mixing.
    slave_ids = sorted({int(row["slave_id"]) for row in registered_meters})
    slave_filter = " or ".join([f'r["slave_id"] == "{sid}"' for sid in slave_ids])
    query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: -{days + 2}d)
  |> filter(fn: (r) => r["_measurement"] == "pm800_telemetry")
  |> filter(fn: (r) => r["_field"] == "energy_combined")
  |> filter(fn: (r) => r["device"] == "PM800")
  |> filter(fn: (r) => {slave_filter})
  |> keep(columns: ["_time", "_value", "slave_id"])
  |> sort(columns: ["_time"])
'''
    try:
        with _influx_client() as client:
            tables = client.query_api().query(query=query, org=INFLUXDB_ORG)
        points: dict[int, list[tuple[datetime, float]]] = {}
        for table in tables:
            for record in table.records:
                try:
                    sid = int(record.values.get("slave_id"))
                    timestamp = record.get_time()
                    value = float(record.get_value())
                    if timestamp is not None and value == value:
                        points.setdefault(sid, []).append((timestamp, value))
                except (TypeError, ValueError):
                    continue
    except Exception as error:
        print(f"InfluxDB energy analytics query error: {error}")
        raise HTTPException(
            status_code=503,
            detail="Unable to query InfluxDB. Check URL, organization, bucket, token, and schema.",
        )

    try:
        local_tz = ZoneInfo(ANALYTICS_TIMEZONE)
    except Exception:
        local_tz = ZoneInfo("Asia/Kolkata")

    now_local = datetime.now(local_tz)
    start_date = now_local.date() - timedelta(days=days - 1)
    yesterday_date = now_local.date() - timedelta(days=1)
    month_start = now_local.date().replace(day=1)

    meter_rows = []
    daily_totals: dict[str, float] = {}
    today_total = yesterday_total = month_total = 0.0

    for registered in registered_meters:
        sid = int(registered["slave_id"])
        rows = sorted(points.get(sid, []), key=lambda pair: pair[0])
        local_rows: list[tuple[datetime, float]] = []
        for timestamp, value in rows:
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            local_rows.append((timestamp.astimezone(local_tz), value))

        per_day: dict[str, float] = {}
        for offset in range(days):
            day = start_date + timedelta(days=offset)
            next_day = day + timedelta(days=1)
            baseline_values = [v for t, v in local_rows if t.date() < day]
            day_values = [(t, v) for t, v in local_rows if day <= t.date() < next_day]
            if not day_values:
                continue
            # If no prior-day baseline exists, the first sample is only a baseline;
            # do not falsely report it as consumption.
            if not baseline_values:
                continue
            baseline = baseline_values[-1]
            latest = day_values[-1][1]
            delta = latest - baseline
            if delta < 0:  # meter reset or rollover; don't show negative consumption
                delta = 0.0
            per_day[day.isoformat()] = round(delta, 3)
            daily_totals[day.isoformat()] = daily_totals.get(day.isoformat(), 0.0) + delta

        today_kwh = per_day.get(now_local.date().isoformat(), 0.0)
        yesterday_kwh = per_day.get(yesterday_date.isoformat(), 0.0)
        meter_month_kwh = sum(
            value for date_key, value in per_day.items()
            if date.fromisoformat(date_key) >= month_start
        )
        today_total += today_kwh
        yesterday_total += yesterday_kwh
        month_total += meter_month_kwh
        meter_rows.append({
            "factory_id": str(registered["factory_id"]),
            "slave_id": sid,
            "meter_name": registered.get("meter_name") or f"Meter {sid}",
            "today_kwh": round(today_kwh, 3),
            "yesterday_kwh": round(yesterday_kwh, 3),
            "month_kwh": round(meter_month_kwh, 3),
            "samples": len(rows),
            "has_data": bool(rows),
        })

    daily = [
        {"date": (start_date + timedelta(days=offset)).isoformat(),
         "kwh": round(daily_totals.get((start_date + timedelta(days=offset)).isoformat(), 0.0), 3)}
        for offset in range(days)
    ]

    return {
        "timezone": ANALYTICS_TIMEZONE,
        "bucket": INFLUXDB_BUCKET,
        "measurement": "pm800_telemetry",
        "energy_field": "energy_combined",
        "unit": "kWh",
        "days": days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "today_kwh": round(today_total, 3),
            "yesterday_kwh": round(yesterday_total, 3),
            "month_kwh": round(month_total, 3),
        },
        "daily": daily,
        "meters": meter_rows,
        "note": "Assumes energy_combined is cumulative kWh. Verify scaling. Add factory_id as an InfluxDB tag if slave IDs repeat across factories.",
    }
