import os
import hmac
from datetime import datetime, timezone, timedelta
from threading import Lock
from functools import lru_cache
from typing import Any
from uuid import UUID
import math
import traceback

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

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)


# --------------------------------------------------
# ALARM CONFIGURATION
# These are safe starting examples; tune per meter/site in Render env vars.
# --------------------------------------------------
HIGH_CURRENT_LIMIT_A = float(os.getenv("HIGH_CURRENT_LIMIT_A", "100"))
LOW_VOLTAGE_LIMIT_V = float(os.getenv("LOW_VOLTAGE_LIMIT_V", "200"))
HIGH_VOLTAGE_LIMIT_V = float(os.getenv("HIGH_VOLTAGE_LIMIT_V", "250"))
METER_OFFLINE_SECONDS = int(os.getenv("METER_OFFLINE_SECONDS", "120"))


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
    allow_methods=["GET", "POST", "PUT", "DELETE"],
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


class UpdateCustomerRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=1, max_length=120)


class UpdateFactoryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=200)
    customer_user_id: str = Field(min_length=1, max_length=100)


class AlarmSettingsRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    factory_id: str = Field(min_length=1, max_length=100)
    scope: str = Field(pattern="^(factory|meter)$")
    slave_id: int | None = Field(default=None, ge=1, le=247)
    high_current_limit_a: float = Field(gt=0, le=100000)
    low_voltage_limit_v: float = Field(ge=0, le=100000)
    high_voltage_limit_v: float = Field(gt=0, le=100000)
    meter_offline_seconds: int = Field(ge=15, le=86400)


class UpdateMeterRequest(BaseModel):
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
# ALARM ENGINE HELPERS
# --------------------------------------------------
def _numeric_reading(reading: dict[str, Any], *keys: str) -> float | None:
    """Read a numeric telemetry field, accepting common key spellings."""
    for key in keys:
        value = reading.get(key)
        if value is None:
            continue
        try:
            number = float(value)
            if math.isfinite(number):
                return number
        except (TypeError, ValueError):
            continue
    return None


def _set_alarm_condition(
    factory_id: str,
    slave_id: int,
    meter_name: str,
    alarm_type: str,
    message: str,
    measured_value: float | None,
    threshold_value: float | None,
    triggered: bool,
) -> None:
    """
    Maintain one open alarm per factory/meter/type.
    Active or acknowledged alarms are not duplicated; normal readings resolve them.
    """
    query = (
        supabase.table("alarms")
        .select("id, status")
        .eq("factory_id", factory_id)
        .eq("slave_id", slave_id)
        .eq("alarm_type", alarm_type)
        .in_("status", ["active", "acknowledged"])
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    existing = (query.data or [None])[0]

    if triggered and existing is None:
        supabase.table("alarms").insert({
            "factory_id": factory_id,
            "slave_id": slave_id,
            "meter_name": meter_name,
            "alarm_type": alarm_type,
            "message": message,
            "measured_value": measured_value,
            "threshold_value": threshold_value,
            "status": "active",
        }).execute()
    elif triggered and existing is not None:
        # Refresh the latest value/message without creating duplicate rows.
        supabase.table("alarms").update({
            "meter_name": meter_name,
            "message": message,
            "measured_value": measured_value,
            "threshold_value": threshold_value,
        }).eq("id", existing["id"]).execute()
    elif not triggered and existing is not None:
        supabase.table("alarms").update({
            "status": "resolved",
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "measured_value": measured_value,
        }).eq("id", existing["id"]).execute()


def get_effective_alarm_settings(factory_id: str, slave_id: int | None = None) -> dict[str, Any]:
    """Return meter override, then factory defaults, then Render environment defaults."""
    settings = {
        "high_current_limit_a": HIGH_CURRENT_LIMIT_A,
        "low_voltage_limit_v": LOW_VOLTAGE_LIMIT_V,
        "high_voltage_limit_v": HIGH_VOLTAGE_LIMIT_V,
        "meter_offline_seconds": METER_OFFLINE_SECONDS,
    }
    try:
        result = (
            supabase.table("alarm_settings")
            .select("factory_id, slave_id, high_current_limit_a, low_voltage_limit_v, high_voltage_limit_v, meter_offline_seconds")
            .eq("factory_id", factory_id)
            .execute()
        )
        rows = result.data or []
        factory_row = next((row for row in rows if row.get("slave_id") is None), None)
        meter_row = next((row for row in rows if slave_id is not None and row.get("slave_id") is not None and int(row["slave_id"]) == int(slave_id)), None)
        for row in (factory_row, meter_row):
            if row:
                for key in settings:
                    if row.get(key) is not None:
                        settings[key] = row[key]
    except Exception as error:
        # Missing migration/table must not crash telemetry; environment defaults remain active.
        print(f"Alarm settings lookup failed; using defaults: {error}")
    return settings


def evaluate_reading_alarms(factory_id: str, reading: dict[str, Any]) -> None:
    """Evaluate current and voltage alarms using meter override/factory/default limits."""
    slave_id = int(reading["slave_id"])
    meter_name = str(reading.get("meter_name") or f"Meter {slave_id}")
    limits = get_effective_alarm_settings(factory_id, slave_id)
    high_current_limit = float(limits["high_current_limit_a"])
    low_voltage_limit = float(limits["low_voltage_limit_v"])
    high_voltage_limit = float(limits["high_voltage_limit_v"])

    current = _numeric_reading(reading, "current", "current_a", "current_A", "amps", "Current")
    if current is not None:
        _set_alarm_condition(
            factory_id, slave_id, meter_name, "HIGH_CURRENT",
            f"{meter_name}: current {current:g} A exceeds limit {high_current_limit:g} A",
            current, high_current_limit, current > high_current_limit,
        )

    voltage = _numeric_reading(reading, "voltage", "voltage_v", "voltage_V", "Voltage")
    if voltage is not None:
        _set_alarm_condition(
            factory_id, slave_id, meter_name, "LOW_VOLTAGE",
            f"{meter_name}: voltage {voltage:g} V is below limit {low_voltage_limit:g} V",
            voltage, low_voltage_limit, voltage < low_voltage_limit,
        )
        _set_alarm_condition(
            factory_id, slave_id, meter_name, "HIGH_VOLTAGE",
            f"{meter_name}: voltage {voltage:g} V exceeds limit {high_voltage_limit:g} V",
            voltage, high_voltage_limit, voltage > high_voltage_limit,
        )


def refresh_offline_alarms(factory_ids: list[str]) -> None:
    """
    Reconcile offline alarms for the supplied factories.
    This runs when an authorized alarm-list request is made; it is not a background
    scheduler, so a future periodic worker is needed for time-triggered alerts/emails.
    """
    if not factory_ids:
        return
    registered_result = (
        supabase.table("factory_meters")
        .select("factory_id, slave_id, meter_name")
        .in_("factory_id", factory_ids)
        .execute()
    )
    registered = registered_result.data or []
    with storage_lock:
        readings = dict(latest_meters)

    now = datetime.now(timezone.utc)
    for meter in registered:
        factory_id = str(meter["factory_id"])
        slave_id = int(meter["slave_id"])
        meter_name = str(meter.get("meter_name") or f"Meter {slave_id}")
        limits = get_effective_alarm_settings(factory_id, slave_id)
        offline_seconds = int(limits["meter_offline_seconds"])
        cutoff = now - timedelta(seconds=offline_seconds)
        reading = readings.get((factory_id, slave_id), {})
        last_seen = reading.get("last_seen")
        try:
            seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            offline = seen_at < cutoff
        except (TypeError, ValueError):
            offline = True

        _set_alarm_condition(
            factory_id, slave_id, meter_name, "METER_OFFLINE",
            (f"{meter_name}: no telemetry received for at least "
             f"{offline_seconds} seconds"),
            None, float(offline_seconds), offline,
        )


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
        print(f"Dashboard statistics error: {type(error).__name__}: {error}")
        traceback.print_exc()
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
        print(f"List factories error: {type(error).__name__}: {error}")
        traceback.print_exc()
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
        print(f"List meters error: {type(error).__name__}: {error}")
        traceback.print_exc()
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve meters. Check factory_meters and factories tables.",
        )



# --------------------------------------------------
# ADMIN: UPDATE CUSTOMER / FACTORY / METER
# --------------------------------------------------
@app.put("/api/v1/admin/customers/{customer_id}")
def update_admin_customer(
    customer_id: str,
    request: UpdateCustomerRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    customer_id = validate_uuid(customer_id, "customer ID")
    full_name = request.full_name.strip()
    email = request.email.strip().lower()
    if not full_name or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid customer name and email are required")
    try:
        profile = (supabase.table("profiles").select("id, role")
                   .eq("id", customer_id).maybe_single().execute()).data
        if not profile or profile.get("role") != "customer":
            raise HTTPException(status_code=404, detail="Customer not found")
        # Email belongs to Supabase Auth; keep profile name in sync as well.
        supabase.auth.admin.update_user_by_id(
            customer_id,
            {"email": email, "user_metadata": {"full_name": full_name}},
        )
        supabase.table("profiles").update({"full_name": full_name}).eq("id", customer_id).eq("role", "customer").execute()
        return {"status": "success", "message": "Customer details updated"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Update customer error: {error}")
        raise HTTPException(status_code=400, detail="Unable to update customer. Check email uniqueness and Supabase Auth configuration.")


@app.put("/api/v1/admin/factories/{factory_id}")
def update_admin_factory(
    factory_id: str,
    request: UpdateFactoryRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    factory_id = validate_uuid(factory_id, "factory ID")
    name = request.name.strip()
    location = request.location.strip()
    customer_user_id = validate_uuid(request.customer_user_id.strip(), "customer user ID")
    if not name or not location:
        raise HTTPException(status_code=400, detail="Factory name and location are required")
    try:
        existing = (supabase.table("factories").select("id")
                    .eq("id", factory_id).maybe_single().execute()).data
        if not existing:
            raise HTTPException(status_code=404, detail="Factory not found")
        customer = (supabase.table("profiles").select("id, role")
                    .eq("id", customer_user_id).maybe_single().execute()).data
        if not customer or customer.get("role") != "customer":
            raise HTTPException(status_code=400, detail="A valid customer account is required")
        supabase.table("factories").update({"name": name, "location": location}).eq("id", factory_id).execute()
        assignments = (supabase.table("factory_users").select("user_id")
                      .eq("factory_id", factory_id).execute()).data or []
        assigned_ids = {str(row.get("user_id")) for row in assignments}
        if customer_user_id not in assigned_ids or len(assigned_ids) != 1:
            supabase.table("factory_users").delete().eq("factory_id", factory_id).execute()
            supabase.table("factory_users").insert({"factory_id": factory_id, "user_id": customer_user_id}).execute()
        return {"status": "success", "message": "Factory details and customer assignment updated"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Update factory error: {error}")
        raise HTTPException(status_code=503, detail="Unable to update factory or customer assignment")


@app.put("/api/v1/admin/meters/{factory_id}/{slave_id}")
def update_admin_meter(
    factory_id: str,
    slave_id: int,
    request: UpdateMeterRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    old_factory_id = validate_uuid(factory_id, "factory ID")
    new_factory_id = validate_uuid(request.factory_id.strip(), "factory ID")
    if not 1 <= slave_id <= 247:
        raise HTTPException(status_code=400, detail="Invalid current slave ID")
    new_slave_id = request.slave_id
    meter_name = request.meter_name.strip()
    if not meter_name:
        raise HTTPException(status_code=400, detail="Meter name is required")
    try:
        existing = (supabase.table("factory_meters").select("factory_id, slave_id, meter_name")
                    .eq("factory_id", old_factory_id).eq("slave_id", slave_id).execute()).data
        if not existing:
            raise HTTPException(status_code=404, detail="Meter registration not found")
        target_factory = (supabase.table("factories").select("id")
                          .eq("id", new_factory_id).maybe_single().execute()).data
        if not target_factory:
            raise HTTPException(status_code=404, detail="Target factory not found")
        same_key = old_factory_id == new_factory_id and slave_id == new_slave_id
        if not same_key:
            duplicate = (supabase.table("factory_meters").select("factory_id, slave_id")
                         .eq("factory_id", new_factory_id).eq("slave_id", new_slave_id).execute()).data
            if duplicate:
                raise HTTPException(status_code=409, detail="That slave ID is already registered in the selected factory")
            # Insert new registration first; only remove the old one after insert succeeds.
            supabase.table("factory_meters").insert({"factory_id": new_factory_id, "slave_id": new_slave_id, "meter_name": meter_name}).execute()
            supabase.table("factory_meters").delete().eq("factory_id", old_factory_id).eq("slave_id", slave_id).execute()
            with storage_lock:
                old_reading = latest_meters.pop((old_factory_id, slave_id), None)
                if old_reading is not None:
                    old_reading["factory_id"] = new_factory_id
                    old_reading["slave_id"] = new_slave_id
                    old_reading["meter_name"] = meter_name
                    latest_meters[(new_factory_id, new_slave_id)] = old_reading
        else:
            supabase.table("factory_meters").update({"meter_name": meter_name}).eq("factory_id", old_factory_id).eq("slave_id", slave_id).execute()
            with storage_lock:
                reading = latest_meters.get((old_factory_id, slave_id))
                if reading is not None:
                    reading["meter_name"] = meter_name
        return {"status": "success", "message": "Meter registration updated"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Update meter error: {error}")
        raise HTTPException(status_code=503, detail="Unable to update meter registration")


# --------------------------------------------------
# ADMIN: DELETE CUSTOMER / FACTORY / METER
# --------------------------------------------------
# Safety policy: do not cascade-delete factories or meters unexpectedly.
# Delete child records explicitly before deleting their parent.
@app.delete("/api/v1/admin/meters/{factory_id}/{slave_id}")
def delete_admin_meter(
    factory_id: str,
    slave_id: int,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    factory_id = validate_uuid(factory_id, "factory ID")
    if not 1 <= slave_id <= 247:
        raise HTTPException(status_code=400, detail="Invalid slave ID")
    try:
        existing = (supabase.table("factory_meters").select("slave_id")
                    .eq("factory_id", factory_id).eq("slave_id", slave_id).execute())
        if not existing.data:
            raise HTTPException(status_code=404, detail="Meter not found")
        supabase.table("factory_meters").delete().eq("factory_id", factory_id).eq("slave_id", slave_id).execute()
        with storage_lock:
            latest_meters.pop((factory_id, slave_id), None)
        return {"status": "success", "message": "Meter deleted"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Delete meter error: {error}")
        raise HTTPException(status_code=503, detail="Unable to delete meter")


@app.delete("/api/v1/admin/factories/{factory_id}")
def delete_admin_factory(
    factory_id: str,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    factory_id = validate_uuid(factory_id, "factory ID")
    try:
        existing = (supabase.table("factories").select("id")
                    .eq("id", factory_id).execute())
        if not existing.data:
            raise HTTPException(status_code=404, detail="Factory not found")
        meters = (supabase.table("factory_meters").select("slave_id")
                  .eq("factory_id", factory_id).limit(1).execute())
        if meters.data:
            raise HTTPException(status_code=409, detail="Delete this factory's meters first")
        # Remove access assignments before deleting the factory.
        supabase.table("factory_users").delete().eq("factory_id", factory_id).execute()
        supabase.table("factories").delete().eq("id", factory_id).execute()
        with storage_lock:
            for key in list(latest_meters):
                if key[0] == factory_id:
                    latest_meters.pop(key, None)
        return {"status": "success", "message": "Factory deleted"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Delete factory error: {error}")
        raise HTTPException(status_code=503, detail="Unable to delete factory; verify dependent records")


@app.delete("/api/v1/admin/customers/{customer_id}")
def delete_admin_customer(
    customer_id: str,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    customer_id = validate_uuid(customer_id, "customer ID")
    try:
        profile = (supabase.table("profiles").select("id, role")
                   .eq("id", customer_id).maybe_single().execute()).data
        if not profile or profile.get("role") != "customer":
            raise HTTPException(status_code=404, detail="Customer not found")
        assigned = (supabase.table("factory_users").select("factory_id")
                    .eq("user_id", customer_id).limit(1).execute())
        if assigned.data:
            raise HTTPException(status_code=409, detail="Delete or reassign this customer's factories first")
        # Auth deletion removes login access. Depending on database FK settings,
        # profile may cascade-delete or need separate cleanup.
        supabase.auth.admin.delete_user(customer_id)
        supabase.table("profiles").delete().eq("id", customer_id).eq("role", "customer").execute()
        return {"status": "success", "message": "Customer account deleted"}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Delete customer error: {error}")
        raise HTTPException(status_code=503, detail="Unable to delete customer; inspect Supabase Auth and profile constraints")


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
            .select("slave_id, meter_name")
            .eq("factory_id", factory_id)
            .execute()
        )
        registered_rows = registered_result.data or []
        registered_ids = {int(row["slave_id"]) for row in registered_rows}
        meter_names = {
            int(row["slave_id"]): str(row.get("meter_name") or f"Meter {row['slave_id']}")
            for row in registered_rows
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
        reading["meter_name"] = meter_names.get(slave_id, f"Meter {slave_id}")
        reading["data_source"] = payload.data_source
        reading["last_seen"] = datetime.now(timezone.utc).isoformat()
        normalized_readings.append(reading)

    with storage_lock:
        for reading in normalized_readings:
            key = (factory_id, int(reading["slave_id"]))
            latest_meters[key] = reading

    # Alarm database failures must be visible to logs, but must not silently
    # invalidate telemetry that has already been accepted into memory.
    for reading in normalized_readings:
        try:
            evaluate_reading_alarms(factory_id, reading)
        except Exception as error:
            print(f"Alarm evaluation failed for factory={factory_id}, "
                  f"slave_id={reading.get('slave_id')}: {error}")

    return {
        "status": "success",
        "message": "Telemetry received",
        "factory_id": factory_id,
        "count": len(normalized_readings),
        "data_source": payload.data_source,
    }




# --------------------------------------------------
# CUSTOMER: FACTORIES AND REGISTERED METERS (INCLUDING OFFLINE METERS)
# --------------------------------------------------
@app.get("/api/v1/customer/factories")
def get_customer_factories(
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    """
    Return all factories assigned to the logged-in customer, including factories
    and registered meters that have never sent telemetry or are currently offline.
    """
    user_id = str(claims.get("sub") or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    factory_ids = get_assigned_factories(user_id)
    if not factory_ids:
        return {"factories": [], "count": 0, "meter_count": 0}

    try:
        factories_result = (
            supabase.table("factories")
            .select("id, name, location, created_at")
            .in_("id", factory_ids)
            .order("created_at", desc=True)
            .execute()
        )
        factory_rows = factories_result.data or []

        meters_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id, meter_name")
            .in_("factory_id", factory_ids)
            .order("slave_id")
            .execute()
        )
        registered_meters = meters_result.data or []

        with storage_lock:
            readings_by_key = dict(latest_meters)

        now = datetime.now(timezone.utc)
        online_cutoff = now - timedelta(seconds=120)
        meters_by_factory: dict[str, list[dict[str, Any]]] = {
            str(factory_id): [] for factory_id in factory_ids
        }

        for registered in registered_meters:
            factory_id = str(registered["factory_id"])
            slave_id = int(registered["slave_id"])
            reading = readings_by_key.get((factory_id, slave_id), {})
            last_seen = reading.get("last_seen")
            try:
                seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
                is_online = seen_at >= online_cutoff
            except (TypeError, ValueError):
                is_online = False

            meter = {
                "factory_id": factory_id,
                "slave_id": slave_id,
                "meter_name": registered.get("meter_name") or f"Meter {slave_id}",
                "status": "online" if is_online else "offline",
                "online": is_online,
                "last_seen": last_seen,
            }
            for key, value in reading.items():
                if key not in {"factory_id", "slave_id", "meter_name", "last_seen", "data_source"}:
                    meter[key] = value
            meters_by_factory.setdefault(factory_id, []).append(meter)

        output = []
        for factory in factory_rows:
            factory_id = str(factory["id"])
            factory_meters = meters_by_factory.get(factory_id, [])
            output.append({
                "id": factory_id,
                "name": factory.get("name") or "Unnamed factory",
                "location": factory.get("location") or "",
                "created_at": factory.get("created_at"),
                "meters": factory_meters,
                "meter_count": len(factory_meters),
                "online_meters": sum(1 for meter in factory_meters if meter["online"]),
                "offline_meters": sum(1 for meter in factory_meters if not meter["online"]),
                "energy_total": sum(
                    float(meter.get("energy", meter.get("energy_kwh", 0)) or 0)
                    for meter in factory_meters
                    if _numeric_reading(meter, "energy", "energy_kwh", "kwh", "active_energy") is not None
                ),
            })

        return {
            "factories": output,
            "count": len(output),
            "meter_count": sum(factory["meter_count"] for factory in output),
        }
    except HTTPException:
        raise
    except Exception as error:
        print(f"Customer factories error: {type(error).__name__}: {error}")
        traceback.print_exc()
        raise HTTPException(status_code=503, detail="Unable to retrieve assigned factories and registered meters")


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

    factory_meter_map = get_factory_meter_map(factory_ids)

    with storage_lock:
        stored_readings = list(latest_meters.values())

    # Match on BOTH factory_id and slave_id. Never filter by slave ID alone.
    filtered_meters = [
        reading
        for reading in stored_readings
        if reading.get("factory_id") in factory_ids
        and int(reading.get("slave_id", 0)) in factory_meter_map.get(
            str(reading.get("factory_id")), set()
        )
    ]

    data_source = (
        filtered_meters[0].get("data_source", "NODE_RED")
        if filtered_meters
        else "SIMULATED"
    )

    return {
        "data_source": data_source,
        "count": len(filtered_meters),
        "factories": factory_ids,
        "meters": filtered_meters,
    }

# --------------------------------------------------
# ADMIN: ALARM THRESHOLD CONFIGURATION
# --------------------------------------------------
@app.get("/api/v1/admin/alarm-settings")
def list_alarm_settings(
    factory_id: str,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List configured factory defaults and meter-specific overrides."""
    factory_id = validate_uuid(factory_id, "factory ID")
    try:
        factory_result = supabase.table("factories").select("id, name").eq("id", factory_id).maybe_single().execute()
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")
        settings_result = (
            supabase.table("alarm_settings")
            .select("id, factory_id, slave_id, high_current_limit_a, low_voltage_limit_v, high_voltage_limit_v, meter_offline_seconds, updated_at")
            .eq("factory_id", factory_id)
            .order("slave_id")
            .execute()
        )
        meters_result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id, meter_name")
            .eq("factory_id", factory_id)
            .order("slave_id")
            .execute()
        )
        return {
            "factory": factory_result.data,
            "settings": settings_result.data or [],
            "meters": meters_result.data or [],
            "environment_defaults": {
                "high_current_limit_a": HIGH_CURRENT_LIMIT_A,
                "low_voltage_limit_v": LOW_VOLTAGE_LIMIT_V,
                "high_voltage_limit_v": HIGH_VOLTAGE_LIMIT_V,
                "meter_offline_seconds": METER_OFFLINE_SECONDS,
            },
        }
    except HTTPException:
        raise
    except Exception as error:
        print(f"List alarm settings error: {type(error).__name__}: {error}")
        traceback.print_exc()
        raise HTTPException(status_code=503, detail="Unable to retrieve alarm settings. Run the alarm_settings SQL migration first.")


@app.put("/api/v1/admin/alarm-settings")
def save_alarm_settings(
    request: AlarmSettingsRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Create or update a factory-wide default or a meter-specific override."""
    factory_id = validate_uuid(request.factory_id, "factory ID")
    if request.low_voltage_limit_v >= request.high_voltage_limit_v:
        raise HTTPException(status_code=400, detail="Low voltage limit must be lower than high voltage limit")
    if request.scope == "factory" and request.slave_id is not None:
        raise HTTPException(status_code=400, detail="Factory-wide settings must not include a slave ID")
    if request.scope == "meter" and request.slave_id is None:
        raise HTTPException(status_code=400, detail="Select a meter for meter-specific settings")
    try:
        factory_result = supabase.table("factories").select("id").eq("id", factory_id).maybe_single().execute()
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")
        if request.scope == "meter":
            meter_result = (supabase.table("factory_meters").select("slave_id")
                            .eq("factory_id", factory_id).eq("slave_id", request.slave_id)
                            .maybe_single().execute())
            if not meter_result.data:
                raise HTTPException(status_code=404, detail="Meter is not registered to this factory")
        row = {
            "factory_id": factory_id,
            "slave_id": request.slave_id if request.scope == "meter" else None,
            "high_current_limit_a": request.high_current_limit_a,
            "low_voltage_limit_v": request.low_voltage_limit_v,
            "high_voltage_limit_v": request.high_voltage_limit_v,
            "meter_offline_seconds": request.meter_offline_seconds,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        query = supabase.table("alarm_settings").select("id").eq("factory_id", factory_id)
        query = query.eq("slave_id", request.slave_id) if request.scope == "meter" else query.is_("slave_id", "null")
        existing_result = query.maybe_single().execute()
        if existing_result.data:
            saved_result = supabase.table("alarm_settings").update(row).eq("id", existing_result.data["id"]).execute()
        else:
            saved_result = supabase.table("alarm_settings").insert(row).execute()
        saved = (saved_result.data or [row])[0]
        return {"status": "success", "message": "Alarm thresholds saved", "settings": saved}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Save alarm settings error: {error}")
        raise HTTPException(status_code=503, detail="Unable to save alarm settings. Check the alarm_settings table and migration.")


@app.delete("/api/v1/admin/alarm-settings")
def delete_alarm_settings(
    factory_id: str,
    scope: str,
    slave_id: int | None = None,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Delete an override so thresholds fall back to the factory/default values."""
    factory_id = validate_uuid(factory_id, "factory ID")
    if scope not in {"factory", "meter"}:
        raise HTTPException(status_code=400, detail="Scope must be factory or meter")
    if scope == "meter" and slave_id is None:
        raise HTTPException(status_code=400, detail="Meter slave ID is required")
    if scope == "factory" and slave_id is not None:
        raise HTTPException(status_code=400, detail="Factory scope must not include a slave ID")
    try:
        query = supabase.table("alarm_settings").delete().eq("factory_id", factory_id)
        query = query.eq("slave_id", slave_id) if scope == "meter" else query.is_("slave_id", "null")
        query.execute()
        return {"status": "success", "message": "Custom thresholds removed; inherited defaults now apply"}
    except Exception as error:
        print(f"Delete alarm settings error: {error}")
        raise HTTPException(status_code=503, detail="Unable to remove custom alarm settings")


# --------------------------------------------------
# ALARMS: ADMIN LIST / CUSTOMER LIST / ACKNOWLEDGE
# --------------------------------------------------
@app.get("/api/v1/admin/alarms")
def list_admin_alarms(
    status: str | None = None,
    factory_id: str | None = None,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List alarm records for admins; reconcile meter-offline state first."""
    try:
        if factory_id:
            factory_id = validate_uuid(factory_id, "factory ID")
            factory_ids = [factory_id]
        else:
            result = supabase.table("factories").select("id").execute()
            factory_ids = [str(row["id"]) for row in (result.data or [])]
        refresh_offline_alarms(factory_ids)
        query = supabase.table("alarms").select("*").in_("factory_id", factory_ids)
        if status:
            if status not in {"active", "acknowledged", "resolved"}:
                raise HTTPException(status_code=400, detail="Invalid alarm status")
            query = query.eq("status", status)
        result = query.order("created_at", desc=True).limit(500).execute()
        return {"alarms": result.data or [], "count": len(result.data or [])}
    except HTTPException:
        raise
    except Exception as error:
        print(f"List admin alarms error: {error}")
        raise HTTPException(status_code=503, detail="Unable to retrieve alarms")


@app.get("/api/v1/alarms")
def list_customer_alarms(
    status: str | None = None,
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    """Return alarms only for factories assigned to the logged-in customer."""
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")
    factory_ids = get_assigned_factories(str(user_id))
    try:
        refresh_offline_alarms(factory_ids)
        if not factory_ids:
            return {"alarms": [], "count": 0}
        query = supabase.table("alarms").select("*").in_("factory_id", factory_ids)
        if status:
            if status not in {"active", "acknowledged", "resolved"}:
                raise HTTPException(status_code=400, detail="Invalid alarm status")
            query = query.eq("status", status)
        result = query.order("created_at", desc=True).limit(500).execute()
        return {"alarms": result.data or [], "count": len(result.data or [])}
    except HTTPException:
        raise
    except Exception as error:
        print(f"List customer alarms error: {error}")
        raise HTTPException(status_code=503, detail="Unable to retrieve alarms")


@app.post("/api/v1/alarms/{alarm_id}/acknowledge")
def acknowledge_alarm(
    alarm_id: str,
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    """Allow admin or a customer assigned to the alarm's factory to acknowledge it."""
    alarm_id = validate_uuid(alarm_id, "alarm ID")
    user_id = str(claims.get("sub") or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")
    try:
        alarm_result = (
            supabase.table("alarms").select("id, factory_id, status")
            .eq("id", alarm_id).maybe_single().execute()
        )
        alarm = alarm_result.data
        if not alarm:
            raise HTTPException(status_code=404, detail="Alarm not found")

        profile_result = (
            supabase.table("profiles").select("role")
            .eq("id", user_id).maybe_single().execute()
        )
        profile = profile_result.data or {}
        is_admin = profile.get("role") == "admin"
        if not is_admin and str(alarm["factory_id"]) not in get_assigned_factories(user_id):
            raise HTTPException(status_code=403, detail="You do not have access to this alarm")
        if alarm["status"] == "resolved":
            raise HTTPException(status_code=409, detail="Resolved alarms cannot be acknowledged")
        updated = (
            supabase.table("alarms").update({
                "status": "acknowledged",
                "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", alarm_id).execute()
        )
        return {"status": "success", "message": "Alarm acknowledged",
                "alarm": (updated.data or [None])[0]}
    except HTTPException:
        raise
    except Exception as error:
        print(f"Acknowledge alarm error: {error}")
        raise HTTPException(status_code=503, detail="Unable to acknowledge alarm")
