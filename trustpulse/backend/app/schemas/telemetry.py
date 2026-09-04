"""
TrustPulse AI — Telemetry Schemas (Matching Phase 1 @trustpulse/sdk).

The backend accepts the SDK batch contract and validates it server-side.
Client-provided fields that imply trust (e.g. risk scores) are NOT accepted.
"""

import math
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class EventTypeEnum(str, Enum):
    BEHAVIORAL_BATCH = "behavioral_batch"
    SESSION_START = "session_start"
    SESSION_STOP = "session_stop"
    HEARTBEAT = "heartbeat"


class TypingFeaturesSchema(BaseModel):
    sampleCount: int = Field(default=0, ge=0, le=100_000)
    meanDwellTime: float = Field(default=0.0, ge=0.0, le=5000.0)
    dwellStdDev: float = Field(default=0.0, ge=0.0, le=5000.0)
    meanFlightTime: float = Field(default=0.0, ge=0.0, le=5000.0)
    flightStdDev: float = Field(default=0.0, ge=0.0, le=5000.0)
    typingSpeed: float = Field(default=0.0, ge=0.0, le=50.0)
    pauseRate: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator(
        "meanDwellTime", "dwellStdDev", "meanFlightTime", "flightStdDev", "typingSpeed", "pauseRate"
    )
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/Infinity not allowed")
        return v


class MouseFeaturesSchema(BaseModel):
    sampleCount: int = Field(default=0, ge=0, le=100_000)
    meanVelocity: float = Field(default=0.0, ge=0.0, le=50_000.0)
    velocityStdDev: float = Field(default=0.0, ge=0.0, le=50_000.0)
    meanAcceleration: float = Field(default=0.0, ge=0.0, le=500_000.0)
    directionChangeRate: float = Field(default=0.0, ge=0.0, le=100.0)
    movementDuration: float = Field(default=0.0, ge=0.0, le=60_000.0)
    totalDistance: float = Field(default=0.0, ge=0.0, le=1_000_000.0)

    @field_validator(
        "meanVelocity",
        "velocityStdDev",
        "meanAcceleration",
        "directionChangeRate",
        "movementDuration",
        "totalDistance",
    )
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/Infinity not allowed")
        return v


class ClickFeaturesSchema(BaseModel):
    clickCount: int = Field(default=0, ge=0, le=100_000)
    doubleClickCount: int = Field(default=0, ge=0, le=100_000)
    meanInterval: float = Field(default=0.0, ge=0.0, le=60_000.0)
    intervalStdDev: float = Field(default=0.0, ge=0.0, le=60_000.0)
    clickFrequency: float = Field(default=0.0, ge=0.0, le=1000.0)

    @field_validator("meanInterval", "intervalStdDev", "clickFrequency")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/Infinity not allowed")
        return v


class ScrollFeaturesSchema(BaseModel):
    scrollEventCount: int = Field(default=0, ge=0, le=100_000)
    totalDistance: float = Field(default=0.0, ge=0.0, le=10_000_000.0)
    meanVelocity: float = Field(default=0.0, ge=0.0, le=100_000.0)
    meanPauseDuration: float = Field(default=0.0, ge=0.0, le=60_000.0)

    @field_validator("totalDistance", "meanVelocity", "meanPauseDuration")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/Infinity not allowed")
        return v


class TouchFeaturesSchema(BaseModel):
    touchCount: int = Field(default=0, ge=0, le=100_000)
    meanDuration: float = Field(default=0.0, ge=0.0, le=10_000.0)
    meanVelocity: float = Field(default=0.0, ge=0.0, le=100_000.0)
    directionDistribution: Dict[str, int] = Field(default_factory=dict)

    @field_validator("meanDuration", "meanVelocity")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/Infinity not allowed")
        return v

    @field_validator("directionDistribution")
    @classmethod
    def validate_directions(cls, v: Dict[str, int]) -> Dict[str, int]:
        allowed = {"tap", "up", "down", "left", "right"}
        for key, val in v.items():
            if key not in allowed:
                raise ValueError(f"Unknown touch direction '{key}'")
            if not isinstance(val, int) or isinstance(val, bool):
                raise ValueError("Direction distribution values must be integers")
            if val < 0 or val > 1_000_000:
                raise ValueError("Direction distribution out of range")
        return v


class UserAgentSummarySchema(BaseModel):
    browser: str = Field(default="Other", max_length=64)
    os: str = Field(default="Other", max_length=64)


class ScreenSchema(BaseModel):
    width: float = Field(default=0.0, ge=0.0, le=100_000.0)
    height: float = Field(default=0.0, ge=0.0, le=100_000.0)
    colorDepth: float = Field(default=0.0, ge=0.0, le=128.0)
    pixelRatio: float = Field(default=1.0, ge=0.0, le=10.0)


class DeviceEnvironmentSchema(BaseModel):
    timezoneOffset: float = Field(default=0.0, ge=-24.0 * 60.0, le=24.0 * 60.0)
    timezone: Optional[str] = Field(None, max_length=128)
    language: str = Field(default="unknown", max_length=64)
    languages: List[str] = Field(default_factory=list, max_length=32)
    touchSupport: bool = Field(default=False)
    maxTouchPoints: int = Field(default=0, ge=0, le=128)
    hardwareConcurrency: Optional[int] = Field(None, ge=1, le=512)


class DeviceContextSchema(BaseModel):
    userAgentSummary: UserAgentSummarySchema = Field(default_factory=UserAgentSummarySchema)
    screen: ScreenSchema = Field(default_factory=ScreenSchema)
    environment: DeviceEnvironmentSchema = Field(default_factory=DeviceEnvironmentSchema)


class ExtractedFeaturePayloadSchema(BaseModel):
    feature_schema_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    typing: Optional[TypingFeaturesSchema] = None
    mouse: Optional[MouseFeaturesSchema] = None
    click: Optional[ClickFeaturesSchema] = None
    scroll: Optional[ScrollFeaturesSchema] = None
    touch: Optional[TouchFeaturesSchema] = None
    device: Optional[DeviceContextSchema] = None


class TelemetryPacketMetadataSchema(BaseModel):
    pageContext: Optional[str] = Field(None, max_length=512)
    pageVisibility: Optional[str] = Field(None, max_length=32)


class TelemetryPacketSchema(BaseModel):
    sessionId: str = Field(..., min_length=1, max_length=128)
    sdkInstanceId: str = Field(..., min_length=1, max_length=64)
    eventId: str = Field(..., min_length=1, max_length=64)
    sequenceNumber: int = Field(..., ge=1, le=9_000_000_000)
    timestamp: int = Field(..., ge=0, description="Epoch timestamp in ms")
    schemaVersion: str = Field(default="1.0.0", min_length=1, max_length=32)
    sdkVersion: str = Field(default="1.0.0", min_length=1, max_length=32)
    eventType: EventTypeEnum = EventTypeEnum.BEHAVIORAL_BATCH
    features: ExtractedFeaturePayloadSchema
    metadata: Optional[TelemetryPacketMetadataSchema] = None
    integrity: Optional[str] = Field(None, max_length=128)


class TelemetryBatchSchema(BaseModel):
    batchId: str = Field(..., min_length=1, max_length=64)
    sentAt: int = Field(..., ge=0)
    packets: List[TelemetryPacketSchema] = Field(..., min_length=1, max_length=100)


class TelemetryPacketResult(BaseModel):
    event_id: str
    status: str  # ACCEPTED, REJECTED
    reason: Optional[str] = None


class TelemetryIngestionResponse(BaseModel):
    status: str = "accepted"
    batch_id: str
    received_packets: int
    accepted_packets: int
    rejected_packets: int
    results: List[TelemetryPacketResult] = Field(default_factory=list)
