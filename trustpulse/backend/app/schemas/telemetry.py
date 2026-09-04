"""
TrustPulse AI - Telemetry Schemas (Matching Phase 1 @trustpulse/sdk)
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
import math


class TypingFeaturesSchema(BaseModel):
    sampleCount: int = Field(default=0, ge=0)
    meanDwellTime: float = Field(default=0.0, ge=0.0)
    dwellStdDev: float = Field(default=0.0, ge=0.0)
    meanFlightTime: float = Field(default=0.0, ge=0.0)
    flightStdDev: float = Field(default=0.0, ge=0.0)
    typingSpeed: float = Field(default=0.0, ge=0.0)
    pauseRate: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("meanDwellTime", "dwellStdDev", "meanFlightTime", "flightStdDev", "typingSpeed", "pauseRate")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return v


class MouseFeaturesSchema(BaseModel):
    sampleCount: int = Field(default=0, ge=0)
    meanVelocity: float = Field(default=0.0, ge=0.0)
    velocityStdDev: float = Field(default=0.0, ge=0.0)
    meanAcceleration: float = Field(default=0.0, ge=0.0)
    directionChangeRate: float = Field(default=0.0, ge=0.0)
    movementDuration: float = Field(default=0.0, ge=0.0)
    totalDistance: float = Field(default=0.0, ge=0.0)

    @field_validator("meanVelocity", "velocityStdDev", "meanAcceleration", "directionChangeRate", "movementDuration", "totalDistance")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return v


class ClickFeaturesSchema(BaseModel):
    clickCount: int = Field(default=0, ge=0)
    doubleClickCount: int = Field(default=0, ge=0)
    meanInterval: float = Field(default=0.0, ge=0.0)
    intervalStdDev: float = Field(default=0.0, ge=0.0)
    clickFrequency: float = Field(default=0.0, ge=0.0)

    @field_validator("meanInterval", "intervalStdDev", "clickFrequency")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return v


class ScrollFeaturesSchema(BaseModel):
    scrollEventCount: int = Field(default=0, ge=0)
    totalDistance: float = Field(default=0.0, ge=0.0)
    meanVelocity: float = Field(default=0.0, ge=0.0)
    meanPauseDuration: float = Field(default=0.0, ge=0.0)

    @field_validator("totalDistance", "meanVelocity", "meanPauseDuration")
    @classmethod
    def validate_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return v


class TouchFeaturesSchema(BaseModel):
    touchCount: int = Field(default=0, ge=0)
    meanDuration: float = Field(default=0.0, ge=0.0)
    meanVelocity: float = Field(default=0.0, ge=0.0)
    directionDistribution: Dict[str, int] = Field(default_factory=dict)


class DeviceContextSchema(BaseModel):
    userAgentSummary: Optional[Dict[str, str]] = None
    screen: Optional[Dict[str, float]] = None
    environment: Optional[Dict[str, Any]] = None


class ExtractedFeaturePayloadSchema(BaseModel):
    feature_schema_version: str = Field(default="1.0.0")
    typing: Optional[TypingFeaturesSchema] = None
    mouse: Optional[MouseFeaturesSchema] = None
    click: Optional[ClickFeaturesSchema] = None
    scroll: Optional[ScrollFeaturesSchema] = None
    touch: Optional[TouchFeaturesSchema] = None
    device: Optional[DeviceContextSchema] = None


class TelemetryPacketMetadataSchema(BaseModel):
    pageContext: Optional[str] = None
    pageVisibility: Optional[str] = None


class TelemetryPacketSchema(BaseModel):
    sessionId: str = Field(..., min_length=1, max_length=128)
    sdkInstanceId: str = Field(..., min_length=1, max_length=64)
    eventId: str = Field(..., min_length=1, max_length=64)
    sequenceNumber: int = Field(..., ge=1)
    timestamp: int = Field(..., description="Epoch timestamp in ms")
    schemaVersion: str = Field(default="1.0.0")
    sdkVersion: str = Field(default="1.0.0")
    eventType: str = Field(default="behavioral_batch")
    features: ExtractedFeaturePayloadSchema
    metadata: Optional[TelemetryPacketMetadataSchema] = None
    integrity: Optional[str] = None


class TelemetryBatchSchema(BaseModel):
    batchId: str = Field(..., min_length=1, max_length=64)
    sentAt: int = Field(..., description="Epoch timestamp in ms")
    packets: List[TelemetryPacketSchema] = Field(..., min_length=1)


class TelemetryIngestionResponse(BaseModel):
    status: str = "accepted"
    batch_id: str
    received_packets: int
    accepted_packets: int
    rejected_packets: int
    reason: Optional[str] = None
