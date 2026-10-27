"""
Data models for the Network Security Port Scanner API.
Provides type safety, serialization, and strict input/output validation.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Payload sent by the frontend client to initiate a port scan."""
    target: str = Field(
        ...,
        description="Target IP address or valid hostname (e.g., 127.0.0.1, localhost)",
        min_length=1,
        max_length=255
    )
    start_port: int = Field(
        ...,
        description="Starting port number (1 to 65535)",
        ge=1,
        le=65535
    )
    end_port: int = Field(
        ...,
        description="Ending port number (1 to 65535)",
        ge=1,
        le=65535
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 100
            }
        }
    }


class PortScanResult(BaseModel):
    """Result of scanning an individual TCP port."""
    port: int = Field(..., description="TCP port number")
    status: str = Field(..., description="Port status: 'open' or 'closed'")
    service: str = Field(..., description="Likely/common service associated with this port")
    response_time_ms: Optional[float] = Field(
        None,
        description="Round-trip TCP connection time in milliseconds (if open)"
    )


class ScanResponse(BaseModel):
    """Aggregated scan summary and port-by-port results."""
    target: str = Field(..., description="Target hostname or IP entered by user")
    ip_address: str = Field(..., description="Resolved IPv4 address that was scanned")
    ports_scanned: int = Field(..., description="Total count of ports scanned")
    open_ports: int = Field(..., description="Number of open ports discovered")
    closed_ports: int = Field(..., description="Number of closed or unreachable ports")
    duration: float = Field(..., description="Total scan execution duration in seconds")
    results: List[PortScanResult] = Field(..., description="Detailed list of scanned ports")


class HealthResponse(BaseModel):
    """Response returned by the /api/health endpoint."""
    status: str = Field(default="ok", description="Server health status")
    message: str = Field(
        default="Network Security Port Scanner API is running",
        description="Informational status message"
    )
