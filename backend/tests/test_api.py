"""
Integration tests for FastAPI REST endpoints.
Tests /api/health and /api/scan with valid, invalid, and boundary payloads.
"""

import sys
import os
import pytest
from starlette.testclient import TestClient

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app

client = TestClient(app)


def test_health_check_endpoint():
    """Verify GET /api/health returns 200 OK and health status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "running" in data["message"].lower()


def test_root_endpoint():
    """Verify GET / returns API operational information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"


def test_scan_endpoint_valid_small_range():
    """Verify POST /api/scan with valid localhost small range returns 200 OK."""
    payload = {
        "target": "127.0.0.1",
        "start_port": 80,
        "end_port": 85
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "127.0.0.1"
    assert data["ip_address"] == "127.0.0.1"
    assert data["ports_scanned"] == 6
    assert len(data["results"]) == 6
    assert "duration" in data


def test_scan_endpoint_invalid_target():
    """Verify POST /api/scan rejects injection strings and invalid hosts."""
    payload = {
        "target": "127.0.0.1; whoami",
        "start_port": 80,
        "end_port": 81
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "Invalid target format" in data["detail"]


def test_scan_endpoint_start_greater_than_end():
    """Verify POST /api/scan rejects start_port > end_port."""
    payload = {
        "target": "127.0.0.1",
        "start_port": 100,
        "end_port": 20
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 400
    assert "cannot be greater than end port" in response.json()["detail"]


def test_scan_endpoint_range_too_large():
    """Verify POST /api/scan rejects requests exceeding 2000 ports."""
    payload = {
        "target": "127.0.0.1",
        "start_port": 1,
        "end_port": 2500
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 400
    assert "Port range too large" in response.json()["detail"]


def test_scan_endpoint_invalid_types():
    """Verify POST /api/scan returns sanitized validation error when types mismatch."""
    payload = {
        "target": "127.0.0.1",
        "start_port": "not-a-number",
        "end_port": 80
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 400
    assert "Input validation error" in response.json()["detail"]
