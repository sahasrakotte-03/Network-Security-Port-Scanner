"""
Unit tests for backend/scanner.py.
Verifies TCP connect logic, ephemeral port scanning, and service identification.
"""

import socket
import sys
import os
import pytest

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import get_service_name, scan_single_port, scan_ports


def test_service_name_mapping():
    """Verify standard service mappings and fallback for unassigned ports."""
    assert "HTTP" in get_service_name(80)
    assert "HTTPS" in get_service_name(443)
    assert "SSH" in get_service_name(22)
    assert "DNS" in get_service_name(53)
    assert get_service_name(61234) == "Unknown"


def test_open_and_closed_port_detection():
    """
    Test scanner accuracy by binding a real local TCP socket to an ephemeral port.
    The active port should register as 'open' while a non-listening port is 'closed'.
    """
    # 1. Spin up a temporary listening TCP server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    open_port = server_sock.getsockname()[1]

    try:
        # Scan the listening port
        result_open = scan_single_port("127.0.0.1", open_port, timeout=0.5)
        assert result_open.status == "open"
        assert result_open.port == open_port
        assert result_open.response_time_ms is not None
        assert result_open.response_time_ms >= 0
    finally:
        # Close server socket
        server_sock.close()

    # Now verify the previously open port is reported closed
    result_closed = scan_single_port("127.0.0.1", open_port, timeout=0.5)
    assert result_closed.status == "closed"
    assert result_closed.response_time_ms is None


def test_batch_port_scanning():
    """Verify batch scanning returns structured ScanResponse with sorted results."""
    # Spin up ephemeral server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    open_port = server_sock.getsockname()[1]

    try:
        # Scan a 5-port range that includes the ephemeral listening port
        start_p = max(1, open_port - 2)
        end_p = min(65535, open_port + 2)

        response = scan_ports(
            target="127.0.0.1",
            ip="127.0.0.1",
            start_port=start_p,
            end_port=end_p,
            max_workers=5,
            timeout=0.5
        )

        assert response.target == "127.0.0.1"
        assert response.ip_address == "127.0.0.1"
        assert response.ports_scanned == (end_p - start_p + 1)
        assert response.open_ports >= 1
        assert response.duration > 0
        assert len(response.results) == response.ports_scanned
        # Verify results are sorted by port number
        ports_returned = [r.port for r in response.results]
        assert ports_returned == sorted(ports_returned)

        # Check that the open port was marked open
        target_res = next((r for r in response.results if r.port == open_port), None)
        assert target_res is not None
        assert target_res.status == "open"
    finally:
        server_sock.close()
