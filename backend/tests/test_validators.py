"""
Unit tests for backend/validators.py.
Verifies target host validation, DNS resolution, and port range boundaries.
"""

import pytest
import sys
import os

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from validators import validate_target, validate_port_range


def test_valid_localhost_target():
    """Verify localhost is valid and resolves to 127.0.0.1."""
    clean_target, resolved_ip = validate_target("localhost")
    assert clean_target == "localhost"
    assert resolved_ip in ("127.0.0.1", "::1", "127.0.1.1")


def test_valid_ipv4_target():
    """Verify valid IPv4 address passes without changes."""
    clean_target, resolved_ip = validate_target("127.0.0.1")
    assert clean_target == "127.0.0.1"
    assert resolved_ip == "127.0.0.1"


def test_empty_target_rejected():
    """Verify empty or whitespace target raises ValueError."""
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_target("")

    with pytest.raises(ValueError, match="cannot be empty"):
        validate_target("   ")


def test_url_scheme_rejected():
    """Verify user providing http:// or https:// is rejected with clear instructions."""
    with pytest.raises(ValueError, match="remove 'http://'"):
        validate_target("http://127.0.0.1")

    with pytest.raises(ValueError, match="remove 'http://'"):
        validate_target("https://localhost")


def test_command_injection_chars_rejected():
    """Verify shell metacharacters are blocked."""
    dangerous_inputs = [
        "127.0.0.1; ls",
        "localhost | whoami",
        "127.0.0.1 && dir",
        "localhost`id`",
        "127.0.0.1/evil",
        "target$(id)",
    ]
    for evil in dangerous_inputs:
        with pytest.raises(ValueError, match="Invalid target format"):
            validate_target(evil)


def test_nonexistent_host_rejected():
    """Verify that unresolvable hostnames raise a clean resolution error."""
    with pytest.raises(ValueError, match="Unable to resolve target"):
        validate_target("nonexistent-domain-test-xyz-987654.local")


def test_valid_port_ranges():
    """Verify valid port ranges are accepted."""
    start, end = validate_port_range(1, 100)
    assert start == 1
    assert end == 100

    start, end = validate_port_range(80, 80)
    assert start == 80
    assert end == 80

    start, end = validate_port_range(1, 2000)
    assert start == 1
    assert end == 2000


def test_start_greater_than_end_rejected():
    """Verify start_port > end_port is rejected."""
    with pytest.raises(ValueError, match="cannot be greater than end port"):
        validate_port_range(500, 100)


def test_port_out_of_bounds_rejected():
    """Verify ports < 1 or > 65535 are rejected."""
    with pytest.raises(ValueError, match="Start port must be between 1 and 65535"):
        validate_port_range(0, 100)

    with pytest.raises(ValueError, match="End port must be between 1 and 65535"):
        validate_port_range(1, 70000)


def test_port_range_exceeding_max_rejected():
    """Verify ranges exceeding 2000 ports are rejected."""
    with pytest.raises(ValueError, match="Port range too large"):
        validate_port_range(1, 2001)
