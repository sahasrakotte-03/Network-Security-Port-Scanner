"""
Input validators for target hosts, IP addresses, and port ranges.
Ensures cybersecurity controls are enforced before scanning begins.
"""

import ipaddress
import re
import socket
from typing import Tuple

# RFC 1123 compliant hostname regex (allowing letters, digits, hyphens, dots)
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# Reject dangerous characters that could indicate command injection attempts
FORBIDDEN_CHARS = re.compile(r"[;&|`$<>{}\\/\"\'\s]")

MAX_PORT_RANGE = 2000
MIN_PORT = 1
MAX_PORT = 65535


def validate_target(target: str) -> Tuple[str, str]:
    """
    Validate target host/IP and resolve it to an IPv4 address.

    Returns:
        Tuple[str, str]: (sanitized_target, resolved_ip)

    Raises:
        ValueError: If the target is invalid, malformed, or fails DNS resolution.
    """
    if not target or not target.strip():
        raise ValueError("Target host or IP address cannot be empty.")

    clean_target = target.strip()

    # Reject common accidental prefixes (e.g. http://, https://, ftp://)
    if "://" in clean_target:
        raise ValueError(
            "Please provide only a hostname or IP address (remove 'http://', 'https://', or similar URL schemes)."
        )

    # Reject forbidden characters (slashes, command injection characters, whitespace)
    if FORBIDDEN_CHARS.search(clean_target):
        raise ValueError(
            "Invalid target format. Target cannot contain spaces, slashes, or shell metacharacters."
        )

    # Check if target is a valid IPv4 address
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(clean_target)
        if ip_obj.version != 4:
            raise ValueError("Only IPv4 addresses and standard hostnames are supported.")
        is_ip = True
    except ValueError as e:
        if "Only IPv4" in str(e):
            raise
        # Not a raw IP; continue to hostname validation
        pass

    if not is_ip:
        # Validate hostname structure (e.g. localhost, example.com, server.local)
        if len(clean_target) > 255 or not HOSTNAME_REGEX.match(clean_target):
            raise ValueError(
                f"Invalid hostname format: '{clean_target}'. Please enter a valid hostname or IPv4 address."
            )

    # Perform safe DNS resolution using Python's socket library
    try:
        resolved_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        raise ValueError(
            f"Unable to resolve target '{clean_target}'. Check your network connection, DNS settings, or host spelling."
        )
    except Exception as exc:
        raise ValueError(
            f"Error resolving target '{clean_target}': Please verify the host is reachable."
        )

    return clean_target, resolved_ip


def validate_port_range(start_port: int, end_port: int, max_range: int = MAX_PORT_RANGE) -> Tuple[int, int]:
    """
    Validate port boundaries and range size.

    Returns:
        Tuple[int, int]: (start_port, end_port)

    Raises:
        ValueError: If port range is invalid or exceeds maximum size.
    """
    if not isinstance(start_port, int) or not isinstance(end_port, int):
        raise ValueError("Port numbers must be valid integers.")

    if start_port < MIN_PORT or start_port > MAX_PORT:
        raise ValueError(f"Start port must be between {MIN_PORT} and {MAX_PORT}.")

    if end_port < MIN_PORT or end_port > MAX_PORT:
        raise ValueError(f"End port must be between {MIN_PORT} and {MAX_PORT}.")

    if start_port > end_port:
        raise ValueError(
            f"Start port ({start_port}) cannot be greater than end port ({end_port})."
        )

    total_ports = end_port - start_port + 1
    if total_ports > max_range:
        raise ValueError(
            f"Port range too large ({total_ports} ports requested). "
            f"Please scan a maximum of {max_range} ports at a time to ensure application stability."
        )

    return start_port, end_port
