"""
TCP Port Scanning Engine using Python's native socket library.
Implements bounded multi-threaded TCP connect scanning with service identification.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from models import PortScanResult, ScanResponse

# Dictionary of well-known IANA port numbers and their standard associated services.
# Note: These represent common/likely service mappings, not guaranteed running services.
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data (File Transfer Protocol Data)",
    21: "FTP (File Transfer Protocol Control)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted text communications)",
    25: "SMTP (Simple Mail Transfer Protocol)",
    43: "WHOIS (Domain Information)",
    53: "DNS (Domain Name System)",
    67: "DHCP-Server (Dynamic Host Config)",
    68: "DHCP-Client",
    69: "TFTP (Trivial File Transfer Protocol)",
    80: "HTTP (Hypertext Transfer Protocol)",
    88: "Kerberos (Authentication Service)",
    110: "POP3 (Post Office Protocol v3)",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Network Time Protocol)",
    135: "MS-RPC (Microsoft RPC Endpoint Mapper)",
    137: "NetBIOS-NS (Name Service)",
    138: "NetBIOS-DGM (Datagram Service)",
    139: "NetBIOS-SSN (Session Service)",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMP-Trap",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP Secure / TLS)",
    445: "SMB (Server Message Block / Windows Share)",
    465: "SMTPS (SMTP over SSL)",
    514: "Syslog",
    515: "LPD (Line Printer Daemon)",
    587: "SMTP-Submission (Message Submission)",
    636: "LDAPS (LDAP over TLS/SSL)",
    993: "IMAPS (IMAP over TLS/SSL)",
    995: "POP3S (POP3 over TLS/SSL)",
    1080: "SOCKS-Proxy",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle-DB",
    2049: "NFS (Network File System)",
    2375: "Docker-Daemon (Unencrypted)",
    2376: "Docker-Daemon (TLS)",
    3000: "Node/React-Dev (Development Server)",
    3306: "MySQL (Database Server)",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "Flask/ASP.NET-Dev",
    5432: "PostgreSQL (Database Server)",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis (Key-Value Store)",
    8000: "HTTP-Alt / Dev-Server (FastAPI/Django)",
    8080: "HTTP-Proxy / Alternate Web Server",
    8443: "HTTPS-Alt (Alternative Secure Web)",
    8888: "HTTP-Alt / Jupyter Notebook",
    9000: "SonarQube / PHP-FPM",
    9090: "Prometheus (Metrics Server)",
    9200: "Elasticsearch (Search Engine)",
    27017: "MongoDB (Document Database)"
}

DEFAULT_TIMEOUT = 0.8  # seconds
MAX_CONCURRENT_WORKERS = 50


def get_service_name(port: int) -> str:
    """
    Look up the commonly associated service name for a given TCP port.
    Returns 'Unknown' if the port has no widely standardized assignment.
    """
    return COMMON_SERVICES.get(port, "Unknown")


def scan_single_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortScanResult:
    """
    Perform a single TCP connect scan on the specified IP and port.

    Mechanics:
    1. Instantiates a TCP stream socket (AF_INET, SOCK_STREAM).
    2. Enforces a non-blocking timeout window.
    3. Invokes connect_ex:
       - 0 indicates a successful TCP 3-way handshake (SYN -> SYN-ACK -> ACK) => OPEN
       - Non-zero indicates connection refused or timed out => CLOSED
    4. Measures elapsed round-trip time in milliseconds.
    5. Always closes the socket in a finally block to avoid resource leaks.
    """
    service_name = get_service_name(port)
    start_time = time.perf_counter()
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((ip, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if result_code == 0:
            return PortScanResult(
                port=port,
                status="open",
                service=service_name,
                response_time_ms=elapsed_ms
            )
        else:
            return PortScanResult(
                port=port,
                status="closed",
                service=service_name,
                response_time_ms=None
            )
    except socket.timeout:
        return PortScanResult(
            port=port,
            status="closed",
            service=service_name,
            response_time_ms=None
        )
    except Exception:
        return PortScanResult(
            port=port,
            status="closed",
            service=service_name,
            response_time_ms=None
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_ports(
    target: str,
    ip: str,
    start_port: int,
    end_port: int,
    max_workers: int = MAX_CONCURRENT_WORKERS,
    timeout: float = DEFAULT_TIMEOUT
) -> ScanResponse:
    """
    Scan a range of TCP ports concurrently using a bounded ThreadPoolExecutor.

    Args:
        target: Target hostname or IP entered by user.
        ip: Resolved IPv4 address to connect to.
        start_port: Lower port boundary.
        end_port: Upper port boundary.
        max_workers: Concurrency ceiling (capped at 50).
        timeout: Socket connection timeout per port.

    Returns:
        ScanResponse: Aggregated scan summary and port-by-port results.
    """
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    worker_count = min(max_workers, MAX_CONCURRENT_WORKERS, total_ports)

    scan_start_time = time.perf_counter()
    results: List[PortScanResult] = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_port = {
            executor.submit(scan_single_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            try:
                res = future.result()
                results.append(res)
            except Exception:
                port = future_to_port[future]
                results.append(
                    PortScanResult(
                        port=port,
                        status="closed",
                        service=get_service_name(port),
                        response_time_ms=None
                    )
                )

    # Sort results in ascending order by port number
    results.sort(key=lambda r: r.port)
    scan_duration = round(time.perf_counter() - scan_start_time, 2)

    open_count = sum(1 for r in results if r.status == "open")
    closed_count = total_ports - open_count

    return ScanResponse(
        target=target,
        ip_address=ip,
        ports_scanned=total_ports,
        open_ports=open_count,
        closed_ports=closed_count,
        duration=scan_duration,
        results=results
    )
