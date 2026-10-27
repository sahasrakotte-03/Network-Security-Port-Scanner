# Security Policy

## Strict Authorization Notice

> **IMPORTANT:** This tool is intended only for systems you own or have explicit permission to test.
>
> Unauthorized scanning, probing, or reconnaissance of computer systems, networks, or Internet devices without prior explicit written permission from the owner is strictly prohibited and may violate local, national, and international laws (such as the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, Section 66 of the Information Technology Act in India, and similar statutes worldwide).

---

## Intended Purpose

The **Network Security Port Scanner** is an educational, defense-oriented cybersecurity software application developed as a college project to demonstrate:
1. Fundamental TCP/IP networking concepts (specifically the TCP 3-way handshake).
2. Network service reconnaissance from a systems administration and security auditing perspective.
3. Secure coding practices and input validation.

---

## Security Controls Implemented in this Project

This application has been engineered with defensive guardrails to prevent accidental abuse, resource exhaustion, and remote code execution:

| Control Area | Security Mechanism | Description |
| :--- | :--- | :--- |
| **Input Validation** | Strict Hostname & IP Filtering | Rejects malformed targets, URL schemes (`http://`, `ftp://`), path traversal, and malicious metacharacters. |
| **No Shell Execution** | Pure Socket API | Under no circumstances does the application invoke subshells or command-line wrappers (no `subprocess.Popen`, `os.system`, or shell string formatting). All networking is done directly via Python's standard `socket` module. |
| **Port Range Bounds** | Upper Bound Limit (Max 2,000 Ports) | Restricts scan ranges to a maximum of 2,000 ports per request (within standard 1–65535 boundaries) to mitigate denial of service risks. |
| **Bounded Concurrency** | Thread Pool Limiter | Worker threads in `ThreadPoolExecutor` are strictly capped at 50 workers to prevent thread exhaustion and CPU starvation. |
| **Controlled Timeouts** | Socket Connection Timeout | Every connection attempt is bounded by a 1.0s timeout, ensuring sockets are never hung indefinitely on unresponsive or filtered hosts. |
| **Resource Cleanup** | Guaranteed Socket Teardown | Every socket descriptor is enclosed in a `finally: s.close()` block to prevent file descriptor leaks. |
| **Error Sanitization** | Safe Exception Handling | System internals, operating system error codes, and Python stack traces are never surfaced to the end user. User-friendly diagnostics are returned instead. |
| **No Offensive Payloads** | Pure TCP Connect Scanning | The scanner does not craft raw packets (no SYN flood/stealth packets), does not conduct banner fuzzing, does not attempt credential bruteforce, and contains no exploit code. |
| **Data Privacy** | No Credential or Data Logging | The application does not collect, log, or persist user credentials, target histories, or confidential telemetry. |

---

## Safe Testing Guidelines

When evaluating or demonstrating this project for academic credit:
1. **Localhost Testing**: Test against `127.0.0.1` or `localhost`.
2. **Local Virtual Machine / Lab**: Use an isolated lab environment (e.g., VirtualBox, Docker containers, or VMware running Linux/Metasploitable in host-only networking mode).
3. **Never Scan**: Public enterprise systems, university campus networks, government resources, or any target without verifiable authorization.

---

## Vulnerability Reporting

If you identify a security vulnerability in this project:
1. Do not open a public GitHub issue detailing exploitable vectors.
2. Please contact the project maintainer via their designated academic email or institutional portal.
3. Provide a clear reproduction script and description of the vulnerability.
