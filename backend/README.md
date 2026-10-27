# Network Security Port Scanner - Backend

FastAPI-powered REST backend for educational network security TCP port scanning and service identification.

## Architecture

- **Framework**: FastAPI (Asynchronous Python 3.10+)
- **Networking**: Python's native `socket` library (`socket.SOCK_STREAM`)
- **Concurrency**: Bounded `concurrent.futures.ThreadPoolExecutor` (Max 50 workers)
- **Validation**: Pydantic v2 schemas + regex sanitization & DNS resolution checks
- **Testing**: `pytest` + `starlette.testclient.TestClient`

## Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API status and links to documentation |
| `GET` | `/api/health` | Service readiness probe |
| `POST` | `/api/scan` | Initiate a bounded TCP connect port scan |
| `GET` | `/docs` | Interactive Swagger UI documentation |

### Example Scan Request

```json
POST /api/scan
Content-Type: application/json

{
  "target": "127.0.0.1",
  "start_port": 1,
  "end_port": 100
}
```

### Example Scan Response

```json
{
  "target": "127.0.0.1",
  "ip_address": "127.0.0.1",
  "ports_scanned": 100,
  "open_ports": 1,
  "closed_ports": 99,
  "duration": 1.25,
  "results": [
    {
      "port": 80,
      "status": "closed",
      "service": "HTTP (Hypertext Transfer Protocol)",
      "response_time_ms": null
    },
    {
      "port": 8000,
      "status": "open",
      "service": "HTTP-Alt / Dev-Server (FastAPI/Django)",
      "response_time_ms": 2.45
    }
  ]
}
```

## Setup & Running

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate virtual environment (optional)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the development server
uvicorn main:app --reload --port 8000
```

## Running Automated Tests

```bash
# From workspace root
python -m pytest backend/tests/ -v
```
