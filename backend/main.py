"""
FastAPI application entrypoint for the Network Security Port Scanner.
Provides REST endpoints, CORS configuration, request validation, and safe error handling.
"""

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from models import HealthResponse, ScanRequest, ScanResponse
from scanner import scan_ports
from validators import validate_port_range, validate_target

app = FastAPI(
    title="Network Security Port Scanner API",
    description="Educational network security tool for authorized TCP port scanning and service discovery.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for React frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Sanitize schema validation errors so users receive clean messages
    instead of raw internal validation structures.
    """
    errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []) if loc != "body")
        msg = err.get("msg", "Invalid input")
        errors.append(f"{field}: {msg}" if field else msg)

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "Input validation error: " + "; ".join(errors)
        }
    )


@app.get("/", tags=["General"])
async def root():
    """Root endpoint welcoming the user and providing links to API documentation."""
    return {
        "title": "Network Security Port Scanner API",
        "status": "operational",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
        "message": "Authorized educational use only."
    }


@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return HealthResponse(
        status="ok",
        message="Network Security Port Scanner API is running"
    )


@app.post("/api/scan", response_model=ScanResponse, tags=["Scanner"])
async def perform_scan(request: ScanRequest):
    """
    Execute an authorized TCP port scan against the specified target.

    Validates target structure and DNS resolution, enforces port boundaries,
    and executes bounded concurrent TCP connect checks.
    """
    # 1. Validate Target Host / IP
    try:
        clean_target, resolved_ip = validate_target(request.target)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to resolve or connect to the target. Verify that the target is reachable and that you have permission to scan it."
        )

    # 2. Validate Port Boundaries and Range Limit
    try:
        start_p, end_p = validate_port_range(request.start_port, request.end_port)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )

    # 3. Perform Concurrently Bounded TCP Connect Scan
    try:
        scan_result = scan_ports(
            target=clean_target,
            ip=resolved_ip,
            start_port=start_p,
            end_port=end_p,
            max_workers=50,
            timeout=0.8
        )
        return scan_result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during port scanning. Please try again with a smaller range."
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
