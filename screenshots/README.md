# Project Screenshots Guide

This directory holds visual demonstration screenshots for documentation, GitHub submission, and college faculty presentations.

## Recommended Screenshots to Capture

When demonstrating the application locally, capture the following 3 screenshots and save them with these exact filenames:

### 1. `dashboard.png`
- **What to capture**: The initial state of the dashboard with the Security Notice banner, target preset `127.0.0.1`, and port range `1 - 100` before or right at scan start.
- **Save as**: `screenshots/dashboard.png`

### 2. `scan-results.png`
- **What to capture**: A completed scan against `127.0.0.1` showing the **Scan Mission Summary** cards, duration, active open ports (e.g. backend port 8000, 3000, or ephemeral test port) highlighted with green badges, and the filter toolbar.
- **Save as**: `screenshots/scan-results.png`

### 3. `error-handling.png`
- **What to capture**: Safe error rejection demonstration:
  - Enter an invalid target like `127.0.0.1; whoami` or `https://127.0.0.1`, OR
  - Enter an inverted port range like `Start Port: 500, End Port: 100`, OR
  - Enter a range larger than 2,000 ports like `Start Port: 1, End Port: 5000`.
  - Capture the user-friendly alert banner showing sanitized error feedback without stack traces.
- **Save as**: `screenshots/error-handling.png`

---

## How to Capture Quickly on Windows
- Press `Windows Key + Shift + S` to use the Windows Snipping Tool.
- Select the browser window running `http://localhost:5173`.
- Save the images directly into this `screenshots/` directory.
