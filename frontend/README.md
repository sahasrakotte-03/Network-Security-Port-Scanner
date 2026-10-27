# Network Security Port Scanner - Frontend

Modern, cybersecurity operations center (SOC)-themed user interface built with React and Vite.

## Design Highlights

- **Aesthetic**: Deep slate dark theme (`#090d16`) with cyan/emerald glowing indicators and high-contrast typography.
- **Security Notice**: Prominent, unhideable ethical authorization banner.
- **Controls**: Interactive target selector with presets (`127.0.0.1`, `localhost`), range presets (`1-100`, `80-443`, `1-1024`), and instant client-side input validation.
- **Real-Time Telemetry**: Live summary cards showcasing ports scanned, open count, closed count, and scan duration in seconds.
- **Filtering & Search**: Dynamic tab filters (`All`, `Open Only`, `Closed`) and live port/service search input.
- **Educational Panels**: Built-in visual guides on TCP 3-way handshake mechanics and defensive security boundaries.

## Technology Stack

- **Framework**: React 18
- **Build Tool**: Vite 6
- **Icons**: Lucide React
- **Styling**: Modern CSS variables, responsive grid, flexbox layout

## Setup & Running

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

The application will be accessible at `http://localhost:5173`.
Vite is preconfigured to reverse-proxy `/api` requests to the FastAPI backend at `http://127.0.0.1:8000`.

## Production Build

```bash
npm run build
```
The compiled static assets will be output to `frontend/dist/`.
