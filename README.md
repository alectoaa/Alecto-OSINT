# Alecto OSINT Intelligence Engine

A FastAPI-based OSINT research tool prepared for local use. The interface and API combine username, email, Discord ID, IP, and domain queries, profile scans, and breach catalog metadata into a single application.

> **Responsible use:** This project should only be used for data that you own or have explicit permission to inspect. Searching for, storing, or sharing unauthorized accounts, passwords, tokens, or personal data may be illegal. Project developers are not responsible for the content of third-party data sources.

## Requirements

- Python 3.11 or higher
- Optional: Tor (for dark-web queries)
- Optional: HIBP, Discord, or other service API keys

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Enter only your own keys into the `.env` file. The `.env` file is not included in Git; never commit real keys. If keys were previously shared, revoke them from the provider panel and renew them.

## Running

```powershell
python server.py
```

Interface: <http://127.0.0.1:8000>

Alternatively:

```powershell
uvicorn server:app --host 127.0.0.1 --port 8000
```

## API Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /` | Web interface |
| `GET /stream?target=...` | Real-time SSE scan |
| `GET /scan?target=...` | Batch JSON scan |
| `GET /discord?id=...` | Discord profile query |
| `GET /ip?address=...` | IP geolocation query |
| `GET /domain?q=...` | Domain name / subdomain query |
| `GET /catalog?q=...` | Breach catalog metadata search |
| `POST /catalog/refresh` | Refresh breach catalog metadata |
| `/scanners` | Create and manage scanners |

## Local Raw Data Search

`/raw-search` is disabled by default. For local test data that you have explicit permission to inspect, explicitly set the following in `.env`:

```dotenv
ENABLE_RAW_SEARCH=true
RAW_LEAKS_DIRECTORY=./data/dumps
```

This feature may return raw lines (which may contain passwords or tokens). `data/` and local database files are covered by `.gitignore`; do not upload them to GitHub.

## Tor Connection

For Tor queries, the local Tor SOCKS5 service must run on `127.0.0.1:9050`, and the control service for circuit renewal on `127.0.0.1:9051`. If these services are not running, onion queries fail with `ProxyConnectionError`. Settings can be modified from within `.env`:

```dotenv
TOR_PROXY=socks5://127.0.0.1:9050
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
```

Tor Browser or Tor Expert Bundle must be running. To check the connection, run the following command in the project folder:

```powershell
python debug_onion.py
```

On a successful connection, the HTTP status and response size for each target are displayed; on a failed connection, the error type is shown. If there is no SOCKS5 service on `127.0.0.1:9050`, all onion targets fail with `ProxyConnectionError`; in this case, start Tor and run the command again. The control port `127.0.0.1:9051` is required for the circuit renewal feature.

The Tor scan produces only redacted result metadata; it does not return passwords, tokens, or raw account lines. Contents in the format of passwords or tokens are hidden for security reasons while generating results.

The Tor engine is used directly via `OnionEngine.search_dark()`. The `/scan` and `/stream` endpoints in the normal web interface currently operate independently of the Tor engine; a separate call using this engine must be made to get Tor results.

## Development Notes

- The application listens on `127.0.0.1` by default for local execution.
- `breach_catalog.sqlite3`, `dark_crawler/found_nodes.db`, and `scanners.json` are local state files created during runtime.
- API keys and webhook URLs must be retrieved solely from environment variables or local configuration entered by the user.