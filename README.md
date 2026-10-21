# NetMedic — Intelligent Network Troubleshooting Assistant

A real working **React + Flask + SQLite** computer networking mini project. Diagnostics are run on the **backend computer**, not in the browser.

## Windows setup

Open this folder in VS Code. Open **two terminals**.

### Terminal 1 — backend

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, skip it and run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.\.venv\Scripts\python.exe app.py` instead.

Check http://127.0.0.1:5000/api/health

### Terminal 2 — frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 (or http://127.0.0.1:5173).

## What is included

- Real ICMP ping (three probes; elapsed process time approximation), DNS A lookup, TCP connectivity
- Explainable health score and rule-based recommendations (not an AI model)
- Live backend host interface and traffic counters
- SQLite history, charts, record deletion, CSV export
- Vite API proxy; responsive dark dashboard
- Backend API homepage (`/`) so you don't see a 404 at port 5000

## API

`GET /`, `GET /api/health`, `GET /api/targets`, `GET /api/network/status`, `POST /api/diagnostics/run`, `GET /api/diagnostics`, `GET /api/diagnostics/<id>`, `DELETE /api/diagnostics/<id>`, `GET /api/analytics/summary`.

Example POST body: `{"target":"127.0.0.1","port":80}`. The TCP test may fail if no service listens on that port; this is a valid diagnostic result.

## Configure approved targets

Only explicit targets are allowed. To use a router that you own or administer, set the environment variable **before** running Flask:

```powershell
$env:NETMEDIC_TARGETS="127.0.0.1,localhost,1.1.1.1,8.8.8.8,example.com,192.168.1.1"
python app.py
```

Do not add devices or networks you do not have permission to test. Never expose the unauthenticated development server to the public internet.

## Notes

- Backend binds to `127.0.0.1:5000`, not `0.0.0.0`.
- DNS check on IP/localhost uses `example.com` to test the resolver; it is not a DNS lookup of that IP.
- ICMP failures may indicate firewall filtering rather than an outage.
- Health score is a project heuristic; no claim of trained AI.
- The app stores diagnostic records in `backend/netmedic.db` when you first start Flask.
- This is a self-contained mini-project, not a hardened production service.
