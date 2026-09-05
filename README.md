# API Sentinel

A demo-scoped API security gateway for the workflow in `API Sentinel WORKFLOW.docx`. It captures every request, evaluates deterministic security signals, applies a risk policy, persists incidents in SQLite, and broadcasts threats to connected dashboards.

## Run

```powershell
cd "C:\Users\Shiv\Desktop\INIT' 26\Codes"
python -m pip install -r requirements.txt
uvicorn sentinel.main:app --reload
```

Open `frontend/index.html` while the API is running. API docs are available at `http://127.0.0.1:8000/docs`.

## Demo traffic

Run these in separate terminals while the server is active:

```powershell
python simulator/normal.py
python simulator/enumeration.py
python simulator/brute_force.py
python simulator/injection.py
```

The API exposes the protected demo routes (`/login`, `/products`, `/users`, `/users/{id}`, `/search`, `/payment`, `/admin/data`) and dashboard routes (`/api/events`, `/api/incidents`, `/api/endpoints`, `/api/stats`, `/api/incidents/{id}`, `/api/incidents/{id}/override`). WebSocket events use `/ws/events`.

## Contracts

`RequestContext`, `SecurityResult`, and `DecisionResult` in `sentinel/models.py` are the shared team interfaces. The database is created as `sentinel.db` on startup. This is deliberately not production-grade injection protection or a universal threat model; the thresholds and patterns exist for a controlled demonstration.

## Tests

```powershell
python -m pytest -q
```
