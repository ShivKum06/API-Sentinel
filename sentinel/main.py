import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import unquote_plus
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sentinel import database
from sentinel.detection import detect
from sentinel.models import OverrideRequest, RequestContext, utc_now
from sentinel.response import decide
from sentinel.risk import build_result

class Hub:
    def __init__(self): self.connections: set[WebSocket] = set()
    async def broadcast(self, message: dict):
        for socket in list(self.connections):
            try: await socket.send_json(message)
            except Exception: self.connections.discard(socket)

hub = Hub()

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield

app = FastAPI(title="API Sentinel", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_gateway(request: Request, call_next):
    started = time.perf_counter()
    body = await request.body()
    request_id = request.headers.get("x-request-id", f"REQ-{uuid.uuid4().hex[:8].upper()}")
    ip = request.client.host if request.client else "127.0.0.1"
    query = unquote_plus(str(request.url.query))
    context = RequestContext(request_id=request_id, timestamp=utc_now(), ip=ip, user_id=request.headers.get("x-user-id"), method=request.method, endpoint=request.url.path, request_size=len(body), query=query, body=body.decode("utf-8", "ignore"))
    signals = detect(context)
    security = build_result(request_id, signals)
    decision = decide(security)
    if decision.decision == "BLOCK" and not request.url.path.startswith("/api/"):
        response = JSONResponse({"detail": "Blocked by API Sentinel", "request_id": request_id}, status_code=403)
    else:
        response = await call_next(request)
    context.status_code = response.status_code
    context.response_size = int(response.headers.get("content-length", "0"))
    context.latency_ms = round((time.perf_counter() - started) * 1000, 2)
    if not signals and request.url.path == "/login" and context.status_code in (401, 403):
        signals = detect(context)
        security = build_result(request_id, signals)
        decision = decide(security)
    request_row = context.model_dump(exclude={"query", "body", "latency_ms"})
    request_row["latency"] = context.latency_ms
    database.insert("api_requests", request_row)
    if signals:
        event_id = database.insert("security_events", {"request_id": request_id, "threat_type": security.threat_type, "rule_score": security.threat_score, "anomaly_score": security.anomaly_score, "risk_score": security.risk_score, "severity": security.severity, "reason": "; ".join(security.reasons), "created_at": utc_now()})
        incident_id = database.insert("incidents", {"event_id": event_id, "endpoint": context.endpoint, "ip": ip, "threat_type": security.threat_type, "risk_score": security.risk_score, "action": decision.decision, "status": "OPEN", "created_at": utc_now()})
        await hub.broadcast({"event": "THREAT_DETECTED", "incident_id": f"INC-{incident_id}", "risk_score": security.risk_score, "severity": security.severity, "endpoint": context.endpoint, "threat_type": security.threat_type})
    response.headers["x-request-id"] = request_id
    return response

@app.get("/products")
def products(): return [{"id": 1, "name": "Demo Widget", "price": 19.99}]

@app.get("/users")
def users(): return [{"id": 1, "name": "Demo User"}, {"id": 2, "name": "Test User"}]

@app.get("/users/{user_id}")
def user(user_id: int): return {"id": user_id, "name": f"Demo User {user_id}"}

@app.post("/login")
def login(payload: dict):
    return JSONResponse({"detail": "Invalid credentials"}, status_code=401) if payload.get("password") != "demo-pass" else {"token": "demo-token", "user_id": "demo-user"}

@app.get("/search")
def search(q: str = ""): return {"query": q, "results": []}

@app.post("/payment")
def payment(): return {"status": "accepted", "mode": "demo"}

@app.get("/admin/data")
def admin_data(): return {"message": "Demo-only admin data"}

@app.get("/api/events")
def events(): return database.rows("SELECT * FROM security_events ORDER BY id DESC LIMIT 100")

@app.get("/api/incidents")
def incidents(): return database.rows("SELECT * FROM incidents ORDER BY id DESC LIMIT 100")

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: int):
    result = database.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    return result or JSONResponse({"detail": "Incident not found"}, status_code=404)

@app.post("/api/incidents/{incident_id}/override")
def override(incident_id: int, payload: OverrideRequest):
    incident_row = database.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not incident_row: return JSONResponse({"detail": "Incident not found"}, status_code=404)
    database.insert("audit_logs", {"incident_id": incident_id, "original_action": incident_row["action"], "new_action": payload.action, "reason": payload.reason, "actor": payload.reviewer, "created_at": utc_now()})
    with database.connect() as db: db.execute("UPDATE incidents SET action = ?, status = 'OVERRIDDEN' WHERE id = ?", (payload.action, incident_id))
    return {"incident_id": incident_id, "action": payload.action, "status": "OVERRIDDEN"}

@app.get("/api/endpoints")
def endpoints(): return database.rows("SELECT endpoint, COUNT(*) AS requests FROM api_requests GROUP BY endpoint ORDER BY requests DESC")

@app.get("/api/stats")
def stats():
    return {"apis_protected": 7, "requests": database.one("SELECT COUNT(*) AS count FROM api_requests")["count"], "threats": database.one("SELECT COUNT(*) AS count FROM security_events")["count"], "blocked": database.one("SELECT COUNT(*) AS count FROM incidents WHERE action = 'BLOCK'")["count"], "critical": database.one("SELECT COUNT(*) AS count FROM incidents WHERE risk_score >= 80")["count"]}

@app.websocket("/ws/events")
async def websocket_events(socket: WebSocket):
    await socket.accept(); hub.connections.add(socket)
    try:
        while True: await socket.receive_text()
    except WebSocketDisconnect: hub.connections.discard(socket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
