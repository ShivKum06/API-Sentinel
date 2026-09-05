from fastapi.testclient import TestClient
from sentinel.main import app


def test_demo_api_and_enumeration_incident():
    with TestClient(app) as client:
        assert client.get("/products").status_code == 200
        for user_id in range(1, 12):
            response = client.get(f"/users/{user_id}", headers={"x-forwarded-for": "10.0.0.20"})
            assert response.status_code == 200
        incidents = client.get("/api/incidents").json()
        assert any(item["threat_type"] == "API_ENUMERATION" for item in incidents)


def test_injection_is_detected():
    with TestClient(app) as client:
        response = client.get("/search", params={"q": "union select password from users"})
        assert response.status_code == 403
        events = client.get("/api/events").json()
        assert any(item["threat_type"] == "INJECTION" for item in events)
