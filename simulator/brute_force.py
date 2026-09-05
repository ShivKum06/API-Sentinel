import sys
import httpx

base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
with httpx.Client(base_url=base_url) as client:
    for attempt in range(1, 11):
        response = client.post("/login", json={"username": "demo", "password": "wrong"})
        print(attempt, response.status_code)
