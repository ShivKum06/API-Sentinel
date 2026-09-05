import sys
import httpx

base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
with httpx.Client(base_url=base_url) as client:
    for user_id in range(1, 31):
        response = client.get(f"/users/{user_id}")
        print(user_id, response.status_code)
