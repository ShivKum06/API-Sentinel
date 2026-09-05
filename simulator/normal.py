import httpx

BASE_URL = "http://127.0.0.1:8000"
for path in ("/products", "/users", "/users/1", "/search?q=widget"):
    response = httpx.get(BASE_URL + path)
    print(response.status_code, path)
