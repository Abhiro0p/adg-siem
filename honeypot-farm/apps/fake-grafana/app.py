"""
Fake Grafana honeypot — emulates Grafana v9.x login page.
All credential attempts are logged to stdout (JSON) and forwarded to the
ADG controller via the ADG_WEBHOOK_URL environment variable.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone

import httpx
from flask import Flask, Response, jsonify, make_response, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fake-grafana")

WEBHOOK_URL = os.getenv("ADG_WEBHOOK_URL", "")
GRAFANA_VERSION = "9.5.3"

# Sanitize user input — only allow printable ASCII, max 256 chars
_SAFE_RE = re.compile(r"[^\x20-\x7E]")


def _sanitize(value: str | None, maxlen: int = 256) -> str:
    if not value:
        return ""
    return _SAFE_RE.sub("", str(value))[:maxlen]


def _security_headers(response: Response) -> Response:
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Server": f"Grafana/{GRAFANA_VERSION}",
        "Cache-Control": "no-store",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
    })
    return response


app.after_request(_security_headers)


def _emit_event(username: str, user_agent: str | None) -> None:
    event = {
        "source": "fake-grafana",
        "event_type": "auth_attempt",
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": {
            "src_ip": request.remote_addr,
            "username": username,
            "user_agent": user_agent,
            "port": 3000,
            "protocol": "http",
            "service": "grafana",
        },
    }
    logger.info(json.dumps(event))
    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json=event, timeout=3)
        except Exception:
            pass


@app.get("/")
def home():
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Grafana</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    body {{ background:#1a1d23; color:#d8d9da; font-family:Inter,sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0 }}
    .box {{ background:#22252c; padding:40px; border-radius:8px; width:320px }}
    h1 {{ text-align:center; font-size:24px; margin-bottom:24px; color:#f05a28 }}
    input {{ width:100%; padding:10px; margin:8px 0; background:#141619; border:1px solid #3c404a; border-radius:4px; color:#d8d9da; box-sizing:border-box }}
    button {{ width:100%; padding:10px; background:#f05a28; border:none; border-radius:4px; color:#fff; cursor:pointer; font-size:16px }}
    .ver {{ text-align:center; font-size:11px; color:#6e7077; margin-top:16px }}
  </style>
</head>
<body>
  <div class="box">
    <h1>&#x25a0; Grafana</h1>
    <form method="post" action="/login">
      <input name="user" placeholder="Email or username" autocomplete="username"/>
      <input name="password" type="password" placeholder="Password" autocomplete="current-password"/>
      <button type="submit">Log in</button>
    </form>
    <p class="ver">Grafana v{GRAFANA_VERSION} (OSS)</p>
  </div>
</body>
</html>"""
    return html


@app.post("/login")
def login():
    time.sleep(random.uniform(0.3, 1.5))
    username = _sanitize(request.form.get("user") or request.json.get("user") if request.is_json else request.form.get("user"))
    _emit_event(username, request.headers.get("User-Agent"))
    resp = make_response(
        json.dumps({"message": "Invalid username or password"}), 401
    )
    resp.content_type = "application/json"
    return resp


@app.get("/api/health")
@app.get("/health")
def health():
    return jsonify({"commit": "abc123ef", "database": "ok", "version": GRAFANA_VERSION})


@app.get("/api/dashboards/home")
def dashboards():
    # Lures scanners into thinking they got past auth
    return jsonify({"message": "Unauthorized"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
