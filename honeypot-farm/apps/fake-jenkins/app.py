"""
Fake Jenkins honeypot — emulates Jenkins v2.x login page.
Logs all auth attempts in structured JSON and optionally forwards to ADG controller.
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
logger = logging.getLogger("fake-jenkins")

WEBHOOK_URL = os.getenv("ADG_WEBHOOK_URL", "")
JENKINS_VERSION = "2.401.3"

_SAFE_RE = re.compile(r"[^\x20-\x7E]")


def _sanitize(value: str | None, maxlen: int = 256) -> str:
    if not value:
        return ""
    return _SAFE_RE.sub("", str(value))[:maxlen]


def _security_headers(response: Response) -> Response:
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Server": "Jetty(10.0.13)",
        "X-Jenkins": JENKINS_VERSION,
        "X-Hudson": "1.395",
        "Cache-Control": "no-store",
    })
    return response


app.after_request(_security_headers)


def _emit_event(username: str, user_agent: str | None) -> None:
    event = {
        "source": "fake-jenkins",
        "event_type": "auth_attempt",
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": {
            "src_ip": request.remote_addr,
            "username": username,
            "user_agent": user_agent,
            "port": 8080,
            "protocol": "http",
            "service": "jenkins",
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
  <title>Sign in [Jenkins]</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    body {{ background:#f9f9f9; font-family:Georgia,serif; margin:0 }}
    #header {{ background:#000; padding:10px 20px; color:#fff; font-size:24px }}
    #main-panel {{ max-width:400px; margin:60px auto; background:#fff; padding:30px; box-shadow:0 1px 4px rgba(0,0,0,.2) }}
    h1 {{ font-size:18px; border-bottom:1px solid #ccc; padding-bottom:8px }}
    input[type=text],input[type=password] {{ width:100%; padding:8px; margin:6px 0; border:1px solid #ccc; box-sizing:border-box }}
    input[type=submit] {{ background:#4b758b; color:#fff; border:none; padding:10px 20px; cursor:pointer }}
  </style>
</head>
<body>
  <div id="header">Jenkins</div>
  <div id="main-panel">
    <h1>Sign in to Jenkins</h1>
    <form method="post" action="/j_acegi_security_check">
      <input type="hidden" name="from" value="/"/>
      <label>Username</label>
      <input type="text" name="j_username" autocomplete="username"/>
      <label>Password</label>
      <input type="password" name="j_password" autocomplete="current-password"/>
      <br/><br/>
      <input type="submit" value="Sign in"/>
      <label><input type="checkbox" name="remember_me"/> Remember me</label>
    </form>
    <p style="font-size:12px;color:#888">Jenkins {JENKINS_VERSION}</p>
  </div>
</body>
</html>"""
    return html


@app.post("/j_acegi_security_check")
def login():
    time.sleep(random.uniform(0.3, 1.5))
    username = _sanitize(request.form.get("j_username"))
    _emit_event(username, request.headers.get("User-Agent"))
    resp = make_response("", 302)
    resp.headers["Location"] = "/loginError"
    return resp


@app.get("/loginError")
def login_error():
    return "<html><body><p>Invalid username or password. <a href='/'>Try again</a></p></body></html>", 200


@app.get("/api/json")
def api_json():
    # Return enough to fool scanners but require auth
    return jsonify({"_class": "hudson.model.Hudson"}), 403


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
