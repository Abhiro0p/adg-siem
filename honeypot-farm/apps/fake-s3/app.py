"""
Fake S3/MinIO API honeypot — emulates AWS S3 REST API.
Captures any credentials or bucket-listing attempts.
"""
from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx
from flask import Flask, Response, make_response, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fake-s3")

WEBHOOK_URL = os.getenv("ADG_WEBHOOK_URL", "")
REGION = os.getenv("AWS_REGION", "us-east-1")
BUCKET_NAME = os.getenv("FAKE_BUCKET", "corp-backups-2024")

_AUTH_RE = re.compile(r"Credential=([^/,]+)")


def _sanitize(value: str | None, maxlen: int = 512) -> str:
    if not value:
        return ""
    return re.sub(r"[^\x20-\x7E]", "", str(value))[:maxlen]


def _security_headers(response: Response) -> Response:
    response.headers.update({
        "x-amz-request-id": "ADG000000000001",
        "x-amz-id-2": "adg-fake-s3-node",
        "Server": "AmazonS3",
        "X-Content-Type-Options": "nosniff",
    })
    return response


app.after_request(_security_headers)


def _emit_event(event_type: str, details: dict) -> None:
    event = {
        "source": "fake-s3",
        "event_type": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": {
            "src_ip": request.remote_addr,
            "user_agent": _sanitize(request.headers.get("User-Agent")),
            "port": 443,
            "protocol": "https",
            "service": "s3",
            **details,
        },
    }
    logger.info(json.dumps(event))
    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json=event, timeout=3)
        except Exception:
            pass


def _xml_error(code: str, message: str, status: int) -> Response:
    root = ET.Element("Error")
    ET.SubElement(root, "Code").text = code
    ET.SubElement(root, "Message").text = message
    ET.SubElement(root, "RequestId").text = "ADG000000000001"
    body = ET.tostring(root, encoding="unicode", xml_declaration=True)
    resp = make_response(body, status)
    resp.content_type = "application/xml"
    return resp


@app.route("/", methods=["GET"])
def list_buckets():
    auth = request.headers.get("Authorization", "")
    match = _AUTH_RE.search(auth)
    access_key = match.group(1) if match else ""
    _emit_event("s3_list_buckets", {"access_key": _sanitize(access_key), "method": "ListBuckets"})
    root = ET.Element("ListAllMyBucketsResult", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
    owner = ET.SubElement(root, "Owner")
    ET.SubElement(owner, "ID").text = "adg00000000000000000000000000000000000000000000000000000000000000"
    ET.SubElement(owner, "DisplayName").text = "adgadmin"
    buckets = ET.SubElement(root, "Buckets")
    bucket = ET.SubElement(buckets, "Bucket")
    ET.SubElement(bucket, "Name").text = BUCKET_NAME
    ET.SubElement(bucket, "CreationDate").text = "2024-01-15T12:00:00.000Z"
    body = ET.tostring(root, encoding="unicode", xml_declaration=True)
    resp = make_response(body, 200)
    resp.content_type = "application/xml"
    return resp


@app.route(f"/{BUCKET_NAME}", methods=["GET"])
def list_objects():
    auth = request.headers.get("Authorization", "")
    match = _AUTH_RE.search(auth)
    access_key = match.group(1) if match else ""
    prefix = _sanitize(request.args.get("prefix", ""))
    _emit_event("s3_list_objects", {
        "access_key": _sanitize(access_key), "bucket": BUCKET_NAME, "prefix": prefix
    })
    return _xml_error("AccessDenied", "Access Denied", 403)


@app.route(f"/{BUCKET_NAME}/<path:key>", methods=["GET", "PUT", "DELETE", "HEAD"])
def object_operation(key: str):
    auth = request.headers.get("Authorization", "")
    match = _AUTH_RE.search(auth)
    access_key = match.group(1) if match else ""
    _emit_event(f"s3_{request.method.lower()}_object", {
        "access_key": _sanitize(access_key),
        "bucket": BUCKET_NAME,
        "key": _sanitize(key),
        "method": request.method,
    })
    if request.method == "HEAD":
        return make_response("", 403)
    return _xml_error("AccessDenied", "Access Denied", 403)


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
