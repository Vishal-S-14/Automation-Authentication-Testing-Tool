# oauth_grant_type_detector_realworld.py
# REAL-WORLD OAuth 2.0 Grant Type Detector
# Logs structured results to grant_type_results.txt

from mitmproxy import http
from urllib.parse import urlparse, parse_qs
import json
import time
import os

OUTPUT_FILE = "grant_type_results.txt"
observed = set()


# -------------------------------------------------
# Utility: Write structured logs to file
# -------------------------------------------------
def write_log(entry):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def log(domain, grant, reason, confidence="HIGH"):
    key = (domain, grant)
    if key in observed:
        return
    observed.add(key)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    entry = (
        f"[{timestamp}]\n"
        f"Domain      : {domain}\n"
        f"Grant Type  : {grant}\n"
        f"Confidence  : {confidence}\n"
        f"Reason      : {reason}\n"
        f"{'-'*60}"
    )

    print(entry)
    write_log(entry)


# -------------------------------------------------
# Utility: Extract grant_type from body
# Supports:
# - application/x-www-form-urlencoded
# - JSON bodies
# -------------------------------------------------
def extract_grant_type(flow):
    content_type = flow.request.headers.get("Content-Type", "").lower()
    body = flow.request.get_text()

    # 1️⃣ JSON
    if "application/json" in content_type:
        try:
            data = json.loads(body)
            return data.get("grant_type", "").lower()
        except:
            return ""

    # 2️⃣ Form encoded
    parsed = parse_qs(body)
    if "grant_type" in parsed:
        return parsed["grant_type"][0].lower()

    return ""


# -------------------------------------------------
# REQUEST ANALYSIS
# -------------------------------------------------
def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    query = parse_qs(parsed_url.query)

    grant_type = extract_grant_type(flow)
    body = flow.request.get_text().lower()
    headers = {k.lower(): v.lower() for k, v in flow.request.headers.items()}

    # ---------------------------------------------
    # AUTHORIZATION ENDPOINT DETECTION
    # ---------------------------------------------
    if "response_type" in query:
        response_type = query["response_type"][0]

        if response_type == "code":
            if "code_challenge" in query:
                log(domain,
                    "Authorization Code Grant (PKCE)",
                    "response_type=code with PKCE challenge")
            else:
                log(domain,
                    "Authorization Code Grant",
                    "response_type=code observed",
                    confidence="MEDIUM")

        if response_type == "token":
            log(domain,
                "Implicit Grant",
                "response_type=token in authorization request")

    # ---------------------------------------------
    # TOKEN ENDPOINT DETECTION
    # ---------------------------------------------
    if grant_type:

        # Authorization Code
        if grant_type == "authorization_code":
            log(domain,
                "Authorization Code Grant",
                "grant_type=authorization_code in token request")

        # Refresh Token
        elif grant_type == "refresh_token":
            log(domain,
                "Refresh Token Grant",
                "grant_type=refresh_token in token request")

        # Client Credentials
        elif grant_type == "client_credentials":
            log(domain,
                "Client Credentials Grant",
                "grant_type=client_credentials detected")

        # Password (ROPC)
        elif grant_type == "password":
            log(domain,
                "Resource Owner Password Credentials (ROPC)",
                "grant_type=password detected")

        # Device Code
        elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            log(domain,
                "Device Code Grant",
                "device_code flow detected")

        # JWT Bearer
        elif grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            log(domain,
                "JWT Bearer Grant",
                "JWT bearer assertion detected")

        # SAML Bearer
        elif grant_type == "urn:ietf:params:oauth:grant-type:saml2-bearer":
            log(domain,
                "SAML Bearer Grant",
                "SAML bearer assertion detected")

        else:
            log(domain,
                f"Unknown Grant ({grant_type})",
                "Unrecognized grant_type value",
                confidence="LOW")

    # ---------------------------------------------
    # Heuristic Client Credentials Detection
    # ---------------------------------------------
    if (
        headers.get("authorization", "").startswith("basic")
        and "/token" in url
        and "username=" not in body
        and not grant_type
    ):
        log(domain,
            "Client Credentials (Inferred)",
            "Basic auth used at token endpoint without explicit grant_type",
            confidence="MEDIUM")


# -------------------------------------------------
# RESPONSE ANALYSIS
# Detect tokens from responses
# -------------------------------------------------
def response(flow: http.HTTPFlow):
    domain = urlparse(flow.request.pretty_url).netloc
    content_type = flow.response.headers.get("Content-Type", "").lower()

    if "application/json" in content_type:
        try:
            data = json.loads(flow.response.get_text())

            if "access_token" in data:
                if "refresh_token" in data:
                    log(domain,
                        "Access + Refresh Token Issuance",
                        "Token response contains access_token and refresh_token",
                        confidence="HIGH")
                else:
                    log(domain,
                        "Access Token Issuance",
                        "Token response contains access_token",
                        confidence="MEDIUM")

        except:
            pass


# -------------------------------------------------
# FINAL SUMMARY
# -------------------------------------------------
def done():
    summary = "\n========== FINAL OAUTH GRANT TYPES DETECTED ==========\n"

    if not observed:
        summary += "No OAuth grant types detected.\n"
    else:
        for domain, grant in observed:
            summary += f"{domain} → {grant}\n"

    summary += "=====================================================\n"

    print(summary)
    write_log(summary)
