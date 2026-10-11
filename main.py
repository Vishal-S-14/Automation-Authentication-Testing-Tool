#!/usr/bin/env python3
"""
Main launcher for Automated Authentication Testing Tool (AAT)
All modules are automated mitmproxy addons.
"""

import os
import sys
import subprocess


MITMPROXY_PORT = "8080"

SCRIPT_MAP = {
    "1": ("JWT Attack: Unverified Signature", "script1.py"),
    "2": ("JWT Attack: Flawed Signature Verification", "script2.py"),
    "3": ("JWT Attack: Brute-Force Secret Key", "script3.py"),
    "4": ("JWT Attack: JWK Header Injection", "script4.py"),
    "5": ("JWT Attack: JKU Injection", "script5.py"),
    "6": ("JWT Attack: KID Directory Traversal", "script6.py"),
    "7": ("JWT Attack: JWKS Scraper + HS256 Abuse", "script7.py"),
    "8": ("OAuth: Grant Type Detector", "script8.py"),
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def run_mitmproxy(script_name):
    print(f"[+] Launching mitmproxy addon: {script_name}")
    print(f"[+] Listening on port: {MITMPROXY_PORT}")

    subprocess.run(
        ["mitmproxy", "-p", MITMPROXY_PORT, "-s", script_name]
    )


# ==============================
#   BANNER
# ==============================
banner_text = r"""
   █████╗ █████╗ ████████╗
  ██╔══██╗██╔══██╗╚══██╔══╝
  ███████║███████║   ██║
  ██╔══██║██╔══██║   ██║
  ██║  ██║██║  ██║   ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

 Automated Authentication Testing Tool
     [ JWT | OAuth | Gen-Auth ]
"""


def menu():
    clear()
    print(banner_text)
    print("=============== ATTACK TOOLKIT ===============")
    for key, (desc, _) in SCRIPT_MAP.items():
        print(f"{key}. {desc}")
    print("0. Exit")
    print("==============================================\n")


def main():
    while True:
        menu()
        choice = input("Select module (1–8): ").strip()

        if choice == "0":
            print("Exiting...")
            sys.exit(0)

        if choice not in SCRIPT_MAP:
            input("Invalid choice. Press ENTER...")
            continue

        desc, script = SCRIPT_MAP[choice]
        print(f"\n[+] Selected: {desc}\n")

        run_mitmproxy(script)

        input("\n[✓] Module finished. Press ENTER to return to menu...")


if __name__ == "__main__":
    main()
