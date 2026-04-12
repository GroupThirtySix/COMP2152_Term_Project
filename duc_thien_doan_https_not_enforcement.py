# ============================================================
#  Author: Duc Thien Doan
#  Vulnerability: Login portal does not enforce HTTPS
#  Target: login.0x10.cloud
# ============================================================
#
#  Flow:
#  1. Connect to the login portal over HTTP
#  2. Check whether it stays on HTTP instead of redirecting
#  3. Report the transport security weakness
# ============================================================

import re
import time
import urllib.error
import urllib.request

AUTHOR = "Duc Thien Doan"
VULNERABILITY = "Login portal does not enforce HTTPS"
SUBDOMAIN = "login.0x10.cloud"
HTTP_TARGET = f"http://{SUBDOMAIN}"
HTTPS_TARGET = f"https://{SUBDOMAIN}"
TIMEOUT = 5
RATE_LIMIT_DELAY = 0.15
USER_AGENT = "COMP2152-Term-Project/1.0"


def rate_limit_pause():
    time.sleep(RATE_LIMIT_DELAY)


def fetch_page(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    rate_limit_pause()
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read(1500).decode("utf-8", "ignore")
        title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else "No title found"
        hsts = response.headers.get("Strict-Transport-Security", "Not set")
        return response.status, response.url, title, hsts


def print_banner():
    print("=" * 60)
    print("  COMP2152 Term Project - Personal Vulnerability Script")
    print("=" * 60)
    print(f"  Author:        {AUTHOR}")
    print(f"  Target:        {SUBDOMAIN}")
    print(f"  Finding:       {VULNERABILITY}")
    print("=" * 60)


def main():
    print_banner()

    try:
        http_status, http_final_url, page_title, _ = fetch_page(HTTP_TARGET)
    except urllib.error.HTTPError as error:
        print(f"\n[ERROR] HTTP error while connecting to {HTTP_TARGET}: {error.code} {error.reason}")
        print("\n" + "=" * 60)
        return
    except urllib.error.URLError as error:
        print(f"\n[ERROR] Could not reach {HTTP_TARGET}: {error.reason}")
        print("\n" + "=" * 60)
        return
    except Exception as error:
        print(f"\n[ERROR] Unexpected failure: {error}")
        print("\n" + "=" * 60)
        return

    try:
        https_status, https_final_url, _, https_hsts = fetch_page(HTTPS_TARGET)
    except Exception:
        https_status = None
        https_final_url = "Unavailable"
        https_hsts = "Unavailable"

    print("\n[1] CONNECT")
    print(f"    HTTP target:    {HTTP_TARGET}")
    print(f"    HTTP status:    {http_status}")
    print(f"    Page title:     {page_title}")

    print("\n[2] CHECK")
    print(f"    Final HTTP URL: {http_final_url}")
    print(f"    HTTPS status:   {https_status if https_status is not None else 'Unavailable'}")
    print(f"    HTTPS URL:      {https_final_url}")
    print(f"    HSTS header:    {https_hsts}")

    http_not_redirected = http_final_url.startswith("http://")
    https_available = isinstance(https_status, int) and 200 <= https_status < 400
    hsts_missing = https_hsts == "Not set"

    print("\n[3] REPORT")
    if http_not_redirected:
        print("    [!] VULNERABILITY FOUND")
        print("    The login portal is accessible over plain HTTP.")
        if https_available:
            print("    HTTPS exists, but users are not forced onto it.")
        else:
            print("    HTTPS was not available during this check.")
        if hsts_missing:
            print("    Strict-Transport-Security is not set.")
        print("    Credentials could be exposed to interception on an unsafe network.")
    else:
        print("    [OK] The login portal redirected away from HTTP.")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
