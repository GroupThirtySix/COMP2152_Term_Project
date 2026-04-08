# ============================================================
#  Author: Gia Duc Can
#  Vulnerability: Missing Security Headers
#  Target: api.0x10.cloud
# ============================================================
#
#  Flow:
#  1. Connect to the target over HTTP and HTTPS
#  2. Check for missing security headers
#  3. Report the security weaknesses
# ============================================================

import urllib.request

AUTHOR = "Gia Duc Can"
VULNERABILITY = "Missing Security Headers"
SUBDOMAIN = "api.0x10.cloud"
HTTP_TARGET = f"http://{SUBDOMAIN}"
HTTPS_TARGET = f"https://{SUBDOMAIN}"
TIMEOUT = 5
USER_AGENT = "COMP2152-Term-Project/1.0"


def check_security_headers(url):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        response = urllib.request.urlopen(request, timeout=TIMEOUT)
        headers = dict(response.headers)

        missing = []

        for h in [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]:
            if h not in headers:
                missing.append(h)

        return response.status, response.url, missing, headers.get("Strict-Transport-Security", "Not set")
    except Exception as e:
        return None, url, ["Error"], str(e)


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

    print("\n[1] CHECK HTTP")
    http_status, http_url, http_missing, _ = check_security_headers(HTTP_TARGET)
    print(f"    HTTP target:    {HTTP_TARGET}")
    print(f"    HTTP status:    {http_status}")
    print(f"    Missing headers: {http_missing}")

    print("\n[2] CHECK HTTPS")
    https_status, https_url, https_missing, hsts = check_security_headers(HTTPS_TARGET)
    print(f"    HTTPS target:   {HTTPS_TARGET}")
    print(f"    HTTPS status:   {https_status}")
    print(f"    Missing headers: {https_missing}")
    print(f"    HSTS header:    {hsts}")

    print("\n[3] REPORT")
    if http_missing and "Error" not in http_missing:
        print("    [!] VULNERABILITY FOUND on HTTP")
        print(f"    Missing security headers: {http_missing}")
        print("    Risk: Increased attack surface on HTTP.")
    else:
        print("    [OK] HTTP has all security headers or is unavailable.")

    if https_missing and "Error" not in https_missing:
        print("    [!] VULNERABILITY FOUND on HTTPS")
        print(f"    Missing security headers: {https_missing}")
        print("    Risk: Increased attack surface on HTTPS.")
    else:
        print("    [OK] HTTPS has all security headers or is unavailable.")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
