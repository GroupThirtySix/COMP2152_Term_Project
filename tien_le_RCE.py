# ============================================================
#  Author: Tien Le
#  Vulnerability: Jenkins Script Console Exposure (RCE)
#  Target: jenkins.0x10.cloud
# ============================================================
#
#  Flow:
#  1. Connect to Jenkins endpoint
#  2. Check if accessible without authentication
#  3. Detect Script Console exposure
#  4. Report vulnerability
# ============================================================

import urllib.request
import urllib.error
import time

AUTHOR = "Tien Le"
TARGET = "https://jenkins.0x10.cloud/script"
TIMEOUT = 5
RATE_LIMIT_DELAY = 0.15
USER_AGENT = "COMP2152-Term-Project/1.0"

def rate_limit_pause():
    time.sleep(RATE_LIMIT_DELAY)

def check_jenkins_script_console(url):
    try:
        rate_limit_pause()

        print("[*] Connecting to Jenkins Script Console...")

        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT}
        )

        response = urllib.request.urlopen(request, timeout=TIMEOUT)
        body = response.read().decode("utf-8", "ignore")
        print(f"[*] HTTP Status: {response.status}")
        if "login" not in body.lower():
            print("[!] Accessible without authentication")
       
            if "script" in body.lower() or "groovy" in body.lower():
                print("[!] Script Console detected")

                print("\n[!] VULNERABILITY FOUND!")
                print("Jenkins Script code console is exposed without authentication.")
                print("Risk: Remote Code Execution ")
                print("Attackers can execute arbitrary code on the server.")

                return True

        print("[OK] No vulnerability detected")
        return False

    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP Error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print(f"[ERROR] Connection failed: {e.reason}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

    return False


def print_banner():
    print("=" * 60)
    print("  COMP2152 Term Project - Vulnerability Script")
    print("=" * 60)
    print(f"  Author:  {AUTHOR}")
    print(f"  Target:  jenkins.0x10.cloud")
    print(f"  Type:    RCE (Jenkins Script Console)")
    print("=" * 60)


def main():
    print_banner()

    print("\n[1] CONNECT")
    print(f"    URL: {TARGET}   ")

    print("\n[2] CHECK")
    vulnerable = check_jenkins_script_console(TARGET)

    print("\n[3] REPORT")
    if vulnerable:
        print("    [!] VULNERABILITY CONFIRMED")
        print("    Jenkins is exposed without authentication.")
        print("    Script Console allows remote code execution.")
    else:
        print("    [OK] Target appears secure")

    print("\n" + "=" * 60)


if _name_ == "_main_":
    main()