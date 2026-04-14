## duc_thien_doan_https_not_enforcement.py

**Goal:** Check whether `login.0x10.cloud` allows insecure HTTP access instead of forcing users onto HTTPS.

This script checks the login page over both HTTP and HTTPS. A login portal should force users onto HTTPS so credentials are encrypted. If the page stays on `http://`, it is a security risk.

The script uses:

- `rate_limit_pause()` to wait `0.15` seconds and respect the project rate limit
- `fetch_page()` to send the request, read part of the response, get the page title, and check the `Strict-Transport-Security` header
- `print_banner()` to show clear output in the terminal

The main logic is:

```python
http_not_redirected = http_final_url.startswith("http://")
https_available = isinstance(https_status, int) and 200 <= https_status < 400
hsts_missing = https_hsts == "Not set"
```

If the HTTP request still ends on `http://`, the site is not enforcing HTTPS. If HTTPS is available but users are not redirected, the login page can still be used insecurely. If HSTS is missing, browsers are not told to always use HTTPS.

The `try/except` blocks handle cases where the server is down, refuses the connection, or returns an error. At the end, the script prints either a vulnerability report or an OK message.

---

## gia_duc_can_http_security_header.py

**Goal:** Check whether `api.0x10.cloud` is missing important security headers on HTTP and HTTPS.

This script sends requests to both versions of the target and looks for missing headers such as `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security`. Missing these headers can increase the risk of attacks like clickjacking, MIME-type confusion, and weaker browser-side protection.

The script uses:

- `check_security_headers()` to request the page, read the response headers, and build a list of missing security headers
- `print_banner()` to display the script information clearly in the terminal

The main logic is:

```python
for h in [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]:
    if h not in headers:
        missing.append(h)
```

If a required header is not found, it is added to the `missing` list. The script checks both HTTP and HTTPS, then prints a short report showing which headers are missing and whether the issue affects one or both versions of the site.

The `try/except` block handles connection or request errors cleanly. If something goes wrong, the script returns an error marker instead of crashing.

---

## tan_phat_nguyen_ssrf.py

**Goal:** Check whether `webhook.0x10.cloud` can be abused for SSRF by making the server request internal addresses.

This script sends controlled `url` parameters to the webhook service and compares the response length for external and internal targets. If the server responds differently to `127.0.0.1` or an internal port like `6379`, that suggests SSRF.

The script uses:

- `verify_service()` to confirm the webhook endpoint is reachable before testing
- `fetch_length()` to request a URL and return the response length
- `test_ssrf()` to compare external and internal requests and collect findings
- `rate_limit_pause()` to respect the project rate limit

The main logic is:

```python
external_len = fetch_length(base_url + "?url=http://example.com")
internal_len = fetch_length(base_url + "?url=http://127.0.0.1")
redis_len = fetch_length(base_url + "?url=http://127.0.0.1:6379")
```

If an internal request works or produces a different response from the external one, the script reports possible SSRF. This matters because SSRF can let an attacker make the server access internal services that should not be publicly reachable.

The `try/except` blocks keep the script from crashing when a request fails. At the end, it prints either the SSRF findings or an OK message.

---

## tien_le_rce.py

**Goal:** Check whether `jenkins.0x10.cloud/script` exposes the Jenkins Script Console without authentication.

This script connects to the Jenkins Script Console page and checks whether it can be accessed directly. If the page does not require login and contains keywords like `script` or `groovy`, that suggests the console is exposed and could lead to remote code execution.

The script uses:

- `rate_limit_pause()` to respect the project rate limit
- `check_jenkins_script_console()` to request the page and look for signs of unauthenticated Script Console access
- `print_banner()` to show clear script information in the terminal

The main logic is:

```python
if "login" not in body.lower():
    if "script" in body.lower() or "groovy" in body.lower():
        return True
```

If the response does not show a login page and includes Script Console indicators, the script reports a vulnerability. This is serious because an exposed Jenkins Script Console can allow attackers to run arbitrary code on the server.

The `try/except` blocks handle HTTP, connection, and unexpected errors cleanly. At the end, the script prints whether the target appears vulnerable or secure.

---

## Patterns to Reuse

When you write your own vulnerability scripts, you'll use the same building blocks:

| Task                  | Module           | Key function                             |
| --------------------- | ---------------- | ---------------------------------------- |
| HTTP request (GET)    | `urllib.request` | `urlopen(url)`                           |
| HTTP request (POST)   | `urllib.request` | `urlopen(Request(url, data=...))`        |
| Read response headers | `urllib.request` | `dict(response.headers)`                 |
| TCP port check        | `socket`         | `sock.connect_ex((host, port))`          |
| Send/receive raw TCP  | `socket`         | `sock.sendall(data)` / `sock.recv(1024)` |
| Read response body    | `urllib.request` | `response.read().decode()`               |
| Parse JSON response   | `json`           | `json.loads(body)`                       |
| Decode base64         | `base64`         | `base64.b64decode(data)`                 |
| Rate limit yourself   | `time`           | `time.sleep(0.15)`                       |

Every vulnerability on `0x10.cloud` can be found using some combination of these.
