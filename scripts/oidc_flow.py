"""Walk the Druid pac4j OIDC login like a browser would, printing every hop.

usage: python3 -I oidc_flow.py <user> <password> [path-after-login ...]
Env: DRUID_URL (default http://localhost:8888).
Cookies are saved to cookies.json next to this script so later runs can reuse them
(pass --reuse as the first arg to skip login).
"""
import html
import http.cookies
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
JAR_FILE = os.path.join(HERE, "cookies.json")
DRUID_URL = os.environ.get("DRUID_URL", "http://localhost:8888")
DRUID_HOST = urllib.parse.urlsplit(DRUID_URL).netloc
jar = {}  # host -> {name: value}; ignores Secure/path like a localhost browser would


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


opener = urllib.request.build_opener(NoRedirect)


def req(method, url, data=None, headers=None, quiet=False):
    host = urllib.parse.urlsplit(url).netloc
    h = dict(headers or {})
    if jar.get(host):
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar[host].items())
    body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        resp = opener.open(r)
    except urllib.error.HTTPError as e:
        resp = e
    status = resp.status if hasattr(resp, "status") else resp.code
    for raw in resp.headers.get_all("Set-Cookie") or []:
        c = http.cookies.SimpleCookie()
        c.load(raw)
        for name, morsel in c.items():
            if morsel["max-age"] == "0" or morsel.value in ("", '""'):
                jar.setdefault(host, {}).pop(name, None)
            else:
                jar.setdefault(host, {})[name] = morsel.value
        if not quiet:
            attrs = "; ".join(p.strip() for p in raw.split(";")[1:])
            print(f"      Set-Cookie {raw.split('=')[0]} ({len(raw)} bytes) [{attrs}]")
    text = resp.read().decode(errors="replace")
    loc = resp.headers.get("Location")
    if not quiet:
        short = url if len(url) < 110 else url[:107] + "..."
        print(f"{method:4} {short}\n   -> {status}" + (f"  Location: {loc[:110]}" if loc else ""))
    return status, loc, text


def follow(method, url, data=None, headers=None):
    status, loc, text = req(method, url, data, headers)
    while status in (301, 302, 303, 307) and loc:
        url = urllib.parse.urljoin(url, loc)
        status, loc, text = req("GET", url)
    return status, url, text


def login(user, password):
    print("== 1. Browser asks the router for the console, unauthenticated")
    status, url, text = follow("GET", DRUID_URL + "/unified-console.html")
    m = re.search(r'action="([^"]+)"', text)
    if not m:
        print("No login form found; got status", status, text[:300])
        sys.exit(1)
    action = html.unescape(m.group(1))
    print(f"\n== 2. Submit credentials for {user} to the Keycloak login form")
    status, url, text = follow(
        "POST", action,
        urllib.parse.urlencode({"username": user, "password": password}),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    print(f"\n   landed on {url} with {status}, {len(text)} bytes")
    with open(JAR_FILE, "w") as f:
        json.dump(jar, f)


def main():
    args = sys.argv[1:]
    if args and args[0] == "--reuse":
        jar.update(json.load(open(JAR_FILE)))
        args = args[1:]
    else:
        login(args[0], args[1])
        args = args[2:]
    print("\n== Router cookies now held by the 'browser':", list(jar.get(DRUID_HOST, {})))
    for path in args:
        method, _, rest = path.partition(" ")
        if not rest:
            method, rest = "GET", path
        body = None
        headers = {}
        if method == "POST":
            rest, _, body = rest.partition(" ")
            headers["Content-Type"] = "application/json"
        status, loc, text = req(method, DRUID_URL + rest, body, headers, quiet=True)
        print(f"{method} {rest} -> {status}" + (f" Location: {loc[:90]}" if loc else f"  {text[:160]!r}"))
    with open(JAR_FILE, "w") as f:
        json.dump(jar, f)


main()
