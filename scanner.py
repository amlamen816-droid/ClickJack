"""scanner.py - reusable HTTP scanner for ClickJack; Python Standard Library only."""
import ssl, urllib.error, urllib.request
from urllib.parse import urlsplit

def normalize_url(url):
    if "://" not in url: url = "https://" + url
    p = urlsplit(url)
    if p.scheme not in ("http","https") or not p.hostname:
        raise ValueError("Invalid HTTP/HTTPS URL.")
    return url

def fetch_headers(url, timeout=10, verify_tls=True):
    url = normalize_url(url)
    req = urllib.request.Request(url, headers={"User-Agent":"ClickJack/1.0"}, method="GET")
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.geturl(), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.geturl(), e.code, dict(e.headers)

if __name__ == "__main__":
    print("scanner.py is the helper module. Run: python clickjack.py --help")