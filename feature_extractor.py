"""
Phase 2 — Feature Extraction Pipeline
Phishing Detection System

Extracts all 30 UCI-compatible features from a raw URL.
Each feature returns: -1 (phishing indicator), 0 (neutral), 1 (legitimate)

Usage:
    from feature_extractor import extract_features
    features = extract_features("http://example.com")
"""

import re
import ssl
import socket
import urllib.parse
import ipaddress
from datetime import datetime, timezone
from typing import Union

# ── Optional heavy imports (graceful fallback if not installed) ─────────────
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _parse_url(url: str) -> urllib.parse.ParseResult:
    """Ensure URL has a scheme before parsing."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urllib.parse.urlparse(url)


def _get_domain(url: str) -> str:
    parsed = _parse_url(url)
    return parsed.netloc.split(":")[0]  # strip port if present


def _fetch_page(url: str, timeout: int = 5):
    """Fetch page HTML. Returns (response, soup) or (None, None)."""
    if not REQUESTS_AVAILABLE:
        return None, None
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, timeout=timeout, headers=headers,
                            allow_redirects=True, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp, soup
    except Exception:
        return None, None


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE FUNCTIONS  (one per UCI feature, documented)
# ═══════════════════════════════════════════════════════════════════════════

# ── URL-based features (no network required) ──────────────────────────────

def f01_having_ip_address(url: str) -> int:
    """
    Check if the URL uses an IP address instead of a domain name.
    Phishing sites often use raw IPs to avoid domain registration.
    -1 = IP found (suspicious), 1 = domain name used (normal)
    """
    domain = _get_domain(url)
    try:
        ipaddress.ip_address(domain)
        return -1  # it's an IP
    except ValueError:
        pass
    # Also catch IP patterns in the URL path
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    if re.search(ip_pattern, url):
        return -1
    return 1


def f02_url_length(url: str) -> int:
    """
    Long URLs are a common phishing trick to hide the real domain.
    < 54 chars → 1 (legit), 54–75 → 0 (suspicious), > 75 → -1 (phishing)
    """
    length = len(url)
    if length < 54:
        return 1
    elif length <= 75:
        return 0
    return -1


def f03_shortining_service(url: str) -> int:
    """
    URL shortening services (bit.ly, tinyurl, etc.) hide the real destination.
    -1 = shortener detected, 1 = full URL
    """
    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
        "is.gd", "buff.ly", "adf.ly", "shorte.st", "rebrand.ly",
        "cutt.ly", "tiny.cc", "lnkd.in", "tr.im", "su.pr"
    ]
    domain = _get_domain(url).lower()
    for s in shorteners:
        if s in domain:
            return -1
    return 1


def f04_having_at_symbol(url: str) -> int:
    """
    '@' in URL causes browser to ignore everything before it.
    Example: http://legit.com@evil.com  → goes to evil.com
    -1 = @ found, 1 = no @
    """
    return -1 if "@" in url else 1


def f05_double_slash_redirecting(url: str) -> int:
    """
    '//' appearing after the domain (not the protocol) is a redirect trick.
    Check position of last '//' — if not at position 6 or 7, it's suspicious.
    -1 = suspicious redirect, 1 = normal
    """
    # Strip the protocol part before checking
    path = url.replace("https://", "").replace("http://", "")
    return -1 if "//" in path else 1


def f06_prefix_suffix(url: str) -> int:
    """
    Hyphens in domain name (e.g., secure-paypal.com) are a phishing tell.
    -1 = hyphen in domain, 1 = no hyphen
    """
    domain = _get_domain(url)
    return -1 if "-" in domain else 1


def f07_having_sub_domain(url: str) -> int:
    """
    Legitimate sites rarely have more than one subdomain.
    1 dot  → 1 (legit)
    2 dots → 0 (suspicious)
    3+ dots → -1 (phishing)
    """
    domain = _get_domain(url)
    # Remove www prefix for counting
    domain_clean = re.sub(r"^www\.", "", domain)
    dots = domain_clean.count(".")
    if dots == 1:
        return 1
    elif dots == 2:
        return 0
    return -1


def f08_ssl_final_state(url: str) -> int:
    """
    Check if site uses HTTPS with a valid SSL certificate.
    HTTPS with valid cert → 1, HTTPS without valid cert → 0, HTTP only → -1
    """
    if not url.startswith("https"):
        return -1
    domain = _get_domain(url)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        return 1  # valid cert
    except ssl.SSLCertVerificationError:
        return 0  # HTTPS but invalid cert
    except Exception:
        return 0  # could not verify


def f09_domain_registration_length(url: str) -> int:
    """
    Phishing domains are usually registered for < 1 year.
    Requires python-whois. Falls back to 0 if unavailable.
    > 1 year expiry → 1, < 1 year → -1
    """
    if not WHOIS_AVAILABLE:
        return 0  # neutral when can't check
    domain = _get_domain(url)
    try:
        w = python_whois.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry is None:
            return -1
        # Make expiry timezone-aware if it isn't
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days
        return 1 if days_left > 365 else -1
    except Exception:
        return 0


def f10_favicon(url: str, soup=None) -> int:
    """
    If favicon is loaded from a different domain, it's suspicious.
    1 = same domain or no favicon, -1 = external favicon
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    icon = soup.find("link", rel=lambda r: r and "icon" in r)
    if icon and icon.get("href"):
        href = icon["href"]
        if href.startswith("http") and domain not in href:
            return -1
    return 1


def f11_port(url: str) -> int:
    """
    Non-standard ports (not 80/443) are suspicious.
    Standard port or no port → 1, non-standard → -1
    """
    parsed = _parse_url(url)
    port = parsed.port
    if port is None or port in (80, 443):
        return 1
    return -1


def f12_https_token(url: str) -> int:
    """
    Having 'https' in the domain name itself (e.g., https-paypal.com)
    is a trick to make the URL look secure.
    -1 = 'https' token in domain, 1 = clean domain
    """
    domain = _get_domain(url).lower()
    return -1 if "https" in domain else 1


# ── Content-based features (requires HTTP fetch) ──────────────────────────

def f13_request_url(url: str, soup=None) -> int:
    """
    % of external objects (img, script, link) loaded from different domain.
    < 22% external → 1, 22–61% → 0, > 61% → -1
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    tags = soup.find_all(["img", "script", "link"])
    if not tags:
        return 1
    external = sum(
        1 for t in tags
        if t.get("src", t.get("href", "")).startswith("http")
        and domain not in t.get("src", t.get("href", ""))
    )
    pct = external / len(tags) * 100
    if pct < 22:
        return 1
    elif pct <= 61:
        return 0
    return -1


def f14_url_of_anchor(url: str, soup=None) -> int:
    """
    % of anchor <a> tags pointing to different domain or empty (#, javascript:).
    < 31% → 1, 31–67% → 0, > 67% → -1
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    anchors = soup.find_all("a", href=True)
    if not anchors:
        return 1
    suspicious = sum(
        1 for a in anchors
        if not a["href"].startswith(("http", "/"))
        or (a["href"].startswith("http") and domain not in a["href"])
    )
    pct = suspicious / len(anchors) * 100
    if pct < 31:
        return 1
    elif pct <= 67:
        return 0
    return -1


def f15_links_in_tags(url: str, soup=None) -> int:
    """
    % of <meta>, <script>, <link> tags with external links.
    < 17% → 1, 17–81% → 0, > 81% → -1
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    tags = soup.find_all(["meta", "script", "link"])
    if not tags:
        return 1
    external = sum(
        1 for t in tags
        for attr in ["src", "href", "content"]
        if t.get(attr, "").startswith("http") and domain not in t.get(attr, "")
    )
    pct = external / len(tags) * 100
    if pct < 17:
        return 1
    elif pct <= 81:
        return 0
    return -1


def f16_sfh(url: str, soup=None) -> int:
    """
    Server Form Handler: check where forms POST their data.
    Same domain → 1, about:blank or empty → -1, different domain → 0
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    forms = soup.find_all("form", action=True)
    if not forms:
        return 1
    for form in forms:
        action = form["action"].lower()
        if action in ("", "about:blank", "#"):
            return -1
        if action.startswith("http") and domain not in action:
            return 0
    return 1


def f17_submitting_to_email(url: str, soup=None) -> int:
    """
    If form action uses mailto: it submits data via email — classic phishing.
    -1 = mailto found, 1 = no mailto
    """
    if soup is None:
        return 0
    forms = soup.find_all("form", action=True)
    for form in forms:
        if "mailto:" in form["action"].lower():
            return -1
    return 1


def f18_abnormal_url(url: str) -> int:
    """
    Check if the hostname appears in the URL string (basic WHOIS check).
    Phishing URLs often have mismatched hostnames.
    This does a simple structural check without WHOIS.
    1 = hostname found in URL, -1 = mismatch
    """
    domain = _get_domain(url)
    return 1 if domain in url else -1


def f19_redirect(url: str, response=None) -> int:
    """
    Count of redirects. 0–1 → 1 (normal), 2 → 0, > 2 → -1 (suspicious)
    """
    if response is None:
        return 0
    redirects = len(response.history)
    if redirects <= 1:
        return 1
    elif redirects == 2:
        return 0
    return -1


def f20_on_mouseover(url: str, soup=None) -> int:
    """
    Phishing pages use onmouseover events to change the status bar URL.
    -1 = onmouseover to change status bar found, 1 = clean
    """
    if soup is None:
        return 0
    html = str(soup)
    if "onmouseover" in html.lower() and "window.status" in html.lower():
        return -1
    return 1


def f21_right_click(url: str, soup=None) -> int:
    """
    Disabling right-click (to prevent 'View Source') is a phishing trick.
    -1 = right-click disabled, 1 = normal
    """
    if soup is None:
        return 0
    html = str(soup)
    if "event.button==2" in html or "contextmenu" in html.lower():
        return -1
    return 1


def f22_popup_window(url: str, soup=None) -> int:
    """
    Pop-up windows with text fields (fake login prompts) are phishing signs.
    -1 = suspicious popup detected, 1 = clean
    """
    if soup is None:
        return 0
    html = str(soup)
    if "window.open" in html and ("prompt(" in html or "confirm(" in html):
        return -1
    return 1


def f23_iframe(url: str, soup=None) -> int:
    """
    Phishing pages use invisible iframes to load malicious content.
    No iframe → 1, visible iframe → 0, invisible/hidden iframe → -1
    """
    if soup is None:
        return 0
    iframes = soup.find_all("iframe")
    if not iframes:
        return 1
    for iframe in iframes:
        style = iframe.get("style", "").lower()
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
            return -1
        width  = iframe.get("width", "100")
        height = iframe.get("height", "100")
        if str(width) == "0" or str(height) == "0":
            return -1
    return 0


# ── Domain age / reputation features ──────────────────────────────────────

def f24_age_of_domain(url: str) -> int:
    """
    Phishing domains are newly created — usually < 6 months old.
    > 6 months → 1, < 6 months → -1
    Requires python-whois.
    """
    if not WHOIS_AVAILABLE:
        return 0
    domain = _get_domain(url)
    try:
        w = python_whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return -1
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - creation).days
        return 1 if age_days > 180 else -1
    except Exception:
        return 0


def f25_dns_record(url: str) -> int:
    """
    If no DNS record exists for the domain, it's almost certainly phishing.
    DNS found → 1, no DNS → -1
    """
    domain = _get_domain(url)
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.gaierror:
        return -1


def f26_web_traffic(url: str) -> int:
    """
    Legitimate sites have traffic rank data. Phishing sites don't.
    This is a simplified proxy: checks if domain resolves + has valid TLD.
    High traffic → 1, low/unknown → 0, no data → -1
    """
    if not TLDEXTRACT_AVAILABLE:
        return 0
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return -1
    # Proxy: if DNS resolves, assume some traffic
    try:
        socket.gethostbyname(_get_domain(url))
        return 0  # can't know rank without API, default to neutral
    except Exception:
        return -1


def f27_page_rank(url: str) -> int:
    """
    PageRank < 0.2 → -1 (phishing), 0.2–0.6 → 0, > 0.6 → 1.
    Without access to PageRank API, use domain age as proxy.
    Returns 0 (neutral) unless we have strong signals.
    """
    # Without a PageRank API, use SSL + DNS as proxy signals
    has_ssl   = 1 if url.startswith("https") else -1
    has_dns   = f25_dns_record(url)
    score     = has_ssl + has_dns
    if score == 2:
        return 1
    elif score == -2:
        return -1
    return 0


def f28_google_index(url: str) -> int:
    """
    Check if page is indexed by Google (proxy: domain resolves + HTTPS).
    1 = likely indexed, -1 = likely not indexed
    Note: real check requires Google Search API.
    """
    has_ssl = url.startswith("https")
    has_dns = f25_dns_record(url) == 1
    return 1 if (has_ssl and has_dns) else -1


def f29_links_pointing_to_page(url: str, soup=None) -> int:
    """
    Number of links pointing to the page (backlinks).
    Without an API, we count internal vs external links as proxy.
    > 2 pointing in → 1, 0–1 → -1
    """
    if soup is None:
        return 0
    domain = _get_domain(url)
    internal = [
        a for a in soup.find_all("a", href=True)
        if domain in a["href"]
    ]
    count = len(internal)
    if count > 2:
        return 1
    elif count == 0:
        return -1
    return 0


def f30_statistical_report(url: str) -> int:
    """
    Check if the host/IP appears in known phishing databases.
    Uses a small static list of known malicious TLDs + patterns.
    -1 = suspicious pattern, 1 = no match
    Note: production system should query PhishTank/Google Safe Browsing API.
    """
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
    domain = _get_domain(url).lower()
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return -1
    # Known phishing keywords in domain
    phishing_keywords = ["secure", "account", "update", "login", "verify",
                         "banking", "confirm", "paypal", "ebay", "amazon"]
    domain_lower = domain.lower()
    matches = sum(1 for kw in phishing_keywords if kw in domain_lower)
    if matches >= 2:
        return -1
    return 1


# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXTRACTION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Pref_suf", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token",
    "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email",
    "Abnormal_URL", "Redirect", "on_mouseover", "RightClick", "popUpWidnow",
    "Iframe", "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
    "Google_Index", "Links_pointing_to_page", "Statistical_report"
]


def extract_features(url: str, fetch_page: bool = True, verbose: bool = False) -> dict:
    """
    Extract all 30 UCI phishing features from a raw URL.

    Args:
        url         : The URL to analyse (with or without scheme)
        fetch_page  : If True, fetches the page for content-based features
        verbose     : If True, prints each feature value

    Returns:
        dict with keys = FEATURE_NAMES, values = -1 / 0 / 1
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Fetch page once (reuse for all content features)
    response, soup = None, None
    if fetch_page:
        response, soup = _fetch_page(url)

    feature_funcs = [
        lambda u: f01_having_ip_address(u),
        lambda u: f02_url_length(u),
        lambda u: f03_shortining_service(u),
        lambda u: f04_having_at_symbol(u),
        lambda u: f05_double_slash_redirecting(u),
        lambda u: f06_prefix_suffix(u),
        lambda u: f07_having_sub_domain(u),
        lambda u: f08_ssl_final_state(u),
        lambda u: f09_domain_registration_length(u),
        lambda u: f10_favicon(u, soup),
        lambda u: f11_port(u),
        lambda u: f12_https_token(u),
        lambda u: f13_request_url(u, soup),
        lambda u: f14_url_of_anchor(u, soup),
        lambda u: f15_links_in_tags(u, soup),
        lambda u: f16_sfh(u, soup),
        lambda u: f17_submitting_to_email(u, soup),
        lambda u: f18_abnormal_url(u),
        lambda u: f19_redirect(u, response),
        lambda u: f20_on_mouseover(u, soup),
        lambda u: f21_right_click(u, soup),
        lambda u: f22_popup_window(u, soup),
        lambda u: f23_iframe(u, soup),
        lambda u: f24_age_of_domain(u),
        lambda u: f25_dns_record(u),
        lambda u: f26_web_traffic(u),
        lambda u: f27_page_rank(u),
        lambda u: f28_google_index(u),
        lambda u: f29_links_pointing_to_page(u, soup),
        lambda u: f30_statistical_report(u),
    ]

    features = {}
    for name, fn in zip(FEATURE_NAMES, feature_funcs):
        try:
            val = fn(url)
        except Exception as e:
            val = 0  # neutral on error
            if verbose:
                print(f"  [WARN] {name}: {e}")
        features[name] = val
        if verbose:
            tag = "✓ legit" if val == 1 else ("✗ phish" if val == -1 else "~ neutral")
            print(f"  {name:<35} {val:>2}   {tag}")

    return features


def batch_extract(urls: list, fetch_page: bool = False) -> "pd.DataFrame":
    """
    Extract features for a list of URLs. Returns a DataFrame.
    fetch_page=False by default for speed in batch mode.
    """
    import pandas as pd
    rows = []
    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {url[:60]}...")
        rows.append(extract_features(url, fetch_page=fetch_page))
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


# ═══════════════════════════════════════════════════════════════════════════
# QUICK DEMO
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    print("=" * 60)
    print("  PHASE 2 — FEATURE EXTRACTION DEMO")
    print("=" * 60)

    test_urls = [
        ("LEGITIMATE", "https://www.github.com"),
        ("SUSPICIOUS",  "http://192.168.1.1/login/paypal-verify"),
        ("PHISHING",    "http://secure-paypal-login.tk@evil.com/update"),
        ("PHISHING",    "http://bit.ly/3xYzAbC"),
    ]

    for label, url in test_urls:
        print(f"\n[{label}] {url}")
        print("-" * 58)
        features = extract_features(url, fetch_page=False, verbose=True)

        legit_count   = sum(1 for v in features.values() if v ==  1)
        phish_count   = sum(1 for v in features.values() if v == -1)
        neutral_count = sum(1 for v in features.values() if v ==  0)
        score = legit_count - phish_count

        print(f"\n  Summary: {legit_count} legit | {phish_count} phishing | {neutral_count} neutral")
        print(f"  Score  : {score:+d}  ({'LIKELY LEGITIMATE' if score > 5 else 'LIKELY PHISHING' if score < 0 else 'UNCERTAIN'})")

    print("\n" + "=" * 60)
    print("  Feature extraction pipeline ready.")
    print("  Import with: from feature_extractor import extract_features")
    print("=" * 60)
