#!/usr/bin/env python3
"""
Find VLESS/VMess/Trojan/SS configs from Haj‑Karim databases.
Matches user‑supplied criteria from environment variables.
Now handles base64-encoded database files.
"""

import os, re, sys, json, base64, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# Database URLs – same list you provided
# ---------------------------------------------------------------------------
DATABASE_URLS = [
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_1.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_2.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_3.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_4.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_5.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_6.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/database/Database_7.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/database/Database_1.txt",
]

# ---------------------------------------------------------------------------
# Helper: fetch and decode a database URL
# ---------------------------------------------------------------------------
def fetch_and_decode(url: str):
    """Download URL, try base64 decode, fallback to plain text.
    Returns list of non‑empty stripped lines."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GitHub-Action/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.URLError as e:
        print(f"[WARN] Failed to fetch {url}: {e}", file=sys.stderr)
        return []

    # Try base64 decoding the whole blob
    try:
        decoded_bytes = base64.b64decode(raw)
        text = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        # Not base64, treat as plain text
        text = raw.decode("utf-8", errors="ignore")

    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    return lines

# ---------------------------------------------------------------------------
# Parse a share‑link into a dict
# ---------------------------------------------------------------------------
def parse_share_link(link: str):
    if "://" not in link:
        return {}
    proto, rest = link.split("://", 1)
    out = {"protocol": proto}

    if proto == "vless":
        m = re.match(r"([^@]+)@([^:]+):(\d+)(\?.*)?(#.*)?$", rest)
        if m:
            out["uuid"] = m.group(1)
            out["address"] = m.group(2)
            out["port"] = m.group(3)
            qs = (m.group(4) or "").lstrip("?")
            params = parse_qs(qs)
            out["network"] = params.get("type", [None])[0]
            out["security"] = params.get("security", [None])[0]
            out["path"] = params.get("path", [None])[0]
            out["host"] = params.get("host", [None])[0]
            frag = (m.group(5) or "").lstrip("#")
            out["remarks"] = unquote(frag) if frag else ""
        return out

    if proto == "vmess":
        try:
            padded = rest + "=" * (len(rest) % 4)
            j = json.loads(base64.b64decode(padded))
            out["uuid"] = j.get("id")
            out["address"] = j.get("add")
            out["port"] = str(j.get("port")) if j.get("port") is not None else None
            out["network"] = j.get("net")
            out["path"] = j.get("path")
            out["host"] = j.get("host")
            out["security"] = j.get("tls")
            out["remarks"] = j.get("ps", "")
        except Exception:
            pass
        return out

    if proto == "trojan":
        m = re.match(r"([^@]+)@([^:]+):(\d+)(\?.*)?(#.*)?$", rest)
        if m:
            out["password"] = m.group(1)
            out["address"] = m.group(2)
            out["port"] = m.group(3)
            qs = (m.group(4) or "").lstrip("?")
            params = parse_qs(qs)
            out["network"] = params.get("type", [None])[0]
            out["security"] = params.get("security", [None])[0]
            out["path"] = params.get("path", [None])[0]
            out["host"] = params.get("host", [None])[0]
            frag = (m.group(5) or "").lstrip("#")
            out["remarks"] = unquote(frag) if frag else ""
        return out

    if proto == "ss":
        m = re.match(r"([^@]+)@([^:]+):(\d+)(#.*)?$", rest)
        if m:
            out["address"] = m.group(2)
            out["port"] = m.group(3)
            frag = (m.group(4) or "").lstrip("#")
            out["remarks"] = unquote(frag) if frag else ""
        return out

    return out

# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------
def matches_criteria(parsed, criteria):
    for key, want in criteria.items():
        if not want:          # skip if not set
            continue
        if parsed.get(key) != want:
            return False
    return True

def main():
    criteria = {
        "protocol": os.environ.get("MATCH_PROTOCOL", "").strip(),
        "address": os.environ.get("MATCH_ADDRESS", "").strip(),
        "port": os.environ.get("MATCH_PORT", "").strip(),
        "uuid": os.environ.get("MATCH_UUID", "").strip(),
        "network": os.environ.get("MATCH_NETWORK", "").strip(),
        "path": os.environ.get("MATCH_PATH", "").strip(),
        "host": os.environ.get("MATCH_HOST", "").strip(),
        "security": os.environ.get("MATCH_SECURITY", "").strip(),
    }

    seen = set()
    matches = []

    for url in DATABASE_URLS:
        lines = fetch_and_decode(url)
        for line in lines:
            parsed = parse_share_link(line)
            if not parsed:
                continue
            if matches_criteria(parsed, criteria):
                if line not in seen:
                    seen.add(line)
                    matches.append(line)

    print(f"Found {len(matches)} matching configs:")
    for m in matches:
        print(m)
    print(f"\nTotal: {len(matches)}")

if __name__ == "__main__":
    main()
