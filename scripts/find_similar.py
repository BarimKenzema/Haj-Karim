#!/usr/bin/env python3
"""
Find VLESS/VMess/Trojan/SS configs from Haj‑Karim databases that match
user‑supplied criteria (protocol, address, port, UUID, network, path, host, security).

Usage:
  Set environment variables MATCH_PROTOCOL, MATCH_ADDRESS, MATCH_PORT,
  MATCH_UUID, MATCH_NETWORK, MATCH_PATH, MATCH_HOST, MATCH_SECURITY.
  Any variable left empty/unset will be ignored in the match.
"""

import json
import os
import re
import sys
import base64
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# Database URLs — always the same, but you can edit this list if needed.
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
# Parse a share‑link into a dict of fields
# ---------------------------------------------------------------------------
def parse_share_link(link: str):
    """Return a dict with keys protocol, address, port, uuid, password,
    network, path, host, security, remarks.  Empty dict on failure."""
    if not link or "://" not in link:
        return {}

    proto, rest = link.split("://", 1)
    out = {"protocol": proto}

    # --- VLESS ---
    if proto == "vless":
        # vless://uuid@address:port?params#remark
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

    # --- VMess (base64 JSON) ---
    if proto == "vmess":
        try:
            # Ensure padding
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

    # --- Trojan ---
    if proto == "trojan":
        # trojan://password@address:port?params#remark
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

    # --- Shadowsocks (SIP002) ---
    if proto == "ss":
        # ss://base64(method:password)@address:port#remark
        m = re.match(r"([^@]+)@([^:]+):(\d+)(#.*)?$", rest)
        if m:
            out["address"] = m.group(2)
            out["port"] = m.group(3)
            frag = (m.group(4) or "").lstrip("#")
            out["remarks"] = unquote(frag) if frag else ""
        return out

    return out


def matches_criteria(parsed: dict, criteria: dict):
    """Return True if parsed config matches all non‑empty criteria."""
    for key, want in criteria.items():
        if not want:          # empty string → ignore this criterion
            continue
        if parsed.get(key) != want:
            return False
    return True


def main():
    # Read criteria from environment variables
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
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GitHub-Action/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.URLError as e:
            print(f"[WARN] Failed to fetch {url}: {e}", file=sys.stderr)
            continue

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
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
