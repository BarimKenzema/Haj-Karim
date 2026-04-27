#!/usr/bin/env python3
"""
Universal config finder – parses vless, vmess, trojan, ss, hy2, tuic.
Matches user‑supplied criteria from environment variables.
"""

import os, re, sys, json, base64, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, unquote

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

def fetch_and_decode(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GitHub-Action/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except Exception as e:
        print(f"[WARN] Failed to fetch {url}: {e}", file=sys.stderr)
        return []
    # Try base64 decode
    try:
        text = base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        text = raw.decode("utf-8", errors="ignore")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]

def parse_generic(proto, rest):
    """Parse proto://auth@host:port?params#remark (VLESS, Trojan, HY2, TUIC)."""
    out = {"protocol": proto}
    # split at first @ to separate auth from host:port?query#fragment
    if "@" in rest:
        auth, after = rest.split("@", 1)
        # auth may contain user:pass or uuid; store as 'auth'
        out["auth"] = auth
        # now after: host:port?query#fragment
        m = re.match(r"([^:]+):(\d+)(\?.*)?(#.*)?$", after)
        if m:
            out["address"] = m.group(1)
            out["port"] = m.group(2)
            qs = (m.group(3) or "").lstrip("?")
            params = parse_qs(qs)
            out["network"] = params.get("type", [None])[0]
            out["security"] = params.get("security", [None])[0]
            out["path"] = params.get("path", [None])[0]
            out["host"] = params.get("host", [None])[0] or params.get("sni", [None])[0] or params.get("peer", [None])[0]
            frag = (m.group(4) or "").lstrip("#")
            out["remarks"] = unquote(frag) if frag else ""
    else:
        # No auth? Unlikely, but try without
        m = re.match(r"([^:]+):(\d+)(\?.*)?(#.*)?$", rest)
        if m:
            out["address"] = m.group(1)
            out["port"] = m.group(2)
            qs = (m.group(3) or "").lstrip("?")
            params = parse_qs(qs)
            out["network"] = params.get("type", [None])[0]
            out["security"] = params.get("security", [None])[0]
            out["path"] = params.get("path", [None])[0]
            out["host"] = params.get("host", [None])[0] or params.get("sni", [None])[0] or params.get("peer", [None])[0]
    return out

def parse_share_link(link):
    if "://" not in link:
        return {}
    proto, rest = link.split("://", 1)
    proto = proto.strip().lower()

    # VMess special
    if proto == "vmess":
        out = {"protocol": "vmess"}
        try:
            padded = rest + "=" * (len(rest) % 4)
            j = json.loads(base64.b64decode(padded))
            out["address"] = j.get("add")
            out["port"] = str(j.get("port")) if j.get("port") is not None else None
            out["uuid"] = j.get("id")
            out["network"] = j.get("net")
            out["path"] = j.get("path")
            out["host"] = j.get("host")
            out["security"] = j.get("tls")
            out["remarks"] = j.get("ps", "")
        except Exception:
            pass
        return out

    # Shadowsocks (SIP002)
    if proto == "ss":
        out = {"protocol": "ss"}
        # ss://base64(method:password)@address:port#remark
        # First try to decode userinfo
        if "@" in rest:
            userinfo, server = rest.split("@", 1)
            # userinfo may be base64
            try:
                ui = base64.b64decode(userinfo).decode()
                if ":" in ui:
                    out["method"], out["password"] = ui.split(":", 1)
            except:
                pass
            host_port, _, frag = server.partition("#")
            if ":" in host_port:
                out["address"], out["port"] = host_port.rsplit(":", 1)
            out["remarks"] = unquote(frag) if frag else ""
        return out

    # VLESS, Trojan, Hysteria2, TUIC: all auth@host:port?params#remark
    if proto in ("vless", "trojan", "hy2", "tuic"):
        return parse_generic(proto, rest)

    # Fallback for unrecognized protocols: try generic parse
    return parse_generic(proto, rest)

def matches_criteria(parsed, criteria):
    for key, want in criteria.items():
        if not want:
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
    total_parsed = 0
    for url in DATABASE_URLS:
        lines = fetch_and_decode(url)
        for line in lines:
            parsed = parse_share_link(line)
            if not parsed or not parsed.get("address"):
                continue
            total_parsed += 1
            if matches_criteria(parsed, criteria):
                if line not in seen:
                    seen.add(line)
                    matches.append(line)

    print(f"\nTotal configs parsed with address: {total_parsed}")
    print(f"Matched: {len(matches)}")
    for m in matches:
        print(m)

if __name__ == "__main__":
    main()
