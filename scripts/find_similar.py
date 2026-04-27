#!/usr/bin/env python3
"""Debug version: shows what's inside the databases and how well parsing works."""

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
        print(f"[WARN] Fetch failed {url}: {e}", file=sys.stderr)
        return []

    # Try base64 decode
    try:
        decoded_bytes = base64.b64decode(raw)
        text = decoded_bytes.decode("utf-8", errors="ignore")
        print(f"[INFO] Base64 decoded OK: {url}")
    except Exception:
        text = raw.decode("utf-8", errors="ignore")
        print(f"[INFO] Not base64, plain text: {url}")

    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    return lines

def parse_share_link(link):
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
            out["address"] = j.get("add")        # <-- note: 'add' not 'address'
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

    total_lines = 0
    parse_ok = 0
    seen = set()
    matches = []
    sample_parsed = []  # store first 5 parsed dicts

    for url in DATABASE_URLS:
        lines = fetch_and_decode(url)
        if not lines:
            continue
        total_lines += len(lines)
        for line in lines:
            parsed = parse_share_link(line)
            if not parsed:
                continue
            parse_ok += 1
            if len(sample_parsed) < 5:
                sample_parsed.append((line[:100] + "...", parsed))

            if matches_criteria(parsed, criteria):
                if line not in seen:
                    seen.add(line)
                    matches.append(line)

    # Debug output
    print("\n============== DEBUG INFO ==============")
    print(f"Total lines (across all databases): {total_lines}")
    print(f"Lines successfully parsed: {parse_ok}")
    print(f"Total matches: {len(matches)}")
    print(f"Search criteria: {criteria}")
    print("\n--- Sample parsed configs (first 5) ---")
    for i, (raw_preview, data) in enumerate(sample_parsed, 1):
        print(f"{i}. Raw: {raw_preview}")
        print(f"   Parsed fields: protocol={data.get('protocol')}, address={data.get('address')}, port={data.get('port')}, network={data.get('network')}, host={data.get('host')}, security={data.get('security')}")
        print()
    print("========================================\n")

    if matches:
        print("Matches found:")
        for m in matches:
            print(m)
    else:
        print("No configs matched the given criteria.")

if __name__ == "__main__":
    main()
