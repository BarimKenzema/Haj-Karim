#!/usr/bin/env python3
"""
Automatic Config Deduplication Script
Removes duplicate VPN configs based on server address + port + UUID
"""

import os
import json
import base64
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Configuration
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'hugs.txt')

# --- Helper Functions ---

def parse_vmess_config(config_str):
    """Parse VMess config silently."""
    try:
        encoded = config_str.replace('vmess://', '').strip().rstrip('.,;!?')
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        decoded_bytes = base64.b64decode(encoded, validate=True)
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']:
            try:
                decoded = decoded_bytes.decode(encoding, errors='ignore')
                parsed = json.loads(decoded)
                if 'add' in parsed and 'port' in parsed and 'id' in parsed:
                    return parsed
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        return None
    except Exception:
        return None


def get_config_fingerprint(config_str):
    """
    Create unique fingerprint based on:
    - Protocol (vmess/vless/trojan/ss)
    - Server address
    - Port
    - UUID/Password
    """
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return None
            addr = vmess_data.get('add', '')
            port = vmess_data.get('port', '')
            uuid = vmess_data.get('id', '')
            return f"vmess|{addr}|{port}|{uuid}"
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            protocol = parsed.scheme
            uuid = parsed.username or ''
            host = parsed.hostname or ''
            port = parsed.port or ''
            return f"{protocol}|{host}|{port}|{uuid}"
        
        elif config_str.startswith('ss://'):
            parts = config_str.split('@')
            if len(parts) == 2:
                server_part = parts[1].split('#')[0]
                method_pass = parts[0].replace('ss://', '')
                return f"ss|{server_part}|{method_pass}"
        
        return None
    except Exception:
        return None


def deduplicate_configs(configs):
    """
    Remove duplicate configs while preserving order.
    Keeps the FIRST occurrence of each unique config.
    """
    unique_configs = []
    seen_fingerprints = set()
    duplicate_count = 0
    
    for config in configs:
        config = config.strip()
        
        # Skip empty lines
        if not config:
            continue
        
        fingerprint = get_config_fingerprint(config)
        
        if fingerprint:
            if fingerprint not in seen_fingerprints:
                unique_configs.append(config)
                seen_fingerprints.add(fingerprint)
            else:
                duplicate_count += 1
        else:
            # Keep configs that couldn't be parsed (preserve unknown formats)
            unique_configs.append(config)
    
    return unique_configs, duplicate_count


def main():
    """Main cleanup function."""
    print(f"\n{'='*70}")
    print(f"  🧹 CONFIG CLEANUP - {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*70}\n")
    
    # Check if file exists
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Error: {CONFIG_FILE} not found!")
        return 1
    
    # Read configs
    print(f"📥 Reading configs from: {CONFIG_FILE}")
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        configs = f.read().splitlines()
    
    original_count = len([c for c in configs if c.strip()])
    print(f"📊 Original config count: {original_count}")
    
    # Deduplicate
    print(f"🔍 Analyzing for duplicates...")
    unique_configs, duplicates_removed = deduplicate_configs(configs)
    unique_count = len(unique_configs)
    
    print(f"\n{'─'*70}")
    print(f"  ✨ Unique configs      : {unique_count}")
    print(f"  🗑️  Duplicates removed  : {duplicates_removed}")
    print(f"  📈 Deduplication rate : {(duplicates_removed/original_count*100) if original_count > 0 else 0:.1f}%")
    print(f"{'─'*70}\n")
    
    # Write back to file
    print(f"💾 Writing cleaned configs back to: {CONFIG_FILE}")
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_configs))
        if unique_configs:  # Add trailing newline
            f.write('\n')
    
    if duplicates_removed > 0:
        print(f"✅ Successfully removed {duplicates_removed} duplicate(s)!")
    else:
        print(f"✅ No duplicates found. File is already clean!")
    
    print(f"\n{'='*70}\n")
    
    return 0


if __name__ == "__main__":
    exit(main())
