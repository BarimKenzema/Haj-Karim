#!/usr/bin/env python3
"""
V2Ray Config Scraper - GitHub Actions Edition
Searches GitHub for V2Ray configs in known-working IP ranges
"""

import requests
import re
import json
import time
from datetime import datetime
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

# GitHub token (automatically provided by Actions)
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

# Known working IP ranges (from your working configs)
WORKING_RANGES = {
    "cherry_servers_lt": {
        "ranges": ["5.199.0.0/16"],
        "provider": "Cherry Servers (Lithuania)",
        "sample_ips": ["5.199.172.73"]  # Your working config
    },
    "ovh_france": {
        "ranges": ["54.36.0.0/16"],
        "provider": "OVH (France)",
        "sample_ips": ["54.36.174.140"]  # Your working config
    }
}

# Search patterns for V2Ray configs
SEARCH_PATTERNS = [
    'vless://',
    'vmess://',
    'trojan://',
    'shadowsocks://',
    '"protocol":"vless"',
    '"protocol":"vmess"',
    '"protocol":"shadowsocks"',
]

OUTPUT_FILE = 'found_configs.txt'

# ============================================================================
# IP RANGE UTILITIES
# ============================================================================

def ip_in_range(ip, cidr_range):
    """Check if IP is in CIDR range"""
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr_range)
    except:
        return False

def extract_ips_from_text(text):
    """Extract all IPs from text"""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(pattern, text)
    
    # Validate IPs
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            # Exclude local/DNS IPs
            if not ip.startswith(('127.', '192.168.', '10.', '172.', '0.', '255.', '1.1.1.', '8.8.8.')):
                valid_ips.append(ip)
    
    return valid_ips

def is_ip_in_working_ranges(ip):
    """Check if IP is in any working range"""
    for range_name, data in WORKING_RANGES.items():
        for cidr in data['ranges']:
            if ip_in_range(ip, cidr):
                return True, range_name, data['provider']
    return False, None, None

# ============================================================================
# GITHUB SEARCH
# ============================================================================

def search_github_code(query, max_results=100):
    """Search GitHub code"""
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {GITHUB_TOKEN}'
    }
    
    url = 'https://api.github.com/search/code'
    params = {
        'q': query,
        'per_page': 100
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('items', [])
        elif response.status_code == 403:
            print(f"⚠️  Rate limited, waiting...")
            time.sleep(60)
            return []
        else:
            print(f"⚠️  Search failed: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

def get_file_content(file_url):
    """Download file content from GitHub"""
    headers = {
        'Accept': 'application/vnd.github.v3.raw',
        'Authorization': f'token {GITHUB_TOKEN}'
    }
    
    try:
        response = requests.get(file_url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.text
    except:
        pass
    
    return None

# ============================================================================
# CONFIG EXTRACTION
# ============================================================================

def extract_v2ray_configs(text):
    """Extract V2Ray configs from text"""
    configs = []
    
    # Pattern 1: URI format (vless://, vmess://, etc.)
    uri_patterns = [
        r'(vless://[^\s\n]+)',
        r'(vmess://[^\s\n]+)',
        r'(trojan://[^\s\n]+)',
        r'(ss://[^\s\n]+)',
    ]
    
    for pattern in uri_patterns:
        matches = re.findall(pattern, text)
        configs.extend(matches)
    
    # Pattern 2: JSON configs (like your configs)
    try:
        # Try to find JSON objects
        json_pattern = r'\{[^}]*"protocol":\s*"(vless|vmess|shadowsocks|trojan)"[^}]*\}'
        json_matches = re.findall(json_pattern, text, re.DOTALL)
        
        for match in json_matches:
            configs.append(match)
    except:
        pass
    
    return configs

# ============================================================================
# MAIN SCRAPER
# ============================================================================

def scrape_configs():
    """Main scraping function"""
    print("="*70)
    print("🔍 V2Ray Config Scraper - GitHub Actions")
    print("="*70)
    print(f"\n⏰ Started: {datetime.now()}\n")
    
    all_found_configs = []
    
    # Search for each pattern
    for pattern in SEARCH_PATTERNS:
        print(f"\n🔎 Searching: '{pattern}'...")
        
        results = search_github_code(pattern, max_results=100)
        print(f"   Found {len(results)} files")
        
        for item in results:
            file_url = item.get('url')
            file_path = item.get('path')
            repo_name = item.get('repository', {}).get('full_name')
            
            print(f"   → Checking: {repo_name}/{file_path}")
            
            # Get file content
            content = get_file_content(file_url)
            if not content:
                continue
            
            # Extract IPs from content
            ips_in_file = extract_ips_from_text(content)
            
            # Check if any IP is in working ranges
            matching_ips = []
            for ip in ips_in_file:
                in_range, range_name, provider = is_ip_in_working_ranges(ip)
                if in_range:
                    matching_ips.append((ip, provider))
            
            if matching_ips:
                print(f"     ✅ MATCH! IPs: {[ip for ip, _ in matching_ips]}")
                
                # Extract configs
                configs = extract_v2ray_configs(content)
                
                for config in configs:
                    all_found_configs.append({
                        'config': config,
                        'ips': matching_ips,
                        'source': f"{repo_name}/{file_path}",
                        'found_at': datetime.now().isoformat()
                    })
            
            time.sleep(1)  # Rate limiting
        
        time.sleep(5)  # Between searches
    
    return all_found_configs

# ============================================================================
# SAVE RESULTS
# ============================================================================

def save_results(configs):
    """Save found configs to file"""
    if not configs:
        print("\n❌ No configs found in working ranges")
        return
    
    print(f"\n✅ Found {len(configs)} configs in working ranges!")
    
    # Save to file
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# V2Ray Configs from Working IP Ranges\n")
        f.write(f"# Auto-generated: {datetime.now()}\n")
        f.write(f"# Total found: {len(configs)}\n\n")
        
        for i, item in enumerate(configs, 1):
            f.write(f"# Config {i}\n")
            f.write(f"# IPs: {item['ips']}\n")
            f.write(f"# Source: {item['source']}\n")
            f.write(f"# Found: {item['found_at']}\n")
            f.write(f"{item['config']}\n\n")
    
    print(f"\n💾 Saved to: {OUTPUT_FILE}")
    
    # Print summary
    print(f"\n📊 Summary by Provider:")
    providers = {}
    for item in configs:
        for ip, provider in item['ips']:
            providers[provider] = providers.get(provider, 0) + 1
    
    for provider, count in providers.items():
        print(f"   {provider}: {count} configs")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    try:
        configs = scrape_configs()
        save_results(configs)
        
        print(f"\n⏰ Finished: {datetime.now()}")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
