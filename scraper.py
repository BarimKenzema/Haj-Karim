#!/usr/bin/env python3
"""
Simple V2Ray Config Scraper - FIXED
Searches for V2Ray configs, then filters by IP range
"""

import requests
import re
import time
import os

# Target IP ranges
TARGET_IPS = [
    '5.199.172.',   # Cherry Servers
    '81.12.33.'     # Iranian tunnel
]

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

# Search for V2Ray-related keywords instead of IPs
SEARCH_QUERIES = [
    'vless:// extension:txt',
    'vmess:// extension:txt',
    '"protocol":"vless" extension:json',
    '"protocol":"vmess" extension:json',
    'trojan:// extension:txt',
    'shadowsocks:// extension:txt',
]

def search_github(query):
    """Search GitHub code"""
    
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    url = 'https://api.github.com/search/code'
    params = {
        'q': query,
        'per_page': 100
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json().get('items', [])
        elif response.status_code == 403:
            print(f"   ⚠️ Rate limited, waiting...")
            time.sleep(60)
            return []
        else:
            return []
            
    except Exception as e:
        return []

def get_file_content(url):
    """Download file"""
    
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3.raw'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.text
    except:
        pass
    
    return None

def contains_target_ip(text):
    """Check if text contains any target IP"""
    for ip_prefix in TARGET_IPS:
        if ip_prefix in text:
            return True
    return False

def extract_configs_with_target_ip(text):
    """Extract only configs containing target IPs"""
    
    configs = []
    
    # Check if file even contains our IPs
    if not contains_target_ip(text):
        return []
    
    # Extract configs line by line
    for line in text.split('\n'):
        line = line.strip()
        
        # Skip empty or comment lines
        if not line or line.startswith('#'):
            continue
        
        # Check if line contains target IP
        has_target = False
        for ip_prefix in TARGET_IPS:
            if ip_prefix in line:
                has_target = True
                break
        
        if not has_target:
            continue
        
        # Check if it's a config
        if any(line.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://']):
            configs.append(line)
        elif '"address"' in line or '"vnext"' in line or '"servers"' in line:
            # JSON config fragment
            configs.append(line)
    
    return configs

def main():
    print("="*70)
    print("Simple V2Ray Scraper - 2 IP Ranges")
    print("="*70)
    print(f"Target IPs: {TARGET_IPS}\n")
    
    all_configs = []
    files_checked = 0
    
    for query in SEARCH_QUERIES:
        print(f"\n🔍 Searching: {query}")
        
        files = search_github(query)
        print(f"   Found {len(files)} files")
        
        for file_item in files:
            files_checked += 1
            
            file_url = file_item.get('url')
            repo = file_item.get('repository', {}).get('full_name', 'unknown')
            path = file_item.get('path', '')
            
            # Download file
            content = get_file_content(file_url)
            if not content:
                continue
            
            # Check if it has our target IPs
            if not contains_target_ip(content):
                continue
            
            # Extract matching configs
            configs = extract_configs_with_target_ip(content)
            
            if configs:
                print(f"   ✓ {repo}/{path} - {len(configs)} configs")
                all_configs.extend(configs)
            
            time.sleep(1)
        
        time.sleep(3)
    
    print(f"\n📊 Checked {files_checked} files")
    
    # Remove duplicates
    unique_configs = list(set(all_configs))
    
    print(f"💾 Found {len(unique_configs)} unique configs in target IP ranges")
    
    # Save
    with open('found_configs.txt', 'w') as f:
        f.write(f"# V2Ray Configs from Your Working IP Ranges\n")
        f.write(f"# Total: {len(unique_configs)}\n")
        f.write(f"# Ranges: 5.199.172.x (Cherry Servers), 81.12.33.x (Iranian tunnel)\n")
        f.write(f"#\n")
        f.write(f"# HOW TO USE:\n")
        f.write(f"# 1. Copy a line below (starts with vless:// or vmess://)\n")
        f.write(f"# 2. Open V2RayNG\n")
        f.write(f"# 3. Tap + → Import from clipboard\n")
        f.write(f"# 4. Test connection\n")
        f.write(f"#\n\n")
        
        if unique_configs:
            # Separate by IP range
            cherry_configs = [c for c in unique_configs if '5.199.172.' in c]
            iranian_configs = [c for c in unique_configs if '81.12.33.' in c]
            
            if cherry_configs:
                f.write(f"# ========================================\n")
                f.write(f"# Cherry Servers (5.199.172.x) - {len(cherry_configs)} configs\n")
                f.write(f"# ========================================\n\n")
                for config in cherry_configs:
                    f.write(f"{config}\n")
                f.write("\n")
            
            if iranian_configs:
                f.write(f"# ========================================\n")
                f.write(f"# Iranian Tunnel (81.12.33.x) - {len(iranian_configs)} configs\n")
                f.write(f"# ========================================\n\n")
                for config in iranian_configs:
                    f.write(f"{config}\n")
        else:
            f.write("# No configs found this time. Try running again later.\n")
    
    print(f"✅ Saved to found_configs.txt")
    
    if unique_configs:
        print(f"\n🎯 Breakdown:")
        print(f"   Cherry Servers: {len([c for c in unique_configs if '5.199.172.' in c])} configs")
        print(f"   Iranian Tunnel: {len([c for c in unique_configs if '81.12.33.' in c])} configs")
    
    print("="*70)

if __name__ == "__main__":
    main()
