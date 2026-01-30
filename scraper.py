#!/usr/bin/env python3
"""
Simple V2Ray Config Scraper
Only searches for configs in 2 specific IP ranges
"""

import requests
import re
import time
import os

# The 2 working IP ranges
TARGET_IPS = [
    '5.199.172.',   # Cherry Servers (your working config)
    '81.12.33.'     # Iranian tunnel (your other working config)
]

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

def search_github(ip_prefix):
    """Search GitHub for configs with specific IP"""
    
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    # Search for the IP prefix
    query = f'"{ip_prefix}" (vless OR vmess OR trojan OR shadowsocks)'
    
    url = 'https://api.github.com/search/code'
    params = {
        'q': query,
        'per_page': 100
    }
    
    try:
        print(f"🔍 Searching for {ip_prefix}*...")
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            items = response.json().get('items', [])
            print(f"   Found {len(items)} files")
            return items
        elif response.status_code == 403:
            print(f"   ⚠️ Rate limited")
            return []
        else:
            print(f"   ✗ Failed: {response.status_code}")
            return []
            
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return []

def get_file_content(url):
    """Download file from GitHub"""
    
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

def extract_configs(text, ip_prefix):
    """Extract configs that contain the IP prefix"""
    
    configs = []
    
    # Only save lines that contain our IP
    for line in text.split('\n'):
        if ip_prefix in line:
            # Clean up the line
            line = line.strip()
            
            # Check if it's a config (starts with protocol or contains JSON)
            if any(line.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://']):
                configs.append(line)
            elif '"address"' in line and ip_prefix in line:
                configs.append(line)
    
    return configs

def main():
    print("="*70)
    print("Simple V2Ray Scraper - 2 IP Ranges Only")
    print("="*70)
    print(f"Target IPs: {TARGET_IPS}\n")
    
    all_configs = []
    
    for ip_prefix in TARGET_IPS:
        # Search GitHub
        files = search_github(ip_prefix)
        
        # Download and extract configs
        for file_item in files:
            file_url = file_item.get('url')
            repo = file_item.get('repository', {}).get('full_name', 'unknown')
            
            print(f"   → {repo}")
            
            content = get_file_content(file_url)
            if content:
                configs = extract_configs(content, ip_prefix)
                all_configs.extend(configs)
                
                if configs:
                    print(f"     ✓ Found {len(configs)} configs")
            
            time.sleep(1)  # Rate limit
        
        time.sleep(5)  # Between searches
    
    # Remove duplicates
    unique_configs = list(set(all_configs))
    
    # Save
    print(f"\n💾 Saving {len(unique_configs)} unique configs...")
    
    with open('found_configs.txt', 'w') as f:
        f.write(f"# V2Ray Configs from Working IP Ranges\n")
        f.write(f"# Total: {len(unique_configs)}\n")
        f.write(f"# IP Ranges: {', '.join(TARGET_IPS)}\n")
        f.write(f"#\n")
        f.write(f"# Copy any line below to V2RayNG\n")
        f.write(f"#\n\n")
        
        for config in unique_configs:
            f.write(f"{config}\n")
    
    print(f"✅ Done! Saved to found_configs.txt")
    print("="*70)

if __name__ == "__main__":
    main()
