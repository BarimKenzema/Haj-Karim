import requests
import re
import os
import base64
import json
import ipaddress
from urllib.parse import urlparse, unquote, quote, parse_qs

# --- CONFIGURATION ---
OUTPUT_DIR = 'Hugs'
SOURCES = [
    'https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/latest_ip_configs.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/filtered-for-refiner.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/active_ip_configs.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/active_sni_configs.txt'
]

# Output definitions
ROTATING_FILES = ['Pre-Hugs-1.txt', 'Pre-Hugs-2.txt', 'Pre-Hugs-3.txt', 'Pre-Hugs-4.txt']
CLOUDFLARE_FILE = 'CF-Configs.txt'
COUNTER_FILE = '.rotation_counter'
MAX_CF_CONFIGS = 4444

# Blacklist terms (regex safe)
BLACKLIST_DOMAINS = [r'\.navy', r'indevs\.in']

# Cloudflare Definitions
CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
]
CLOUDFLARE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_RANGES]
CLOUDFLARE_DOMAINS = ['cloudflare.com', 'workers.dev', 'pages.dev', 'trycloudflare.com']

def setup_environment():
    """Ensure output directory exists."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def download_file(url):
    """Download content from URL."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"❌ Error downloading {url}: {e}")
        return ""

def decode_subscription(content):
    """Decode base64 subscription if needed."""
    content = content.strip()
    if not content.startswith(('vless://', 'vmess://', 'trojan://', 'hysteria://', 'hy2://')):
        try:
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)
            decoded = base64.b64decode(content).decode('utf-8')
            return decoded
        except:
            pass
    return content

def get_config_details(config):
    """
    Parses a config line and returns a dictionary with:
    { 'address': str, 'port': str, 'sni': str, 'host': str }
    Returns None if parsing fails.
    """
    details = {'address': '', 'port': '', 'sni': '', 'host': ''}
    
    try:
        if config.startswith('vmess://'):
            b64_part = config.replace('vmess://', '').split('#')[0]
            missing_padding = len(b64_part) % 4
            if missing_padding:
                b64_part += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_part).decode('utf-8'))
            
            details['address'] = data.get('add', '')
            details['port'] = str(data.get('port', ''))
            details['sni'] = data.get('sni', '')
            details['host'] = data.get('host', '')
            
        elif config.startswith(('vless://', 'trojan://', 'hysteria://', 'hy2://')):
            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            
            details['address'] = parsed.hostname or ''
            details['port'] = str(parsed.port) if parsed.port else ''
            details['sni'] = params.get('sni', [''])[0]
            details['host'] = params.get('host', [''])[0]
            
        else:
            return None
            
    except:
        return None
        
    return details

def is_blacklisted(details):
    """Check if config contains forbidden domains."""
    if not details: return True
    
    check_string = f"{details['address']} {details['sni']} {details['host']}".lower()
    
    for pattern in BLACKLIST_DOMAINS:
        if re.search(pattern, check_string):
            return True
    return False

def is_cloudflare(details):
    """Check if config is using Cloudflare."""
    if not details: return False
    
    # Check Address (IP or Domain)
    address = details['address']
    
    # Check if address is IP and in CF ranges
    try:
        ip = ipaddress.ip_address(address)
        for network in CLOUDFLARE_NETWORKS:
            if ip in network:
                return True
    except ValueError:
        # Check if address domain is CF
        if any(d in address.lower() for d in CLOUDFLARE_DOMAINS):
            return True

    # Check SNI/Host for CF domains
    check_fields = [details['sni'].lower(), details['host'].lower()]
    for field in check_fields:
        if any(d in field for d in CLOUDFLARE_DOMAINS):
            return True
            
    return False

def rename_config(config_line):
    """Rename config according to pattern."""
    if '#' not in config_line: return config_line
    
    protocol_part, name_part = config_line.rsplit('#', 1)
    name_part = unquote(name_part)
    
    patterns = [
        (r'^([\U0001F1E6-\U0001F1FF]{2})\s*@MoboNetPC\s*([\U0001F1E6-\U0001F1FF]{2})$', r"\1 Support 👉 @MoboNetPC \2"),
        (r'^🔓\s*@MoboNetPC\s*🔓$', "🔓 Support 👉 @MoboNetPC 🔓"),
        (r'^([\U0001F1E6-\U0001F1FF]{2})\s*@VPNProxyTest\s*([\U0001F1E6-\U0001F1FF]{2})$', r"\1 پشتیبانی 👉 @VPNProxyTest \2"),
        (r'^🔓\s*@VPNProxyTest\s*🔓$', "🔓 پشتیبانی 👉 @VPNProxyTest 🔓")
    ]
    
    for pat, repl in patterns:
        if re.match(pat, name_part):
            new_name = re.sub(pat, repl, name_part)
            return f"{protocol_part}#{quote(new_name, safe='')}"
            
    return config_line

def manage_cloudflare_file(new_configs):
    """Accumulate CF configs, deduplicate, and cap at limit."""
    file_path = os.path.join(OUTPUT_DIR, CLOUDFLARE_FILE)
    existing_configs = []
    
    # Load existing
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    # Decode if stored as base64 list (optional safety)
                    if not content.startswith(('vless://', 'vmess://')):
                        try:
                            content = base64.b64decode(content).decode('utf-8')
                        except: pass
                    existing_configs = content.splitlines()
        except Exception as e:
            print(f"⚠️ Error reading existing CF file: {e}")

    # Combine Old + New
    # We want new configs to replace old ones if we hit the limit.
    # Strategy: Append new to old, then keep the *last* MAX_CF_CONFIGS
    # But we must deduplicate first.
    
    combined = existing_configs + new_configs
    
    # Deduplicate (Keep last occurrence to ensure freshness)
    seen = set()
    unique_list = []
    for cfg in reversed(combined): # Process from newest to oldest
        # Use simple string check or server:port logic
        details = get_config_details(cfg)
        key = f"{details['address']}:{details['port']}" if details else cfg
        
        if key not in seen:
            seen.add(key)
            unique_list.append(cfg)
    
    # Revert to chronological order (Oldest -> Newest)
    unique_list.reverse()
    
    # Cap at limit (Keep the tail/newest)
    if len(unique_list) > MAX_CF_CONFIGS:
        final_list = unique_list[-MAX_CF_CONFIGS:]
    else:
        final_list = unique_list
        
    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_list))
    
    return len(final_list)

def get_next_rotation_file():
    """Determine the next file for non-CF configs."""
    counter_path = COUNTER_FILE
    
    counter = 0
    if os.path.exists(counter_path):
        try:
            with open(counter_path, 'r') as f:
                counter = int(f.read().strip())
        except: pass
        
    current_file = ROTATING_FILES[counter]
    next_counter = (counter + 1) % len(ROTATING_FILES)
    
    with open(counter_path, 'w') as f:
        f.write(str(next_counter))
        
    return os.path.join(OUTPUT_DIR, current_file)

def main():
    setup_environment()
    print("="*60)
    print("🔄 ADVANCED V2RAY CONFIG PROCESSOR")
    print("="*60)
    
    # 1. Download & Clean
    raw_configs = []
    for url in SOURCES:
        print(f"📥 Fetching: {url.split('/')[-1]}...", end=" ")
        content = download_file(url)
        decoded = decode_subscription(content)
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        
        # Initial Protocol Filter (Exclude Shadowsocks)
        valid = [l for l in lines if l.startswith(('vless://', 'vmess://', 'trojan://', 'hysteria://', 'hy2://'))]
        raw_configs.extend(valid)
        print(f"Found {len(valid)}")

    if not raw_configs:
        print("❌ No configs found.")
        return

    # 2. Process: Deduplicate, Filter Blacklist, Separate CF/Non-CF
    print("\n🔍 Processing configs...")
    
    seen_keys = set()
    cf_batch = []
    non_cf_batch = []
    
    ignored_ss = 0
    ignored_blacklist = 0
    
    for config in raw_configs:
        # Deduplication Key (Server:Port)
        details = get_config_details(config)
        
        if not details: 
            continue
            
        # Deduplicate
        key = f"{details['address']}:{details['port']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        
        # Blacklist Check (.navy, indevs.in)
        if is_blacklisted(details):
            ignored_blacklist += 1
            continue
            
        # Rename
        renamed_config = rename_config(config)
        
        # Classify
        if is_cloudflare(details):
            cf_batch.append(renamed_config)
        else:
            non_cf_batch.append(renamed_config)

    # 3. Save Cloudflare Configs (Accumulate)
    print(f"\n☁️  Cloudflare Configs found in batch: {len(cf_batch)}")
    total_cf = manage_cloudflare_file(cf_batch)
    print(f"   ↳ Saved to {OUTPUT_DIR}/{CLOUDFLARE_FILE} (Total Accumulated: {total_cf})")

    # 4. Save Non-Cloudflare Configs (Rotate)
    print(f"\n🌍 Non-Cloudflare Configs found: {len(non_cf_batch)}")
    target_file = get_next_rotation_file()
    
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(non_cf_batch))
    print(f"   ↳ Saved to {target_file}")

    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    print(f"Total Unique Processed: {len(seen_keys)}")
    print(f"⛔ Ignored (Blacklist): {ignored_blacklist}")
    print(f"☁️  Cloudflare (New):   {len(cf_batch)}")
    print(f"🌍 Non-CF (Saved):     {len(non_cf_batch)}")
    print("="*60)

if __name__ == "__main__":
    main()
