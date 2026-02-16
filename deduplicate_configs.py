import requests
import re
import os
import base64
import json
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, unquote, quote, parse_qs

# Updated source files - now using unified latest_configs.txt
SOURCES = [
    'https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/latest_configs.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/latest_configs.txt'
]

OUTPUT_DIR = 'Hugs'
OUTPUT_FILES = ['Pre-Hugs-1.txt', 'Pre-Hugs-2.txt', 'Pre-Hugs-3.txt', 'Pre-Hugs-4.txt']
CF_OUTPUT_FILE = 'CF-Configs.txt'
CF_MAX_CONFIGS = 2222
COUNTER_FILE = '.rotation_counter'

# Blacklisted patterns (will be excluded)
BLACKLIST_PATTERNS = ['.navy', 'indevs.in']

# Cloudflare IP ranges
CLOUDFLARE_IP_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]

CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IP_RANGES]

CLOUDFLARE_DOMAINS = [
    'workers.dev', 'pages.dev', 'cloudflare.com', 'cloudflare-dns.com',
    'cfargotunnel.com', 'trycloudflare.com',
]


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
            print(f"    ℹ️  Decoded base64 subscription")
            return decoded
        except:
            pass
    
    return content


def is_cloudflare_ip(ip_str):
    """Check if an IP address belongs to Cloudflare."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in CF_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_cloudflare_domain(domain):
    """Check if domain is a known Cloudflare domain."""
    if not domain:
        return False
    domain = domain.lower()
    for cf_domain in CLOUDFLARE_DOMAINS:
        if domain.endswith(cf_domain):
            return True
    return False


def parse_vmess_config(config_str):
    """Parse VMess config."""
    try:
        b64_part = config_str.replace('vmess://', '').split('#')[0]
        missing_padding = len(b64_part) % 4
        if missing_padding:
            b64_part += '=' * (4 - missing_padding)
        decoded = base64.b64decode(b64_part).decode('utf-8')
        return json.loads(decoded)
    except:
        return None


def extract_config_details(config_line):
    """Extract server, SNI, and host from config."""
    config_line = config_line.strip()
    server = ""
    sni = ""
    host = ""
    
    if config_line.startswith(('vless://', 'trojan://', 'hysteria://', 'hy2://')):
        try:
            match = re.search(r'@([^:?#]+):(\d+)', config_line)
            if match:
                server = match.group(1)
            
            if '?' in config_line:
                query_part = config_line.split('?')[1].split('#')[0]
                params = parse_qs(query_part)
                sni = params.get('sni', [''])[0]
                host = params.get('host', [''])[0]
        except:
            pass
    
    elif config_line.startswith('vmess://'):
        vmess_data = parse_vmess_config(config_line)
        if vmess_data:
            server = vmess_data.get('add', '')
            sni = vmess_data.get('sni', '')
            host = vmess_data.get('host', '')
    
    return server, sni, host


def extract_server_port(config_line):
    """Extract server:port from config for deduplication."""
    config_line = config_line.strip()
    
    if config_line.startswith(('vless://', 'trojan://', 'hysteria://', 'hy2://')):
        try:
            match = re.search(r'@([^:?#]+):(\d+)', config_line)
            if match:
                return f"{match.group(1)}:{match.group(2)}"
        except:
            pass
    
    elif config_line.startswith('vmess://'):
        vmess_data = parse_vmess_config(config_line)
        if vmess_data:
            return f"{vmess_data.get('add', '')}:{vmess_data.get('port', '')}"
    
    return config_line


def is_blacklisted(config_line):
    """Check if config contains blacklisted patterns."""
    server, sni, host = extract_config_details(config_line)
    
    for pattern in BLACKLIST_PATTERNS:
        pattern_lower = pattern.lower()
        if server and pattern_lower in server.lower():
            return True
        if sni and pattern_lower in sni.lower():
            return True
        if host and pattern_lower in host.lower():
            return True
    
    return False


def is_cloudflare_config(config_line):
    """Check if config uses Cloudflare server."""
    server, sni, host = extract_config_details(config_line)
    
    if not server:
        return False
    
    if is_cloudflare_ip(server):
        return True
    
    if is_cloudflare_domain(server):
        return True
    
    if host and is_cloudflare_domain(host):
        return True
    
    return False


def rename_config(config_line):
    """Rename config according to pattern."""
    if '#' not in config_line:
        return config_line
    
    protocol_part, name_part = config_line.rsplit('#', 1)
    name_part = unquote(name_part)
    
    # Pattern: Flag + @MoboNetPC + Flag → Flag + Support 👉 @MoboNetPC + Flag
    pattern1_flag = re.match(r'^([\U0001F1E6-\U0001F1FF]{2})\s*@MoboNetPC\s*([\U0001F1E6-\U0001F1FF]{2})$', name_part)
    if pattern1_flag:
        flag = pattern1_flag.group(1)
        new_name = f"{flag} Support 👉 @MoboNetPC {flag}"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern: 🔓 @MoboNetPC 🔓
    pattern1_lock = re.match(r'^🔓\s*@MoboNetPC\s*🔓$', name_part)
    if pattern1_lock:
        new_name = "🔓 Support 👉 @MoboNetPC 🔓"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern: Flag + @VPNProxyTest + Flag
    pattern2_flag = re.match(r'^([\U0001F1E6-\U0001F1FF]{2})\s*@VPNProxyTest\s*([\U0001F1E6-\U0001F1FF]{2})$', name_part)
    if pattern2_flag:
        flag = pattern2_flag.group(1)
        new_name = f"{flag} پشتیبانی 👉 @VPNProxyTest {flag}"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern: 🔓 @VPNProxyTest 🔓
    pattern2_lock = re.match(r'^🔓\s*@VPNProxyTest\s*🔓$', name_part)
    if pattern2_lock:
        new_name = "🔓 پشتیبانی 👉 @VPNProxyTest 🔓"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    return config_line


def get_next_output_file():
    """Get the next output file using rotation counter."""
    counter_path = os.path.join(OUTPUT_DIR, COUNTER_FILE)
    
    if os.path.exists(counter_path):
        try:
            with open(counter_path, 'r') as f:
                counter = int(f.read().strip())
        except:
            counter = 0
    else:
        counter = 0
    
    current_file = OUTPUT_FILES[counter]
    next_counter = (counter + 1) % 4
    
    with open(counter_path, 'w') as f:
        f.write(str(next_counter))
    
    print(f"🔄 Using rotation slot {counter + 1}/4: '{current_file}'")
    
    return current_file


def load_existing_cf_configs():
    """Load existing Cloudflare configs from file."""
    cf_file_path = os.path.join(OUTPUT_DIR, CF_OUTPUT_FILE)
    
    if os.path.exists(cf_file_path):
        try:
            with open(cf_file_path, 'r', encoding='utf-8') as f:
                configs = [line.strip() for line in f.readlines() if line.strip()]
                print(f"📂 Loaded {len(configs)} existing Cloudflare configs")
                return configs
        except Exception as e:
            print(f"⚠️  Error loading existing CF configs: {e}")
    
    return []


def save_cf_configs(new_configs, existing_configs):
    """Save Cloudflare configs with accumulation logic."""
    cf_file_path = os.path.join(OUTPUT_DIR, CF_OUTPUT_FILE)
    
    existing_servers = set()
    for config in existing_configs:
        server_port = extract_server_port(config)
        existing_servers.add(server_port)
    
    unique_new = []
    for config in new_configs:
        server_port = extract_server_port(config)
        if server_port not in existing_servers:
            unique_new.append(config)
            existing_servers.add(server_port)
    
    print(f"📊 New unique Cloudflare configs: {len(unique_new)}")
    
    combined = existing_configs + unique_new
    
    if len(combined) > CF_MAX_CONFIGS:
        combined = combined[-CF_MAX_CONFIGS:]
        print(f"📊 Trimmed to {CF_MAX_CONFIGS} configs")
    
    with open(cf_file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(combined))
    
    print(f"✅ Saved {len(combined)} Cloudflare configs to '{CF_OUTPUT_FILE}'")
    
    return len(combined)


def ensure_output_dir():
    """Ensure output directory exists."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"📁 Created output directory: '{OUTPUT_DIR}'")


def main():
    print("="*60)
    print("🔄 V2RAY CONFIG DEDUPLICATOR & RENAMER")
    print("="*60)
    
    ensure_output_dir()
    
    # Download source files
    print("\n📥 Downloading source files...")
    all_configs = []
    
    for url in SOURCES:
        print(f"  • {url.split('/')[-1]}...", end=" ")
        content = download_file(url)
        
        if content:
            decoded_content = decode_subscription(content)
            lines = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            
            # Exclude shadowsocks (ss://)
            valid_configs = [
                line for line in lines
                if line.startswith(('vless://', 'vmess://', 'trojan://', 'hysteria://', 'hy2://'))
            ]
            
            all_configs.extend(valid_configs)
            print(f"✅ {len(valid_configs)} configs")
        else:
            print("❌ Failed")
    
    print(f"\n📊 Total configs downloaded: {len(all_configs)}")
    
    if len(all_configs) == 0:
        print("❌ No configs found! Exiting.")
        return
    
    # Filter blacklisted
    print("\n🚫 Filtering blacklisted patterns...")
    filtered_configs = []
    blacklisted_count = 0
    
    for config in all_configs:
        if is_blacklisted(config):
            blacklisted_count += 1
        else:
            filtered_configs.append(config)
    
    print(f"✅ Configs after filter: {len(filtered_configs)}")
    print(f"🗑️  Blacklisted removed: {blacklisted_count}")
    
    # Deduplicate
    print("\n🔍 Deduplicating...")
    seen_servers = {}
    unique_configs = []
    
    for config in filtered_configs:
        server_port = extract_server_port(config)
        if server_port not in seen_servers:
            seen_servers[server_port] = config
            unique_configs.append(config)
    
    print(f"✅ Unique configs: {len(unique_configs)}")
    print(f"🗑️  Duplicates removed: {len(filtered_configs) - len(unique_configs)}")
    
    # Rename
    print("\n✏️  Renaming configs...")
    renamed_configs = []
    renamed_count = 0
    
    for config in unique_configs:
        renamed = rename_config(config)
        if renamed != config:
            renamed_count += 1
        renamed_configs.append(renamed)
    
    print(f"✅ Configs renamed: {renamed_count}")
    
    # Separate CF and non-CF
    print("\n☁️  Separating Cloudflare configs...")
    cf_configs = []
    non_cf_configs = []
    
    for config in renamed_configs:
        if is_cloudflare_config(config):
            cf_configs.append(config)
        else:
            non_cf_configs.append(config)
    
    print(f"☁️  Cloudflare: {len(cf_configs)}")
    print(f"🖥️  Non-Cloudflare: {len(non_cf_configs)}")
    
    # Save non-CF to rotating file
    print("\n📁 Saving non-Cloudflare configs...")
    output_file = get_next_output_file()
    output_path = os.path.join(OUTPUT_DIR, output_file)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(non_cf_configs))
    
    print(f"✅ Saved {len(non_cf_configs)} to '{output_path}'")
    
    # Save CF configs
    print(f"\n☁️  Processing Cloudflare configs...")
    existing_cf = load_existing_cf_configs()
    cf_total = save_cf_configs(cf_configs, existing_cf)
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    print(f"Total Downloaded:       {len(all_configs)}")
    print(f"Blacklisted Removed:    {blacklisted_count}")
    print(f"After Deduplication:    {len(unique_configs)}")
    print(f"Configs Renamed:        {renamed_count}")
    print(f"Non-CF Configs:         {len(non_cf_configs)} → {output_file}")
    print(f"CF Configs (new):       {len(cf_configs)}")
    print(f"CF Configs (total):     {cf_total} → {CF_OUTPUT_FILE}")
    print(f"Output Directory:       {OUTPUT_DIR}/")
    print("="*60)
    print("✅ Process completed!")


if __name__ == "__main__":
    main()
