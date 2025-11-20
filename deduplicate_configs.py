import requests
import re
import os
import base64
import json
from datetime import datetime
from urllib.parse import urlparse, unquote, quote

# Source files
SOURCES = [
    'https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/latest_ip_configs.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/filtered-for-refiner.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/active_ip_configs.txt',
    'https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/active_sni_configs.txt'
]

OUTPUT_FILES = ['Pre-Hugs-1.txt', 'Pre-Hugs-2.txt', 'Pre-Hugs-3.txt', 'Pre-Hugs-4.txt']

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
    
    # Check if content is base64 encoded (doesn't start with protocol://)
    if not content.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria://', 'hy2://')):
        try:
            # Try to decode as base64
            # Add padding if needed
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(content).decode('utf-8')
            print(f"    ℹ️  Decoded base64 subscription")
            return decoded
        except:
            # If decode fails, return as-is
            pass
    
    return content

def extract_server_port(config_line):
    """Extract server:port from v2ray config for deduplication."""
    config_line = config_line.strip()
    
    # vless:// or trojan://
    if config_line.startswith(('vless://', 'trojan://', 'hysteria://', 'hy2://')):
        try:
            # Format: protocol://uuid@server:port?params#name
            match = re.search(r'@([^:?#]+):(\d+)', config_line)
            if match:
                return f"{match.group(1)}:{match.group(2)}"
        except:
            pass
    
    # vmess://
    elif config_line.startswith('vmess://'):
        try:
            # Decode base64
            b64_part = config_line.replace('vmess://', '').split('#')[0]
            # Add padding if needed
            missing_padding = len(b64_part) % 4
            if missing_padding:
                b64_part += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(b64_part).decode('utf-8')
            vmess_data = json.loads(decoded)
            return f"{vmess_data.get('add', '')}:{vmess_data.get('port', '')}"
        except:
            pass
    
    # ss:// (shadowsocks)
    elif config_line.startswith('ss://'):
        try:
            # Format: ss://base64@server:port#name or ss://method:password@server:port#name
            match = re.search(r'@([^:?#]+):(\d+)', config_line)
            if match:
                return f"{match.group(1)}:{match.group(2)}"
        except:
            pass
    
    # If can't parse, use entire line as unique identifier
    return config_line

def rename_config(config_line):
    """Rename config according to new pattern."""
    # Extract the remark/name part (after #)
    if '#' not in config_line:
        return config_line
    
    protocol_part, name_part = config_line.rsplit('#', 1)
    name_part = unquote(name_part)  # Decode URL encoding
    
    # Pattern 1: Flag emoji + @MoboNetPC + Flag emoji → Flag + Support 👉 @MoboNetPC + Flag
    # Example: 🇹🇷 @MoboNetPC 🇹🇷 → 🇹🇷 Support 👉 @MoboNetPC 🇹🇷
    pattern1_flag = re.match(r'^([\U0001F1E6-\U0001F1FF]{2})\s*@MoboNetPC\s*([\U0001F1E6-\U0001F1FF]{2})$', name_part)
    if pattern1_flag:
        flag = pattern1_flag.group(1)
        new_name = f"{flag} Support 👉 @MoboNetPC {flag}"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern 2: 🔓 @MoboNetPC 🔓 → 🔓 Support 👉 @MoboNetPC 🔓
    pattern1_lock = re.match(r'^🔓\s*@MoboNetPC\s*🔓$', name_part)
    if pattern1_lock:
        new_name = "🔓 Support 👉 @MoboNetPC 🔓"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern 3: Flag emoji + @VPNProxyTest + Flag emoji → Flag + پشتیبانی 👉 @VPNProxyTestSupport + Flag
    # Example: 🇹🇷 @VPNProxyTest 🇹🇷 → 🇹🇷 پشتیبانی 👉 @VPNProxyTestSupport 🇹🇷
    pattern2_flag = re.match(r'^([\U0001F1E6-\U0001F1FF]{2})\s*@VPNProxyTest\s*([\U0001F1E6-\U0001F1FF]{2})$', name_part)
    if pattern2_flag:
        flag = pattern2_flag.group(1)
        new_name = f"{flag} پشتیبانی 👉 @VPNProxyTestSupport {flag}"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # Pattern 4: 🔓 @VPNProxyTest 🔓 → 🔓 پشتیبانی 👉 @VPNProxyTestSupport 🔓
    pattern2_lock = re.match(r'^🔓\s*@VPNProxyTest\s*🔓$', name_part)
    if pattern2_lock:
        new_name = "🔓 پشتیبانی 👉 @VPNProxyTestSupport 🔓"
        return f"{protocol_part}#{quote(new_name, safe='')}"
    
    # If no pattern matches, return original
    return config_line

def get_oldest_output_file():
    """Find the oldest Pre-Hugs file (or first non-existent one)."""
    oldest_file = None
    oldest_time = None
    
    for filename in OUTPUT_FILES:
        if not os.path.exists(filename):
            # If file doesn't exist, use this one
            print(f"📝 File '{filename}' doesn't exist. Using it.")
            return filename
        
        # Get file modification time
        mtime = os.path.getmtime(filename)
        
        if oldest_time is None or mtime < oldest_time:
            oldest_time = mtime
            oldest_file = filename
    
    print(f"🔄 Oldest file is '{oldest_file}'. Overwriting it.")
    return oldest_file

def main():
    print("="*60)
    print("🔄 V2RAY CONFIG DEDUPLICATOR & RENAMER")
    print("="*60)
    
    # Step 1: Download all source files
    print("\n📥 Downloading source files...")
    all_configs = []
    
    for url in SOURCES:
        print(f"  • {url.split('/')[-1]}...", end=" ")
        content = download_file(url)
        
        if content:
            # Try to decode if base64
            decoded_content = decode_subscription(content)
            
            # Split by newlines and filter empty lines
            lines = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            
            # Filter only valid config lines (starting with known protocols)
            valid_configs = [
                line for line in lines 
                if line.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria://', 'hy2://'))
            ]
            
            all_configs.extend(valid_configs)
            print(f"✅ {len(valid_configs)} configs")
        else:
            print("❌ Failed")
    
    print(f"\n📊 Total configs downloaded: {len(all_configs)}")
    
    if len(all_configs) == 0:
        print("❌ No configs found! Exiting.")
        return
    
    # Step 2: Deduplicate based on server:port
    print("\n🔍 Deduplicating...")
    seen_servers = {}
    unique_configs = []
    
    for config in all_configs:
        server_port = extract_server_port(config)
        if server_port not in seen_servers:
            seen_servers[server_port] = config
            unique_configs.append(config)
    
    print(f"✅ Unique configs after deduplication: {len(unique_configs)}")
    print(f"🗑️  Duplicates removed: {len(all_configs) - len(unique_configs)}")
    
    # Step 3: Rename configs
    print("\n✏️  Renaming configs...")
    renamed_configs = []
    renamed_count = 0
    
    for config in unique_configs:
        renamed = rename_config(config)
        if renamed != config:
            renamed_count += 1
        renamed_configs.append(renamed)
    
    print(f"✅ Configs renamed: {renamed_count}")
    
    # Step 4: Find oldest output file
    print("\n📁 Determining output file...")
    output_file = get_oldest_output_file()
    
    # Step 5: Write to file
    print(f"\n💾 Writing {len(renamed_configs)} configs to '{output_file}'...")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(renamed_configs))
    
    print(f"✅ Successfully written to '{output_file}'")
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    print(f"Total Downloaded:     {len(all_configs)}")
    print(f"After Deduplication:  {len(unique_configs)}")
    print(f"Configs Renamed:      {renamed_count}")
    print(f"Output File:          {output_file}")
    print(f"Final Count:          {len(renamed_configs)}")
    print("="*60)
    print("✅ Process completed successfully!")

if __name__ == "__main__":
    main()
