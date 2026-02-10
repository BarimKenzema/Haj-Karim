#!/usr/bin/env python3
"""
Proxy Config Updater
Downloads, deduplicates, tests, and sorts proxy configurations
"""

import requests
import base64
import re
import socket
import time
import concurrent.futures
import json
import os
from urllib.parse import urlparse, unquote

# Configuration
TIMEOUT = 5  # Connection timeout in seconds
MAX_WORKERS = 100  # Concurrent connection tests

# First group URLs (WebSocket configs)
WS_URLS = [
    "https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/networks/ws.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/networks/w"
]

# Second group URLs (Reality/gRPC configs)
REALITY_URLS = [
    "https://raw.githubusercontent.com/BarimKenzema/Final-Boss/refs/heads/main/special/reality_tcp.txt",
    "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main/networks/grpc"
]

# Output files
WS_OUTPUT = "output/ws_tested.txt"
REALITY_OUTPUT = "output/reality_grpc_tested.txt"


def download_content(url):
    """Download content from a URL"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"[ERROR] Failed to download {url}: {e}")
        return ""


def decode_base64(content):
    """Try to decode base64 content"""
    try:
        # Add padding if needed
        padding = 4 - len(content) % 4
        if padding != 4:
            content += '=' * padding
        decoded = base64.b64decode(content).decode('utf-8')
        return decoded
    except:
        return None


def parse_configs(content):
    """Parse configs from content (handles both base64 and plain text)"""
    configs = []
    
    # First try to decode as base64
    decoded = decode_base64(content)
    if decoded and ('vmess://' in decoded or 'vless://' in decoded or 
                    'trojan://' in decoded or 'ss://' in decoded or
                    'hysteria' in decoded):
        content = decoded
    
    # Split by newlines and filter valid configs
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if line and any(line.startswith(proto) for proto in 
                       ['vmess://', 'vless://', 'trojan://', 'ss://', 
                        'ssr://', 'hysteria://', 'hysteria2://', 'hy2://',
                        'tuic://', 'warp://']):
            configs.append(line)
    
    return configs


def extract_server_info(config):
    """Extract server address and port from config"""
    config = config.strip()
    
    try:
        # VMess: vmess://base64encoded
        if config.startswith('vmess://'):
            encoded = config[8:].split('#')[0]
            try:
                # Add padding
                padding = 4 - len(encoded) % 4
                if padding != 4:
                    encoded += '=' * padding
                decoded = base64.b64decode(encoded).decode('utf-8')
                data = json.loads(decoded)
                server = data.get('add', '') or data.get('address', '')
                port = int(data.get('port', 443))
                return server, port
            except:
                return None, None
        
        # VLESS: vless://uuid@server:port?params#name
        elif config.startswith('vless://'):
            match = re.match(r'vless://[^@]+@\[?([^\]:\/?#]+)\]?:(\d+)', config)
            if match:
                return match.group(1), int(match.group(2))
        
        # Trojan: trojan://password@server:port?params#name
        elif config.startswith('trojan://'):
            match = re.match(r'trojan://[^@]+@\[?([^\]:\/?#]+)\]?:(\d+)', config)
            if match:
                return match.group(1), int(match.group(2))
        
        # Shadowsocks: ss://base64@server:port#name or ss://base64#name
        elif config.startswith('ss://'):
            content = config[5:]
            if '@' in content:
                match = re.match(r'[^@]+@\[?([^\]:\/?#]+)\]?:(\d+)', content)
                if match:
                    return match.group(1), int(match.group(2))
            else:
                # Fully encoded format
                encoded = content.split('#')[0]
                try:
                    padding = 4 - len(encoded) % 4
                    if padding != 4:
                        encoded += '=' * padding
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    match = re.match(r'[^@]+@\[?([^\]:\/?#]+)\]?:(\d+)', decoded)
                    if match:
                        return match.group(1), int(match.group(2))
                except:
                    pass
        
        # SSR: ssr://base64encoded
        elif config.startswith('ssr://'):
            encoded = config[6:].split('#')[0]
            try:
                padding = 4 - len(encoded) % 4
                if padding != 4:
                    encoded += '=' * padding
                decoded = base64.b64decode(encoded).decode('utf-8')
                parts = decoded.split(':')
                if len(parts) >= 2:
                    return parts[0], int(parts[1])
            except:
                pass
        
        # Hysteria2: hysteria2://auth@server:port?params#name
        elif config.startswith('hysteria2://') or config.startswith('hy2://'):
            prefix_len = 12 if config.startswith('hysteria2://') else 5
            content = config[prefix_len:]
            match = re.match(r'[^@]*@?\[?([^\]:\/?#]+)\]?:(\d+)', content)
            if match:
                return match.group(1), int(match.group(2))
        
        # Hysteria: hysteria://server:port?params#name
        elif config.startswith('hysteria://'):
            content = config[11:]
            match = re.match(r'\[?([^\]:\/?#]+)\]?:(\d+)', content)
            if match:
                return match.group(1), int(match.group(2))
        
        # TUIC: tuic://uuid:password@server:port?params#name
        elif config.startswith('tuic://'):
            match = re.match(r'tuic://[^@]+@\[?([^\]:\/?#]+)\]?:(\d+)', config)
            if match:
                return match.group(1), int(match.group(2))
    
    except Exception as e:
        pass
    
    return None, None


def test_connection(config, timeout=TIMEOUT):
    """Test TCP connection to server and measure latency"""
    server, port = extract_server_info(config)
    
    if not server or not port:
        return config, float('inf'), False, "Parse error"
    
    try:
        # Resolve hostname
        try:
            ip = socket.gethostbyname(server)
        except socket.gaierror:
            return config, float('inf'), False, "DNS error"
        
        # Test TCP connection
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        end_time = time.time()
        sock.close()
        
        if result == 0:
            latency = round((end_time - start_time) * 1000, 2)  # ms
            return config, latency, True, "OK"
        else:
            return config, float('inf'), False, f"Connection refused"
    
    except socket.timeout:
        return config, float('inf'), False, "Timeout"
    except Exception as e:
        return config, float('inf'), False, str(e)


def remove_duplicates(configs):
    """Remove duplicate configs based on server:port"""
    seen = {}
    unique = []
    
    for config in configs:
        server, port = extract_server_info(config)
        if server and port:
            key = f"{server.lower()}:{port}"
            if key not in seen:
                seen[key] = True
                unique.append(config)
        else:
            # Keep configs we can't parse
            unique.append(config)
    
    return unique


def download_all_configs(urls):
    """Download configs from multiple URLs"""
    all_configs = []
    
    for url in urls:
        print(f"[INFO] Downloading from: {url}")
        content = download_content(url)
        if content:
            configs = parse_configs(content)
            all_configs.extend(configs)
            print(f"[INFO] Found {len(configs)} configs")
        else:
            print(f"[WARN] No content from {url}")
    
    return all_configs


def test_all_configs(configs, max_workers=MAX_WORKERS):
    """Test all configs concurrently"""
    alive_configs = []
    total = len(configs)
    tested = 0
    
    print(f"[INFO] Testing {total} configs with {max_workers} workers...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(test_connection, config): config 
                          for config in configs}
        
        for future in concurrent.futures.as_completed(future_to_config):
            tested += 1
            config, latency, is_alive, status = future.result()
            
            if is_alive:
                alive_configs.append((config, latency))
            
            # Progress update every 50 tests
            if tested % 50 == 0 or tested == total:
                print(f"[INFO] Progress: {tested}/{total} tested, {len(alive_configs)} alive")
    
    return alive_configs


def save_configs(configs, output_file):
    """Save configs to file"""
    # Create output directory if needed
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for config, latency in configs:
            f.write(f"{config}\n")
    
    print(f"[INFO] Saved {len(configs)} configs to {output_file}")


def process_group(urls, output_file, group_name):
    """Process a group of config URLs"""
    print(f"\n{'='*60}")
    print(f"Processing: {group_name}")
    print(f"{'='*60}")
    
    # Download all configs
    configs = download_all_configs(urls)
    print(f"[INFO] Total configs downloaded: {len(configs)}")
    
    if not configs:
        print(f"[WARN] No configs found for {group_name}")
        return
    
    # Remove duplicates
    unique_configs = remove_duplicates(configs)
    print(f"[INFO] After removing duplicates: {len(unique_configs)}")
    
    # Test connections
    alive_configs = test_all_configs(unique_configs)
    print(f"[INFO] Alive configs: {len(alive_configs)}")
    
    if not alive_configs:
        print(f"[WARN] No alive configs found for {group_name}")
        # Create empty file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        open(output_file, 'w').close()
        return
    
    # Sort by latency (lowest first)
    alive_configs.sort(key=lambda x: x[1])
    
    # Save to file
    save_configs(alive_configs, output_file)
    
    # Print top 5 fastest
    print(f"\n[INFO] Top 5 fastest servers:")
    for i, (config, latency) in enumerate(alive_configs[:5], 1):
        server, port = extract_server_info(config)
        print(f"  {i}. {server}:{port} - {latency}ms")


def main():
    """Main function"""
    print("="*60)
    print("Proxy Config Updater")
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # Process WebSocket configs
    process_group(WS_URLS, WS_OUTPUT, "WebSocket Configs")
    
    # Process Reality/gRPC configs
    process_group(REALITY_URLS, REALITY_OUTPUT, "Reality/gRPC Configs")
    
    print(f"\n{'='*60}")
    print(f"Completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)


if __name__ == "__main__":
    main()
