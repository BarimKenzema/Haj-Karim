#!/usr/bin/env python3
"""
Config Finder Script - Robust Version
Searches through database files for configs matching specific criteria
Handles malformed configs without crashing
"""

import os
import re
import base64
import json
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional
import requests

# Configuration
BASE_URL = "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main"
IP_DATABASE_PREFIX = "database_ip"
SNI_DATABASE_PREFIX = "database_sni"
MAX_DATABASE_NUM = 99

# Search parameters from environment variables
SEARCH_SNI = os.getenv('SEARCH_SNI', 'www.icloud.com')
SEARCH_SECURITY = os.getenv('SEARCH_SECURITY', '')
SEARCH_FLOW = os.getenv('SEARCH_FLOW', '')
SEARCH_PORT = os.getenv('SEARCH_PORT', '')
SEARCH_PROTOCOL = os.getenv('SEARCH_PROTOCOL', '')
SEARCH_NETWORK = os.getenv('SEARCH_NETWORK', '')
MAX_RESULTS = int(os.getenv('MAX_RESULTS', '100'))

print("=" * 80)
print("CONFIG FINDER - Searching your database (Robust Mode)")
print("=" * 80)
print(f"Search Parameters:")
print(f"  SNI: {SEARCH_SNI if SEARCH_SNI else 'Any'}")
print(f"  Security: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}")
print(f"  Flow: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}")
print(f"  Port: {SEARCH_PORT if SEARCH_PORT else 'Any'}")
print(f"  Protocol: {SEARCH_PROTOCOL if SEARCH_PROTOCOL else 'Any'}")
print(f"  Network: {SEARCH_NETWORK if SEARCH_NETWORK else 'Any'}")
print(f"  Max Results: {MAX_RESULTS if MAX_RESULTS > 0 else 'Unlimited'}")
print("=" * 80)

def safe_lower(value):
    """Safely convert to lower case, returning empty string if None."""
    if value is None:
        return ""
    return str(value).lower().strip()

def clean_port(port_str):
    """Clean port string (handle '443:80' or non-numeric)."""
    if not port_str:
        return ""
    # If port contains ':', take the first part (common scraper artifact)
    if ':' in str(port_str):
        port_str = str(port_str).split(':')[0]
    # Remove non-digits
    return ''.join(filter(str.isdigit, str(port_str)))

def download_and_decode(url: str) -> List[str]:
    """Download and decode a base64 encoded database file."""
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 404:
            return []
        
        response.raise_for_status()
        content = response.text.strip()
        
        if not content:
            return []
        
        # Try to decode as base64
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            return [line.strip() for line in decoded.splitlines() if line.strip()]
        except Exception:
            # If not base64, treat as plain text
            return [line.strip() for line in content.splitlines() if line.strip()]
    
    except Exception as e:
        print(f"  Warning: Could not load {url}: {e}")
        return []

def parse_vmess_config(config_str: str) -> Optional[Dict]:
    """Parse VMess config and return JSON data."""
    try:
        encoded = config_str.replace('vmess://', '').strip()
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded_bytes = base64.b64decode(encoded, validate=True)
        
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1']:
            try:
                decoded = decoded_bytes.decode(encoding, errors='ignore')
                parsed = json.loads(decoded)
                if 'add' in parsed: # Relaxed check
                    return parsed
            except Exception:
                continue
        return None
    except Exception:
        return None

def extract_config_details(config_str: str) -> Dict:
    """Extract all relevant details from a config string."""
    # Initialize with safe empty strings
    details = {
        'protocol': '',
        'host': '',
        'port': '',
        'sni': '',
        'security': '',
        'flow': '',
        'network': '',
        'config': config_str
    }
    
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return details
            
            details['protocol'] = 'vmess'
            details['host'] = str(vmess_data.get('add', ''))
            details['port'] = clean_port(vmess_data.get('port', ''))
            details['sni'] = str(vmess_data.get('sni', ''))
            details['security'] = str(vmess_data.get('tls', 'none'))
            details['network'] = str(vmess_data.get('net', 'tcp'))
        
        elif config_str.startswith(('vless://', 'trojan://')):
            # Handle invalid URLs nicely
            try:
                parsed = urlparse(config_str)
            except ValueError:
                return details # Skip malformed URLs

            params = parse_qs(parsed.query)
            
            details['protocol'] = parsed.scheme
            details['host'] = parsed.hostname or ''
            details['port'] = clean_port(parsed.port)
            
            # Safe extraction from lists
            sni_list = params.get('sni') or params.get('serverName') or ['']
            details['sni'] = sni_list[0]
            
            security_list = params.get('security') or ['none']
            details['security'] = security_list[0]
            
            flow_list = params.get('flow') or ['']
            details['flow'] = flow_list[0]
            
            type_list = params.get('type') or ['tcp']
            details['network'] = type_list[0]
        
        elif config_str.startswith('ss://'):
            details['protocol'] = 'shadowsocks'
            try:
                parts = config_str.split('@')
                if len(parts) >= 2:
                    server_part = parts[-1].split('#')[0]
                    if ':' in server_part:
                        # Find last colon for port
                        host, port = server_part.rsplit(':', 1)
                        details['host'] = host
                        details['port'] = clean_port(port)
            except:
                pass
    
    except Exception:
        # Silently fail on bad configs to prevent log spam
        pass
    
    return details

def matches_criteria(details: Dict) -> bool:
    """Check if config matches search criteria."""
    
    # SNI check
    if SEARCH_SNI:
        search_term = safe_lower(SEARCH_SNI)
        config_sni = safe_lower(details['sni'])
        config_full = safe_lower(details['config'])
        
        # Check explicit SNI field or full config string
        if search_term not in config_sni and search_term not in config_full:
            return False
    
    # Security check
    if SEARCH_SECURITY:
        if safe_lower(SEARCH_SECURITY) not in safe_lower(details['security']):
            return False
    
    # Flow check
    if SEARCH_FLOW:
        if safe_lower(SEARCH_FLOW) not in safe_lower(details['flow']):
            return False
    
    # Port check
    if SEARCH_PORT:
        if str(SEARCH_PORT) != str(details['port']):
            return False
    
    # Protocol check
    if SEARCH_PROTOCOL:
        if safe_lower(SEARCH_PROTOCOL) != safe_lower(details['protocol']):
            return False
    
    # Network check
    if SEARCH_NETWORK:
        if safe_lower(SEARCH_NETWORK) != safe_lower(details['network']):
            return False
    
    return True

def search_databases() -> List[Dict]:
    """Search through all database files."""
    found_configs = []
    total_scanned = 0
    
    print("\n" + "=" * 80)
    print("SEARCHING DATABASES")
    print("=" * 80)
    
    # Combined search for cleaner code
    db_types = [(IP_DATABASE_PREFIX, "IP"), (SNI_DATABASE_PREFIX, "SNI")]
    
    for prefix, label in db_types:
        print(f"\n📁 Searching {label} databases...")
        
        for i in range(1, MAX_DATABASE_NUM + 1):
            if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
                break
            
            filename = f"{prefix}.txt" if i == 1 else f"{prefix}_{i}.txt"
            url = f"{BASE_URL}/{filename}"
            
            print(f"  Checking: {filename}", end=" ")
            
            configs = download_and_decode(url)
            
            if not configs:
                print("(not found or empty)")
                if i > 5: # Stop if we hit 5 consecutive empty files
                    break
                continue
            
            print(f"({len(configs)} configs)")
            
            for config in configs:
                total_scanned += 1
                details = extract_config_details(config)
                
                # Only check valid configs
                if not details['protocol']:
                    continue

                if matches_criteria(details):
                    # Check for duplicates
                    if not any(d['config'] == details['config'] for d in found_configs):
                        found_configs.append(details)
                        if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
                            break
    
    print("\n" + "=" * 80)
    print(f"Total configs scanned: {total_scanned}")
    print(f"Matching configs found: {len(found_configs)}")
    print("=" * 80)
    
    return found_configs

def save_results(found_configs: List[Dict]):
    """Save results to files."""
    
    # Create files even if empty
    with open('search_summary.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("SEARCH SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Results: {len(found_configs)} configs found\n")
    
    with open('found_configs.txt', 'w', encoding='utf-8') as f:
        f.write("Configs found:\n")

    with open('found_configs_plain.txt', 'w', encoding='utf-8') as f:
        f.write("")

    if not found_configs:
        print("\n⚠️  No matching configs found!")
        return
    
    # Save detailed results
    with open('found_configs.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("FOUND CONFIGS - DETAILED\n")
        f.write("=" * 80 + "\n\n")
        
        for i, details in enumerate(found_configs, 1):
            f.write(f"Config #{i}\n")
            f.write(f"  Protocol: {details['protocol']}\n")
            f.write(f"  Host: {details['host']}\n")
            f.write(f"  Port: {details['port']}\n")
            f.write(f"  SNI: {details['sni']}\n")
            f.write(f"  Full Config:\n")
            f.write(f"  {details['config']}\n")
            f.write("-" * 80 + "\n\n")
    
    # Save plain configs only
    with open('found_configs_plain.txt', 'w', encoding='utf-8') as f:
        for details in found_configs:
            f.write(details['config'] + '\n')
    
    # Save detailed summary
    with open('search_summary.txt', 'a', encoding='utf-8') as f:
        # Statistics
        protocols = {}
        securities = {}
        ports = {}
        
        for details in found_configs:
            p = details['protocol'] or "unknown"
            protocols[p] = protocols.get(p, 0) + 1
            
            s = details['security'] or "none"
            securities[s] = securities.get(s, 0) + 1
            
            pt = details['port'] or "unknown"
            ports[pt] = ports.get(pt, 0) + 1
        
        f.write("\nStatistics:\n")
        f.write(f"  Protocols: {protocols}\n")
        f.write(f"  Security: {securities}\n")
        f.write(f"  Ports: {ports}\n")
    
    print(f"\n✅ Results saved to artifacts.")

def main():
    """Main execution."""
    try:
        found_configs = search_databases()
        save_results(found_configs)
        
        print("\n" + "=" * 80)
        print("SEARCH COMPLETE!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()
