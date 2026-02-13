#!/usr/bin/env python3
"""
Config Finder Script
Searches through database files for configs matching specific criteria
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
print("CONFIG FINDER - Searching your database")
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
                if 'add' in parsed and 'port' in parsed:
                    return parsed
            except Exception:
                continue
        return None
    except Exception:
        return None

def extract_config_details(config_str: str) -> Dict:
    """Extract all relevant details from a config string."""
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
            details['host'] = vmess_data.get('add', '')
            details['port'] = str(vmess_data.get('port', ''))
            details['sni'] = vmess_data.get('sni', '')
            details['security'] = vmess_data.get('tls', 'none')
            details['network'] = vmess_data.get('net', 'tcp')
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            
            details['protocol'] = parsed.scheme
            details['host'] = parsed.hostname or ''
            details['port'] = str(parsed.port) if parsed.port else ''
            details['sni'] = params.get('sni', [''])[0] or params.get('serverName', [''])[0]
            details['security'] = params.get('security', ['none'])[0]
            details['flow'] = params.get('flow', [''])[0]
            details['network'] = params.get('type', ['tcp'])[0]
        
        elif config_str.startswith('ss://'):
            details['protocol'] = 'shadowsocks'
            # Basic parsing for ss
            parts = config_str.split('@')
            if len(parts) == 2:
                server_part = parts[1].split('#')[0]
                if ':' in server_part:
                    host, port = server_part.rsplit(':', 1)
                    details['host'] = host
                    details['port'] = port
    
    except Exception as e:
        print(f"  Warning: Could not parse config: {e}")
    
    return details

def matches_criteria(details: Dict) -> bool:
    """Check if config matches search criteria."""
    
    # SNI check
    if SEARCH_SNI:
        sni_match = False
        if SEARCH_SNI.lower() in details['sni'].lower():
            sni_match = True
        # Also check in full config for SNI
        if SEARCH_SNI.lower() in details['config'].lower():
            sni_match = True
        if not sni_match:
            return False
    
    # Security check
    if SEARCH_SECURITY:
        if SEARCH_SECURITY.lower() not in details['security'].lower():
            return False
    
    # Flow check
    if SEARCH_FLOW:
        if SEARCH_FLOW.lower() not in details['flow'].lower():
            return False
    
    # Port check
    if SEARCH_PORT:
        if str(SEARCH_PORT) != details['port']:
            return False
    
    # Protocol check
    if SEARCH_PROTOCOL:
        if SEARCH_PROTOCOL.lower() != details['protocol'].lower():
            return False
    
    # Network check
    if SEARCH_NETWORK:
        if SEARCH_NETWORK.lower() != details['network'].lower():
            return False
    
    return True

def search_databases() -> List[Dict]:
    """Search through all database files."""
    found_configs = []
    total_scanned = 0
    
    print("\n" + "=" * 80)
    print("SEARCHING DATABASES")
    print("=" * 80)
    
    # Search IP databases
    print("\n📁 Searching IP databases...")
    for i in range(1, MAX_DATABASE_NUM + 1):
        if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
            break
        
        if i == 1:
            url = f"{BASE_URL}/{IP_DATABASE_PREFIX}.txt"
        else:
            url = f"{BASE_URL}/{IP_DATABASE_PREFIX}_{i}.txt"
        
        print(f"  Checking: {IP_DATABASE_PREFIX}{'_' + str(i) if i > 1 else ''}.txt", end=" ")
        
        configs = download_and_decode(url)
        
        if not configs:
            print("(not found or empty)")
            if i > 5:  # Stop if we hit 5 consecutive empty files
                break
            continue
        
        print(f"({len(configs)} configs)")
        
        for config in configs:
            total_scanned += 1
            details = extract_config_details(config)
            
            if matches_criteria(details):
                found_configs.append(details)
                if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
                    break
    
    # Search SNI databases
    print("\n📁 Searching SNI databases...")
    for i in range(1, MAX_DATABASE_NUM + 1):
        if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
            break
        
        if i == 1:
            url = f"{BASE_URL}/{SNI_DATABASE_PREFIX}.txt"
        else:
            url = f"{BASE_URL}/{SNI_DATABASE_PREFIX}_{i}.txt"
        
        print(f"  Checking: {SNI_DATABASE_PREFIX}{'_' + str(i) if i > 1 else ''}.txt", end=" ")
        
        configs = download_and_decode(url)
        
        if not configs:
            print("(not found or empty)")
            if i > 5:
                break
            continue
        
        print(f"({len(configs)} configs)")
        
        for config in configs:
            total_scanned += 1
            details = extract_config_details(config)
            
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
    
    if not found_configs:
        print("\n⚠️  No matching configs found!")
        
        # Create empty files with explanation
        with open('search_summary.txt', 'w') as f:
            f.write("NO MATCHING CONFIGS FOUND\n\n")
            f.write("Search Parameters:\n")
            f.write(f"  SNI: {SEARCH_SNI if SEARCH_SNI else 'Any'}\n")
            f.write(f"  Security: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}\n")
            f.write(f"  Flow: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}\n")
            f.write(f"  Port: {SEARCH_PORT if SEARCH_PORT else 'Any'}\n")
            f.write(f"  Protocol: {SEARCH_PROTOCOL if SEARCH_PROTOCOL else 'Any'}\n")
            f.write(f"  Network: {SEARCH_NETWORK if SEARCH_NETWORK else 'Any'}\n")
        
        with open('found_configs.txt', 'w') as f:
            f.write("No configs found matching criteria\n")
        
        with open('found_configs_plain.txt', 'w') as f:
            f.write("No configs found matching criteria\n")
        
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
            f.write(f"  Security: {details['security']}\n")
            f.write(f"  Flow: {details['flow']}\n")
            f.write(f"  Network: {details['network']}\n")
            f.write(f"  Full Config:\n")
            f.write(f"  {details['config']}\n")
            f.write("-" * 80 + "\n\n")
    
    # Save plain configs only
    with open('found_configs_plain.txt', 'w', encoding='utf-8') as f:
        for details in found_configs:
            f.write(details['config'] + '\n')
    
    # Save summary
    with open('search_summary.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("SEARCH SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Search Parameters:\n")
        f.write(f"  SNI: {SEARCH_SNI if SEARCH_SNI else 'Any'}\n")
        f.write(f"  Security: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}\n")
        f.write(f"  Flow: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}\n")
        f.write(f"  Port: {SEARCH_PORT if SEARCH_PORT else 'Any'}\n")
        f.write(f"  Protocol: {SEARCH_PROTOCOL if SEARCH_PROTOCOL else 'Any'}\n")
        f.write(f"  Network: {SEARCH_NETWORK if SEARCH_NETWORK else 'Any'}\n")
        f.write(f"\nResults: {len(found_configs)} configs found\n\n")
        
        # Statistics
        protocols = {}
        securities = {}
        flows = {}
        ports = {}
        
        for details in found_configs:
            protocols[details['protocol']] = protocols.get(details['protocol'], 0) + 1
            securities[details['security']] = securities.get(details['security'], 0) + 1
            if details['flow']:
                flows[details['flow']] = flows.get(details['flow'], 0) + 1
            if details['port']:
                ports[details['port']] = ports.get(details['port'], 0) + 1
        
        f.write("Statistics:\n")
        f.write(f"  Protocols: {protocols}\n")
        f.write(f"  Security: {securities}\n")
        f.write(f"  Flows: {flows}\n")
        f.write(f"  Ports: {ports}\n")
    
    print(f"\n✅ Results saved to:")
    print(f"  - found_configs.txt (detailed)")
    print(f"  - found_configs_plain.txt (configs only)")
    print(f"  - search_summary.txt (summary)")
    
    # Display first few results
    print(f"\n" + "=" * 80)
    print(f"PREVIEW - First 5 Results")
    print("=" * 80)
    
    for i, details in enumerate(found_configs[:5], 1):
        print(f"\nConfig #{i}:")
        print(f"  Protocol: {details['protocol']}")
        print(f"  SNI: {details['sni']}")
        print(f"  Security: {details['security']}")
        print(f"  Flow: {details['flow']}")
        print(f"  Port: {details['port']}")

def main():
    """Main execution."""
    try:
        found_configs = search_databases()
        save_results(found_configs)
        
        print("\n" + "=" * 80)
        print("SEARCH COMPLETE!")
        print("=" * 80)
        print("\nDownload the artifacts from GitHub Actions to get all files.")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    main()
