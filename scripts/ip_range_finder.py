#!/usr/bin/env python3
"""
IP Range Config Finder
Searches for configs with IPs in the same range as working configs
"""

import os
import re
import base64
import json
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional, Set
import requests

# Configuration
BASE_URL = "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main"
IP_DATABASE_PREFIX = "database_ip"
SNI_DATABASE_PREFIX = "database_sni"
MAX_DATABASE_NUM = 99

# Search parameters from environment variables
WORKING_IPS = os.getenv('WORKING_IPS', '45.76.74.41')
SUBNET_MASK = int(os.getenv('SUBNET_MASK', '24'))
SEARCH_SECURITY = os.getenv('SEARCH_SECURITY', '')
SEARCH_FLOW = os.getenv('SEARCH_FLOW', '')
MAX_RESULTS = int(os.getenv('MAX_RESULTS', '200'))

print("=" * 80)
print("IP RANGE CONFIG FINDER - Finding configs in same IP ranges")
print("=" * 80)
print(f"Working IPs: {WORKING_IPS}")
print(f"Subnet Mask: /{SUBNET_MASK}")
print(f"Security Filter: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}")
print(f"Flow Filter: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}")
print(f"Max Results: {MAX_RESULTS if MAX_RESULTS > 0 else 'Unlimited'}")
print("=" * 80)

# Parse working IPs and create subnets
WORKING_IP_LIST = [ip.strip() for ip in WORKING_IPS.split(',')]
TARGET_SUBNETS = []

print(f"\nCalculating IP ranges from {len(WORKING_IP_LIST)} working IP(s):")
for ip_str in WORKING_IP_LIST:
    try:
        ip = ipaddress.ip_address(ip_str)
        # Create network based on subnet mask
        network = ipaddress.ip_network(f"{ip}/{SUBNET_MASK}", strict=False)
        TARGET_SUBNETS.append(network)
        print(f"  ✅ {ip_str} → {network} ({network.num_addresses} addresses)")
    except Exception as e:
        print(f"  ❌ Invalid IP: {ip_str} - {e}")

if not TARGET_SUBNETS:
    print("\n❌ No valid IP ranges to search for!")
    exit(1)

print(f"\nSearching for configs in {len(TARGET_SUBNETS)} IP range(s)")
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


def extract_ip_from_config(config_str: str) -> Optional[str]:
    """Extract IP address from config string."""
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if vmess_data:
                host = vmess_data.get('add', '')
                # Check if it's an IP
                try:
                    ipaddress.ip_address(host)
                    return host
                except:
                    return None
        
        elif config_str.startswith(('vless://', 'trojan://', 'ss://')):
            parsed = urlparse(config_str)
            host = parsed.hostname
            if host:
                try:
                    ipaddress.ip_address(host)
                    return host
                except:
                    return None
        
        return None
    except Exception:
        return None


def extract_config_details(config_str: str) -> Dict:
    """Extract all relevant details from a config string."""
    details = {
        'protocol': '',
        'host': '',
        'port': '',
        'ip': None,
        'security': '',
        'flow': '',
        'network': '',
        'config': config_str,
        'in_target_range': False,
        'matched_subnet': None
    }
    
    try:
        # Extract IP
        ip_str = extract_ip_from_config(config_str)
        if ip_str:
            details['ip'] = ip_str
            
            # Check if IP is in any target subnet
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for subnet in TARGET_SUBNETS:
                    if ip_addr in subnet:
                        details['in_target_range'] = True
                        details['matched_subnet'] = str(subnet)
                        break
            except:
                pass
        
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return details
            
            details['protocol'] = 'vmess'
            details['host'] = vmess_data.get('add', '')
            details['port'] = str(vmess_data.get('port', ''))
            details['security'] = vmess_data.get('tls', 'none')
            details['network'] = vmess_data.get('net', 'tcp')
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            
            details['protocol'] = parsed.scheme
            details['host'] = parsed.hostname or ''
            details['port'] = str(parsed.port) if parsed.port else ''
            details['security'] = params.get('security', ['none'])[0]
            details['flow'] = params.get('flow', [''])[0]
            details['network'] = params.get('type', ['tcp'])[0]
        
        elif config_str.startswith('ss://'):
            details['protocol'] = 'shadowsocks'
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
    
    # MUST be in target IP range
    if not details['in_target_range']:
        return False
    
    # Security check
    if SEARCH_SECURITY:
        if SEARCH_SECURITY.lower() not in details['security'].lower():
            return False
    
    # Flow check
    if SEARCH_FLOW:
        if SEARCH_FLOW.lower() not in details['flow'].lower():
            return False
    
    return True


def search_databases() -> List[Dict]:
    """Search through all database files."""
    found_configs = []
    total_scanned = 0
    total_with_ip = 0
    total_in_range = 0
    
    print("\n" + "=" * 80)
    print("SEARCHING DATABASES FOR IP RANGES")
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
            if i > 5:
                break
            continue
        
        print(f"({len(configs)} configs)")
        
        for config in configs:
            total_scanned += 1
            details = extract_config_details(config)
            
            if details['ip']:
                total_with_ip += 1
            
            if details['in_target_range']:
                total_in_range += 1
            
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
            
            if details['ip']:
                total_with_ip += 1
            
            if details['in_target_range']:
                total_in_range += 1
            
            if matches_criteria(details):
                # Check for duplicates
                if not any(d['config'] == details['config'] for d in found_configs):
                    found_configs.append(details)
                    if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
                        break
    
    print("\n" + "=" * 80)
    print(f"Total configs scanned: {total_scanned}")
    print(f"Configs with IP addresses: {total_with_ip}")
    print(f"IPs in target range: {total_in_range}")
    print(f"Matching all criteria: {len(found_configs)}")
    print("=" * 80)
    
    return found_configs


def save_results(found_configs: List[Dict]):
    """Save results to files."""
    
    if not found_configs:
        print("\n⚠️  No matching configs found in the IP ranges!")
        
        # Create empty files with explanation
        with open('ip_range_summary.txt', 'w') as f:
            f.write("NO MATCHING CONFIGS FOUND IN IP RANGES\n\n")
            f.write("Search Parameters:\n")
            f.write(f"  Working IPs: {WORKING_IPS}\n")
            f.write(f"  Subnet Mask: /{SUBNET_MASK}\n")
            f.write(f"  Target Subnets:\n")
            for subnet in TARGET_SUBNETS:
                f.write(f"    - {subnet}\n")
            f.write(f"  Security: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}\n")
            f.write(f"  Flow: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}\n")
        
        with open('ip_range_configs.txt', 'w') as f:
            f.write("No configs found in the specified IP ranges\n")
        
        with open('ip_range_configs_plain.txt', 'w') as f:
            f.write("No configs found in the specified IP ranges\n")
        
        return
    
    # Group configs by subnet
    configs_by_subnet = {}
    for details in found_configs:
        subnet = details['matched_subnet']
        if subnet not in configs_by_subnet:
            configs_by_subnet[subnet] = []
        configs_by_subnet[subnet].append(details)
    
    # Save detailed results
    with open('ip_range_configs.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("CONFIGS FOUND IN TARGET IP RANGES\n")
        f.write("=" * 80 + "\n\n")
        
        for subnet, configs in configs_by_subnet.items():
            f.write(f"\n{'=' * 80}\n")
            f.write(f"Subnet: {subnet} ({len(configs)} configs)\n")
            f.write(f"{'=' * 80}\n\n")
            
            for i, details in enumerate(configs, 1):
                f.write(f"Config #{i}\n")
                f.write(f"  IP: {details['ip']}\n")
                f.write(f"  Protocol: {details['protocol']}\n")
                f.write(f"  Port: {details['port']}\n")
                f.write(f"  Security: {details['security']}\n")
                f.write(f"  Flow: {details['flow']}\n")
                f.write(f"  Network: {details['network']}\n")
                f.write(f"  Full Config:\n")
                f.write(f"  {details['config']}\n")
                f.write("-" * 80 + "\n\n")
    
    # Save plain configs only
    with open('ip_range_configs_plain.txt', 'w', encoding='utf-8') as f:
        for subnet, configs in configs_by_subnet.items():
            f.write(f"# Subnet: {subnet} ({len(configs)} configs)\n")
            for details in configs:
                f.write(details['config'] + '\n')
            f.write('\n')
    
    # Save summary
    with open('ip_range_summary.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("IP RANGE SEARCH SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Search Parameters:\n")
        f.write(f"  Working IPs: {WORKING_IPS}\n")
        f.write(f"  Subnet Mask: /{SUBNET_MASK}\n")
        f.write(f"  Target Subnets:\n")
        for subnet in TARGET_SUBNETS:
            f.write(f"    - {subnet} ({subnet.num_addresses} addresses)\n")
        f.write(f"  Security: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}\n")
        f.write(f"  Flow: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}\n")
        f.write(f"\nResults: {len(found_configs)} configs found\n\n")
        
        # Breakdown by subnet
        f.write("Configs per Subnet:\n")
        for subnet, configs in configs_by_subnet.items():
            f.write(f"  {subnet}: {len(configs)} configs\n")
        f.write("\n")
        
        # IP distribution
        f.write("Unique IPs Found:\n")
        unique_ips = set(d['ip'] for d in found_configs)
        for ip in sorted(unique_ips):
            count = sum(1 for d in found_configs if d['ip'] == ip)
            f.write(f"  {ip}: {count} config(s)\n")
        f.write("\n")
        
        # Statistics
        protocols = {}
        securities = {}
        flows = {}
        
        for details in found_configs:
            protocols[details['protocol']] = protocols.get(details['protocol'], 0) + 1
            securities[details['security']] = securities.get(details['security'], 0) + 1
            if details['flow']:
                flows[details['flow']] = flows.get(details['flow'], 0) + 1
        
        f.write("Statistics:\n")
        f.write(f"  Protocols: {protocols}\n")
        f.write(f"  Security: {securities}\n")
        f.write(f"  Flows: {flows}\n")
    
    print(f"\n✅ Results saved to:")
    print(f"  - ip_range_configs.txt (detailed)")
    print(f"  - ip_range_configs_plain.txt (configs only)")
    print(f"  - ip_range_summary.txt (summary)")
    
    # Display results
    print(f"\n" + "=" * 80)
    print(f"RESULTS BY SUBNET")
    print("=" * 80)
    
    for subnet, configs in configs_by_subnet.items():
        print(f"\n📍 {subnet}: {len(configs)} configs")
        unique_ips_in_subnet = set(d['ip'] for d in configs)
        print(f"   Unique IPs: {', '.join(sorted(unique_ips_in_subnet))}")


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
