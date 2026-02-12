#!/usr/bin/env python3
"""
Advanced IP Range Config Finder
- Searches neighboring IP subnets
- Identifies provider/ASN and searches all their ranges
- Finds configs most likely to work together
"""

import os
import re
import base64
import json
import ipaddress
import time
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional, Set, Tuple
import requests

# Configuration
BASE_URL = "https://raw.githubusercontent.com/BarimKenzema/Haj-Karim/refs/heads/main"
IP_DATABASE_PREFIX = "database_ip"
SNI_DATABASE_PREFIX = "database_sni"
MAX_DATABASE_NUM = 99

# Search parameters
WORKING_IP = os.getenv('WORKING_IP', '45.76.74.41')
SEARCH_MODE = os.getenv('SEARCH_MODE', 'neighbors')  # neighbors, provider, both
NEIGHBOR_RANGE = int(os.getenv('NEIGHBOR_RANGE', '5'))
SEARCH_SECURITY = os.getenv('SEARCH_SECURITY', '')
SEARCH_FLOW = os.getenv('SEARCH_FLOW', '')
MAX_RESULTS = int(os.getenv('MAX_RESULTS', '500'))

# Common cloud provider IP ranges (CIDR notation)
PROVIDER_RANGES = {
    'Vultr': [
        '45.32.0.0/16', '45.63.0.0/16', '45.76.0.0/16', '45.77.0.0/16',
        '66.42.0.0/16', '104.156.224.0/19', '108.61.0.0/16',
        '140.82.0.0/16', '144.202.0.0/16', '149.28.0.0/16',
        '155.138.0.0/16', '207.148.0.0/16', '207.246.0.0/16',
    ],
    'DigitalOcean': [
        '104.131.0.0/16', '104.236.0.0/16', '138.197.0.0/16',
        '159.65.0.0/16', '159.89.0.0/16', '159.203.0.0/16',
        '161.35.0.0/16', '164.90.0.0/16', '165.227.0.0/16',
        '167.71.0.0/16', '167.99.0.0/16', '167.172.0.0/16',
        '178.62.0.0/16', '188.166.0.0/16', '206.189.0.0/16',
    ],
    'Linode': [
        '45.33.0.0/16', '45.56.0.0/16', '45.79.0.0/16',
        '50.116.0.0/16', '66.175.208.0/20', '69.164.192.0/19',
        '96.126.96.0/19', '139.144.0.0/16', '172.104.0.0/15',
        '173.255.192.0/18', '192.155.80.0/20',
    ],
    'Hetzner': [
        '5.9.0.0/16', '46.4.0.0/16', '78.46.0.0/15',
        '88.99.0.0/16', '94.130.0.0/16', '95.216.0.0/16',
        '116.203.0.0/16', '135.181.0.0/16', '138.201.0.0/16',
        '144.76.0.0/16', '148.251.0.0/16', '159.69.0.0/16',
        '162.55.0.0/16', '168.119.0.0/16', '176.9.0.0/16',
    ],
    'AWS': [
        '13.0.0.0/8', '18.0.0.0/8', '52.0.0.0/8',
        '54.0.0.0/8', '99.0.0.0/8',
    ],
    'Google Cloud': [
        '34.64.0.0/10', '35.184.0.0/13', '35.192.0.0/11',
    ],
}

print("=" * 80)
print("ADVANCED IP RANGE CONFIG FINDER")
print("=" * 80)
print(f"Working IP: {WORKING_IP}")
print(f"Search Mode: {SEARCH_MODE}")
print(f"Neighbor Range: ±{NEIGHBOR_RANGE} subnets")
print(f"Security Filter: {SEARCH_SECURITY if SEARCH_SECURITY else 'Any'}")
print(f"Flow Filter: {SEARCH_FLOW if SEARCH_FLOW else 'Any'}")
print(f"Max Results: {MAX_RESULTS if MAX_RESULTS > 0 else 'Unlimited'}")
print("=" * 80)


def get_ip_info(ip_str: str) -> Dict:
    """Get ASN and provider info for an IP using ip-api.com (free, no auth)."""
    try:
        print(f"\n🔍 Looking up provider info for {ip_str}...")
        response = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,isp,org,as,asname",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                print(f"   Provider: {data.get('isp', 'Unknown')}")
                print(f"   Organization: {data.get('org', 'Unknown')}")
                print(f"   ASN: {data.get('as', 'Unknown')}")
                print(f"   Country: {data.get('country', 'Unknown')}")
                return data
        
        print("   ⚠️  Could not get IP info (using neighbor search only)")
        return {}
    
    except Exception as e:
        print(f"   ⚠️  IP lookup failed: {e}")
        return {}


def generate_neighbor_subnets(ip_str: str, count: int = 5) -> List[ipaddress.IPv4Network]:
    """Generate neighboring /24 subnets around the given IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Get the /24 network this IP belongs to
        base_network = ipaddress.ip_network(f"{ip}/24", strict=False)
        
        # Get the third octet
        octets = str(base_network.network_address).split('.')
        base_third_octet = int(octets[2])
        
        subnets = []
        
        # Generate neighboring subnets
        for offset in range(-count, count + 1):
            new_third_octet = base_third_octet + offset
            if 0 <= new_third_octet <= 255:
                neighbor_network = ipaddress.ip_network(
                    f"{octets[0]}.{octets[1]}.{new_third_octet}.0/24"
                )
                subnets.append(neighbor_network)
        
        return subnets
    
    except Exception as e:
        print(f"Error generating neighbors: {e}")
        return []


def identify_provider(ip_str: str, ip_info: Dict) -> Tuple[Optional[str], List[ipaddress.IPv4Network]]:
    """Identify cloud provider and return their IP ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # First, check known provider ranges
        for provider, ranges in PROVIDER_RANGES.items():
            for cidr in ranges:
                network = ipaddress.ip_network(cidr)
                if ip in network:
                    print(f"\n✅ Identified provider: {provider}")
                    print(f"   Searching {len(ranges)} known {provider} IP ranges...")
                    return provider, [ipaddress.ip_network(r) for r in ranges]
        
        # If not in known ranges, check ISP name from ip-api
        if ip_info:
            isp = ip_info.get('isp', '').lower()
            org = ip_info.get('org', '').lower()
            
            for provider in PROVIDER_RANGES.keys():
                if provider.lower() in isp or provider.lower() in org:
                    print(f"\n✅ Provider identified from ISP name: {provider}")
                    ranges = PROVIDER_RANGES[provider]
                    print(f"   Searching {len(ranges)} known {provider} IP ranges...")
                    return provider, [ipaddress.ip_network(r) for r in ranges]
        
        print("\n⚠️  Provider not in known list (using generic /16 search)")
        # Fallback: use /16 of the IP
        fallback_network = ipaddress.ip_network(f"{ip}/16", strict=False)
        return "Unknown", [fallback_network]
    
    except Exception as e:
        print(f"Error identifying provider: {e}")
        return None, []


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
        
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            return [line.strip() for line in decoded.splitlines() if line.strip()]
        except Exception:
            return [line.strip() for line in content.splitlines() if line.strip()]
    
    except Exception:
        return []


def parse_vmess_config(config_str: str) -> Optional[Dict]:
    """Parse VMess config."""
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
    """Extract IP address from config."""
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if vmess_data:
                host = vmess_data.get('add', '')
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


def extract_config_details(config_str: str, target_subnets: List[ipaddress.IPv4Network]) -> Dict:
    """Extract config details and check if IP is in target ranges."""
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
        ip_str = extract_ip_from_config(config_str)
        if ip_str:
            details['ip'] = ip_str
            
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for subnet in target_subnets:
                    if ip_addr in subnet:
                        details['in_target_range'] = True
                        details['matched_subnet'] = str(subnet)
                        break
            except:
                pass
        
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if vmess_data:
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
    
    except Exception:
        pass
    
    return details


def matches_criteria(details: Dict) -> bool:
    """Check if config matches search criteria."""
    if not details['in_target_range']:
        return False
    
    if SEARCH_SECURITY and SEARCH_SECURITY.lower() not in details['security'].lower():
        return False
    
    if SEARCH_FLOW and SEARCH_FLOW.lower() not in details['flow'].lower():
        return False
    
    return True


def search_databases(target_subnets: List[ipaddress.IPv4Network]) -> List[Dict]:
    """Search databases for configs in target subnets."""
    found_configs = []
    total_scanned = 0
    total_in_range = 0
    
    print(f"\n🔍 Searching for configs in {len(target_subnets)} IP ranges...")
    print(f"   (This may take a few minutes)")
    
    # Combine IP and SNI databases
    all_databases = []
    
    # IP databases
    for i in range(1, MAX_DATABASE_NUM + 1):
        if i == 1:
            all_databases.append(f"{BASE_URL}/{IP_DATABASE_PREFIX}.txt")
        else:
            all_databases.append(f"{BASE_URL}/{IP_DATABASE_PREFIX}_{i}.txt")
    
    # SNI databases
    for i in range(1, MAX_DATABASE_NUM + 1):
        if i == 1:
            all_databases.append(f"{BASE_URL}/{SNI_DATABASE_PREFIX}.txt")
        else:
            all_databases.append(f"{BASE_URL}/{SNI_DATABASE_PREFIX}_{i}.txt")
    
    progress_interval = max(1, len(all_databases) // 20)
    
    for idx, url in enumerate(all_databases):
        if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
            break
        
        if (idx + 1) % progress_interval == 0 or idx == 0:
            print(f"   Progress: {idx + 1}/{len(all_databases)} databases... (found {len(found_configs)} so far)")
        
        configs = download_and_decode(url)
        
        if not configs:
            if idx > 10:  # Stop if we hit too many empty files
                break
            continue
        
        for config in configs:
            total_scanned += 1
            details = extract_config_details(config, target_subnets)
            
            if details['in_target_range']:
                total_in_range += 1
            
            if matches_criteria(details):
                if not any(d['config'] == details['config'] for d in found_configs):
                    found_configs.append(details)
                    if MAX_RESULTS > 0 and len(found_configs) >= MAX_RESULTS:
                        break
    
    print(f"\n✅ Scan complete!")
    print(f"   Total configs scanned: {total_scanned}")
    print(f"   IPs in target ranges: {total_in_range}")
    print(f"   Matching all criteria: {len(found_configs)}")
    
    return found_configs


def save_results(found_configs: List[Dict], ip_info: Dict, provider_name: Optional[str], search_ranges: List):
    """Save results to files."""
    
    # Save provider info
    with open('provider_info.txt', 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("PROVIDER INFORMATION\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Working IP: {WORKING_IP}\n")
        if ip_info:
            f.write(f"ISP: {ip_info.get('isp', 'Unknown')}\n")
            f.write(f"Organization: {ip_info.get('org', 'Unknown')}\n")
            f.write(f"ASN: {ip_info.get('as', 'Unknown')}\n")
            f.write(f"Country: {ip_info.get('country', 'Unknown')}\n")
        if provider_name:
            f.write(f"Identified Provider: {provider_name}\n")
        f.write(f"\nSearch Mode: {SEARCH_MODE}\n")
        f.write(f"IP Ranges Searched: {len(search_ranges)}\n")
    
    if not found_configs:
        print("\n⚠️  No matching configs found!")
        
        with open('advanced_ip_summary.txt', 'w') as f:
            f.write("NO MATCHING CONFIGS FOUND\n\n")
            f.write(f"Searched {len(search_ranges)} IP ranges\n")
            f.write(f"Mode: {SEARCH_MODE}\n")
        
        with open('advanced_ip_configs.txt', 'w') as f:
            f.write("No configs found\n")
        
        with open('advanced_ip_configs_plain.txt', 'w') as f:
            f.write("No configs found\n")
        
        return
    
    # Group by subnet
    configs_by_subnet = {}
    for details in found_configs:
        subnet = details['matched_subnet']
        if subnet not in configs_by_subnet:
            configs_by_subnet[subnet] = []
        configs_by_subnet[subnet].append(details)
    
    # Detailed results
    with open('advanced_ip_configs.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("ADVANCED IP SEARCH RESULTS\n")
        f.write("=" * 80 + "\n\n")
        
        for subnet in sorted(configs_by_subnet.keys()):
            configs = configs_by_subnet[subnet]
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
                f.write(f"  Full Config:\n  {details['config']}\n")
                f.write("-" * 80 + "\n\n")
    
    # Plain configs
    with open('advanced_ip_configs_plain.txt', 'w', encoding='utf-8') as f:
        for subnet in sorted(configs_by_subnet.keys()):
            f.write(f"# Subnet: {subnet}\n")
            for details in configs_by_subnet[subnet]:
                f.write(details['config'] + '\n')
            f.write('\n')
    
    # Summary
    with open('advanced_ip_summary.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("SEARCH SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Working IP: {WORKING_IP}\n")
        f.write(f"Search Mode: {SEARCH_MODE}\n")
        f.write(f"IP Ranges Searched: {len(search_ranges)}\n")
        f.write(f"Configs Found: {len(found_configs)}\n\n")
        
        f.write("Results by Subnet:\n")
        for subnet in sorted(configs_by_subnet.keys()):
            f.write(f"  {subnet}: {len(configs_by_subnet[subnet])} configs\n")
        
        f.write("\nUnique IPs:\n")
        unique_ips = sorted(set(d['ip'] for d in found_configs))
        for ip in unique_ips:
            count = sum(1 for d in found_configs if d['ip'] == ip)
            f.write(f"  {ip}: {count} config(s)\n")
    
    print(f"\n✅ Results saved!")
    print(f"   Total configs: {len(found_configs)}")
    print(f"   Unique IPs: {len(unique_ips)}")
    print(f"   Subnets covered: {len(configs_by_subnet)}")


def main():
    """Main execution."""
    try:
        # Get IP info
        ip_info = get_ip_info(WORKING_IP)
        time.sleep(1)  # Rate limit for API
        
        target_subnets = []
        provider_name = None
        
        # NEIGHBORS mode
        if SEARCH_MODE in ['neighbors', 'both']:
            print(f"\n📍 Generating {NEIGHBOR_RANGE * 2 + 1} neighboring /24 subnets...")
            neighbor_subnets = generate_neighbor_subnets(WORKING_IP, NEIGHBOR_RANGE)
            target_subnets.extend(neighbor_subnets)
            print(f"   Added {len(neighbor_subnets)} neighbor subnets")
            for subnet in neighbor_subnets:
                print(f"     - {subnet}")
        
        # PROVIDER mode
        if SEARCH_MODE in ['provider', 'both']:
            provider_name, provider_ranges = identify_provider(WORKING_IP, ip_info)
            if provider_ranges:
                target_subnets.extend(provider_ranges)
                print(f"   Added {len(provider_ranges)} provider ranges")
        
        if not target_subnets:
            print("\n❌ No IP ranges to search!")
            return
        
        # Remove duplicates
        unique_subnets = []
        seen = set()
        for subnet in target_subnets:
            subnet_str = str(subnet)
            if subnet_str not in seen:
                unique_subnets.append(subnet)
                seen.add(subnet_str)
        
        print(f"\n📊 Total unique IP ranges to search: {len(unique_subnets)}")
        
        # Search
        found_configs = search_databases(unique_subnets)
        
        # Save
        save_results(found_configs, ip_info, provider_name, unique_subnets)
        
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
