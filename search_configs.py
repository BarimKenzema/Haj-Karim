# FILE: search_configs.py
# Search through database files for configs matching specific domain patterns

import os
import base64
import json
import re
from urllib.parse import urlparse, parse_qs

# =========================
# CONFIGURATION
# =========================

# Domain to search for (will match anything ending with this)
SEARCH_DOMAIN = "fromblancwithlove.com"

# Files to search through
FILES_TO_SEARCH = [
    'database_sni.txt',
    'database_sni_2.txt',
    'database_sni_3.txt',
    'database_sni_4.txt',
    'database_sni_5.txt',
    'database_sni_6.txt',
    'database_ip.txt',
    'database_ip_2.txt',
    'database_ip_3.txt',
    'database_ip_4.txt',
    'database_ip_5.txt', 
    'database_ip_6.txt', 
    'filtered-for-refiner.txt',
    'latest_ip_configs.txt',
    'premium_configs.txt',
]

# =========================
# HELPER FUNCTIONS
# =========================

def load_file(filepath):
    """Load and decode a base64 encoded config file."""
    if not os.path.exists(filepath):
        return []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return []
            
            # Try to decode as base64
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                return decoded.splitlines()
            except:
                # If not base64, treat as plain text
                return content.splitlines()
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return []

def parse_vmess_config(config_str):
    """Parse VMess config and return JSON data."""
    try:
        encoded = config_str.replace('vmess://', '').strip().rstrip('.,;!?')
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        decoded_bytes = base64.b64decode(encoded, validate=True)
        
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']:
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

def extract_domains_from_config(config_str):
    """
    Extract all domain/hostname fields from a config.
    Returns a list of domains found in the config.
    """
    domains = []
    
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if vmess_data:
                # Check address
                if 'add' in vmess_data:
                    domains.append(('address', vmess_data['add']))
                # Check SNI
                if 'sni' in vmess_data and vmess_data['sni']:
                    domains.append(('sni', vmess_data['sni']))
                # Check host
                if 'host' in vmess_data and vmess_data['host']:
                    domains.append(('host', vmess_data['host']))
        
        elif config_str.startswith(('vless://', 'trojan://', 'ss://')):
            parsed = urlparse(config_str)
            
            # Check hostname/address
            if parsed.hostname:
                domains.append(('address', parsed.hostname))
            
            # Check query parameters
            params = parse_qs(parsed.query)
            
            # Check SNI
            if 'sni' in params and params['sni'][0]:
                domains.append(('sni', params['sni'][0]))
            
            # Check host
            if 'host' in params and params['host'][0]:
                domains.append(('host', params['host'][0]))
            
            # Check serverName (for Reality)
            if 'serverName' in params and params['serverName'][0]:
                domains.append(('serverName', params['serverName'][0]))
    
    except Exception as e:
        pass
    
    return domains

def matches_domain_pattern(domain, pattern):
    """
    Check if a domain matches the search pattern.
    Returns True if domain ends with pattern.
    """
    if not domain or not pattern:
        return False
    
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()
    
    # Exact match
    if domain == pattern:
        return True
    
    # Ends with pattern (e.g., "kz-2.fromblancwithlove.com" ends with "fromblancwithlove.com")
    if domain.endswith('.' + pattern) or domain.endswith(pattern):
        return True
    
    return False

def get_config_summary(config_str):
    """Get a brief summary of the config for display."""
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if vmess_data:
                return f"VMess - {vmess_data.get('add', 'unknown')}:{vmess_data.get('port', '?')} ({vmess_data.get('ps', 'no name')})"
        
        elif config_str.startswith('vless://'):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            security = params.get('security', ['none'])[0]
            flow = params.get('flow', [''])[0]
            name = parsed.fragment or 'no name'
            return f"VLess - {parsed.hostname}:{parsed.port} (security={security}, flow={flow}) - {name}"
        
        elif config_str.startswith('trojan://'):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            security = params.get('security', ['none'])[0]
            name = parsed.fragment or 'no name'
            return f"Trojan - {parsed.hostname}:{parsed.port} (security={security}) - {name}"
        
        return config_str[:100] + "..." if len(config_str) > 100 else config_str
    
    except Exception:
        return config_str[:100] + "..." if len(config_str) > 100 else config_str

# =========================
# MAIN SEARCH FUNCTION
# =========================

def search_configs(search_domain, files_to_search):
    """
    Search through all database files for configs matching the domain pattern.
    """
    print(f"{'='*80}")
    print(f"  SEARCHING FOR CONFIGS WITH DOMAIN: *.{search_domain}")
    print(f"{'='*80}\n")
    
    all_matches = []
    total_configs_scanned = 0
    
    for filepath in files_to_search:
        if not os.path.exists(filepath):
            continue
        
        print(f"📁 Searching in: {filepath}")
        configs = load_file(filepath)
        
        if not configs:
            print(f"   (empty or unreadable)\n")
            continue
        
        file_matches = []
        
        for config in configs:
            total_configs_scanned += 1
            
            # Extract all domains from this config
            domains = extract_domains_from_config(config)
            
            # Check if any domain matches our pattern
            matching_domains = []
            for field_name, domain in domains:
                if matches_domain_pattern(domain, search_domain):
                    matching_domains.append((field_name, domain))
            
            if matching_domains:
                file_matches.append({
                    'config': config,
                    'matching_domains': matching_domains,
                    'source_file': filepath
                })
        
        if file_matches:
            print(f"   ✅ Found {len(file_matches)} matching config(s)")
            all_matches.extend(file_matches)
        else:
            print(f"   ❌ No matches")
        
        print()
    
    # Display results
    print(f"{'='*80}")
    print(f"  SEARCH RESULTS")
    print(f"{'='*80}\n")
    print(f"Total configs scanned: {total_configs_scanned}")
    print(f"Total matches found: {len(all_matches)}\n")
    
    if all_matches:
        print(f"{'='*80}")
        print(f"  MATCHED CONFIGS")
        print(f"{'='*80}\n")
        
        for i, match in enumerate(all_matches, 1):
            print(f"Match #{i}")
            print(f"  Source: {match['source_file']}")
            print(f"  Summary: {get_config_summary(match['config'])}")
            print(f"  Matching fields:")
            for field_name, domain in match['matching_domains']:
                print(f"    • {field_name}: {domain}")
            print(f"  Full config:")
            print(f"    {match['config']}")
            print()
        
        # Save to file
        output_file = f"search_results_{search_domain.replace('.', '_')}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Search results for domain: *.{search_domain}\n")
            f.write(f"Total matches: {len(all_matches)}\n")
            f.write(f"{'='*80}\n\n")
            
            for i, match in enumerate(all_matches, 1):
                f.write(f"Match #{i}\n")
                f.write(f"Source: {match['source_file']}\n")
                f.write(f"Summary: {get_config_summary(match['config'])}\n")
                f.write(f"Matching fields:\n")
                for field_name, domain in match['matching_domains']:
                    f.write(f"  • {field_name}: {domain}\n")
                f.write(f"Full config:\n{match['config']}\n")
                f.write(f"{'-'*80}\n\n")
        
        print(f"💾 Results saved to: {output_file}")
        
        # Save configs only (for easy import)
        configs_only_file = f"configs_only_{search_domain.replace('.', '_')}.txt"
        with open(configs_only_file, 'w', encoding='utf-8') as f:
            for match in all_matches:
                f.write(match['config'] + '\n')
        
        print(f"💾 Configs saved to: {configs_only_file}")
    else:
        print("No matching configs found.")
    
    print(f"\n{'='*80}")
    print("Search complete!")
    print(f"{'='*80}")

# =========================
# MAIN EXECUTION
# =========================

if __name__ == "__main__":
    print("\n🔍 Config Domain Search Tool\n")
    
    # You can modify the search domain here or accept it as input
    import sys
    
    if len(sys.argv) > 1:
        search_domain = sys.argv[1]
    else:
        search_domain = SEARCH_DOMAIN
    
    print(f"Search domain: *.{search_domain}\n")
    
    # Perform the search
    search_configs(search_domain, FILES_TO_SEARCH)
