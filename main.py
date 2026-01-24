# FILE: main.py (for your GitHub scraper repo)
# VERSION 44.1: Optimized with Cleanup + Debug Logging

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse, parse_qs, quote, urlencode, urlunparse
import concurrent.futures
import geoip2.database
from dns import resolver

print("--- GITHUB COLLECTOR v44.1 (Optimized with Cleanup + Debug) START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 44444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')
VALIDATED_LINKS_FILE = 'validated_subscriptions.json'

# Database configuration
DATABASE_SNI_BASE = 'database_sni'
DATABASE_IP_BASE = 'database_ip'
ACTIVE_FILE_SNI = 'filtered-for-refiner.txt'
ACTIVE_FILE_IP = 'latest_ip_configs.txt'
MAX_ACTIVE_CONFIGS = 4444
MAX_DB_SIZE_MB = 44  # Reduced from 44 to 40MB for safety
MAX_DB_FILES_TO_KEEP = 4  # Keep 4 most recent database files

# --- SHARED CACHING & GLOBALS ---
dns_cache = {}
geoip_reader = None

COUNTRY_FLAGS = {
    "AD": "🇦🇩", "AE": "🇦🇪", "AF": "🇦🇫", "AG": "🇦🇬", "AI": "🇦🇮", "AL": "🇦🇱", "AM": "🇦🇲", 
    "AO": "🇦🇴", "AQ": "🇦🇶", "AR": "🇦🇷", "AS": "🇦🇸", "AT": "🇦🇹", "AU": "🇦🇺", "AW": "🇦🇼", 
    "AX": "🇦🇽", "AZ": "🇦🇿", "BA": "🇧🇦", "BB": "🇧🇧", "BD": "🇧🇩", "BE": "🇧🇪", "BF": "🇧🇫", 
    "BG": "🇧🇬", "BH": "🇧🇭", "BI": "🇧🇮", "BJ": "🇧🇯", "BL": "🇧🇱", "BM": "🇧🇲", "BN": "🇧🇳", 
    "BO": "🇧🇴", "BR": "🇧🇷", "BS": "🇧🇸", "BT": "🇧🇹", "BW": "🇧🇼", "BY": "🇧🇾", "BZ": "🇧🇿", 
    "CA": "🇨🇦", "CC": "🇨🇨", "CD": "🇨🇩", "CF": "🇨🇫", "CG": "🇨🇬", "CH": "🇨🇭", "CI": "🇨🇮", 
    "CK": "🇨🇰", "CL": "🇨🇱", "CM": "🇨🇲", "CN": "🇨🇳", "CO": "🇨🇴", "CR": "🇨🇷", "CU": "🇨🇺", 
    "CV": "🇨🇻", "CW": "🇨🇼", "CX": "🇨🇽", "CY": "🇨🇾", "CZ": "🇨🇿", "DE": "🇩🇪", "DJ": "🇩🇯", 
    "DK": "🇩🇰", "DM": "🇩🇲", "DO": "🇩🇴", "DZ": "🇩🇿", "EC": "🇪🇨", "EE": "🇪🇪", "EG": "🇪🇬", 
    "EH": "🇪🇭", "ER": "🇪🇷", "ES": "🇪🇸", "ET": "🇪🇹", "FI": "🇫🇮", "FJ": "🇫🇯", "FK": "🇫🇰", 
    "FM": "🇫🇲", "FO": "🇫🇴", "FR": "🇫🇷", "GA": "🇬🇦", "GB": "🇬🇧", "GD": "🇬🇩", "GE": "🇬🇪", 
    "GF": "🇬🇫", "GG": "🇬🇬", "GH": "🇬🇭", "GI": "🇬🇮", "GL": "🇬🇱", "GM": "🇬🇲", "GN": "🇬🇳", 
    "GP": "🇬🇵", "GQ": "🇬🇶", "GR": "🇬🇷", "GT": "🇬🇹", "GU": "🇬🇺", "GW": "🇬🇼", "GY": "🇬🇾", 
    "HK": "🇭🇰", "HN": "🇭🇳", "HR": "🇭🇷", "HT": "🇭🇹", "HU": "🇭🇺", "ID": "🇮🇩", "IE": "🇮🇪", 
    "IL": "🇮🇱", "IM": "🇮🇲", "IN": "🇮🇳", "IO": "🇮🇴", "IQ": "🇮🇶", "IR": "🇮🇷", "IS": "🇮🇸", 
    "IT": "🇮🇹", "JE": "🇯🇪", "JM": "🇯🇲", "JO": "🇯🇴", "JP": "🇯🇵", "KE": "🇰🇪", "KG": "🇰🇬", 
    "KH": "🇰🇭", "KI": "🇰🇮", "KM": "🇰🇲", "KN": "🇰🇳", "KP": "🇰🇵", "KR": "🇰🇷", "KW": "🇰🇼", 
    "KY": "🇰🇾", "KZ": "🇰🇿", "LA": "🇱🇦", "LB": "🇱🇧", "LC": "🇱🇨", "LI": "🇱🇮", "LK": "🇱🇰", 
    "LR": "🇱🇷", "LS": "🇱🇸", "LT": "🇱🇹", "LU": "🇱🇺", "LV": "🇱🇻", "LY": "🇱🇾", "MA": "🇲🇦", 
    "MC": "🇲🇨", "MD": "🇲🇩", "ME": "🇲🇪", "MG": "🇲🇬", "MH": "🇲🇭", "MK": "🇲🇰", "ML": "🇲🇱", 
    "MM": "🇲🇲", "MN": "🇲🇳", "MO": "🇲🇴", "MP": "🇲🇵", "MQ": "🇲🇶", "MR": "🇲🇷", "MS": "🇲🇸", 
    "MT": "🇲🇹", "MU": "🇲🇺", "MV": "🇲🇻", "MW": "🇲🇼", "MX": "🇲🇽", "MY": "🇲🇾", "MZ": "🇲🇿", 
    "NA": "🇳🇦", "NC": "🇳🇨", "NE": "🇳🇪", "NF": "🇳🇫", "NG": "🇳🇬", "NI": "🇳🇮", "NL": "🇳🇱", 
    "NO": "🇳🇴", "NP": "🇳🇵", "NR": "🇳🇷", "NU": "🇳🇺", "NZ": "🇳🇿", "OM": "🇴🇲", "PA": "🇵🇦", 
    "PE": "🇵🇪", "PF": "🇵🇫", "PG": "🇵🇬", "PH": "🇵🇭", "PK": "🇵🇰", "PL": "🇵🇱", "PM": "🇵🇲", 
    "PR": "🇵🇷", "PS": "🇵🇸", "PT": "🇵🇹", "PW": "🇵🇼", "PY": "🇵🇾", "QA": "🇶🇦", "RE": "🇷🇪", 
    "RO": "🇷🇴", "RS": "🇷🇸", "RU": "🇷🇺", "RW": "🇷🇼", "SA": "🇸🇦", "SB": "🇸🇧", "SC": "🇸🇨", 
    "SD": "🇸🇩", "SE": "🇸🇪", "SG": "🇸🇬", "SH": "🇸🇭", "SI": "🇸🇮", "SK": "🇸🇰", "SL": "🇸🇱", 
    "SM": "🇸🇲", "SN": "🇸🇳", "SO": "🇸🇴", "SR": "🇸🇷", "SS": "🇸🇸", "ST": "🇸🇹", "SV": "🇸🇻", 
    "SX": "🇸🇽", "SY": "🇸🇾", "SZ": "🇸🇿", "TC": "🇹🇨", "TD": "🇹🇩", "TG": "🇹🇬", "TH": "🇹🇭", 
    "TJ": "🇹🇯", "TK": "🇹🇰", "TL": "🇹🇱", "TM": "🇹🇲", "TN": "🇹🇳", "TO": "🇹🇴", "TR": "🇹🇷", 
    "TT": "🇹🇹", "TV": "🇹🇻", "TW": "🇹🇼", "TZ": "🇹🇿", "UA": "🇺🇦", "UG": "🇺🇬", "US": "🇺🇸", 
    "UY": "🇺🇾", "UZ": "🇺🇿", "VA": "🇻🇦", "VC": "🇻🇨", "VE": "🇻🇪", "VG": "🇻🇬", "VI": "🇻🇮", 
    "VN": "🇻🇳", "VU": "🇻🇺", "WF": "🇼🇫", "WS": "🇼🇸", "YE": "🇾🇪", "YT": "🇾🇹", "ZA": "🇿🇦", 
    "ZM": "🇿🇲", "ZW": "🇿🇼", "XX": "🔓"
}

# =========================
# Database Cleanup & Management
# =========================

def cleanup_old_database_files(base_name, keep_latest=MAX_DB_FILES_TO_KEEP):
    """
    Keep only the N most recent database files to prevent repository bloat.
    Deletes older numbered files.
    """
    files = get_database_files(base_name)
    
    if len(files) <= keep_latest:
        return  # Nothing to clean
    
    # Sort files: base file first, then numbered ones
    # We want to keep the latest numbered files
    to_delete = files[:-keep_latest] if len(files) > keep_latest else []
    
    deleted_count = 0
    for file_path in to_delete:
        try:
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            os.remove(file_path)
            print(f"  🗑️  Removed old database: {file_path} ({size_mb:.2f}MB)")
            deleted_count += 1
        except Exception as e:
            print(f"  ⚠️  Could not remove {file_path}: {e}")
    
    if deleted_count > 0:
        print(f"  ✅ Cleaned up {deleted_count} old database file(s) for {base_name}")

def get_database_files(base_name):
    """Get all database files for a base name (e.g., 'database_ip')"""
    files = []
    # Check base file
    base_file = f"{base_name}.txt"
    if os.path.exists(base_file):
        files.append(base_file)
    # Check numbered files
    i = 2
    while True:
        numbered_file = f"{base_name}_{i}.txt"
        if os.path.exists(numbered_file):
            files.append(numbered_file)
            i += 1
        else:
            break
    return files

def get_current_database_file(base_name):
    """Get the current active database file (latest one to write to)"""
    files = get_database_files(base_name)
    if not files:
        return f"{base_name}.txt"
    return files[-1]  # Last one is the latest

def load_database(db_file):
    """Load a single database file (base64 encoded)"""
    if not os.path.exists(db_file):
        return set()
    try:
        with open(db_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return set()
            decoded = base64.b64decode(content).decode('utf-8')
            return set(decoded.splitlines())
    except Exception as e:
        print(f"Warning: Could not load {db_file}: {e}")
        return set()

def load_all_databases(base_name):
    """Load configs from ALL database files (base + numbered)"""
    all_configs = set()
    files = get_database_files(base_name)
    
    if not files:
        print(f"  No database files found for {base_name}")
        return all_configs
    
    print(f"  Loading from {len(files)} database file(s):")
    for db_file in files:
        configs = load_database(db_file)
        all_configs.update(configs)
        size_mb = os.path.getsize(db_file) / (1024 * 1024) if os.path.exists(db_file) else 0
        print(f"    • {db_file}: {len(configs)} configs ({size_mb:.2f} MB)")
    
    return all_configs

def save_database(db_file, configs_set):
    """Save configs to a single database file (base64 encoded)"""
    try:
        content = "\n".join(sorted(configs_set))
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(db_file, 'w', encoding='utf-8') as f:
            f.write(encoded)
    except Exception as e:
        print(f"Error saving {db_file}: {e}")

def save_database_smart(base_name, new_configs_list):
    """
    Smart save: Add new configs to current DB file.
    If it would exceed MAX_DB_SIZE_MB, create new numbered file.
    Returns the filename that was written to.
    """
    if not new_configs_list:
        return None
    
    current_file = get_current_database_file(base_name)
    
    # Load existing configs from current file only
    existing = load_database(current_file) if os.path.exists(current_file) else set()
    
    # Combine with new configs
    combined = existing.union(set(new_configs_list))
    
    # Calculate what the size would be
    test_content = "\n".join(sorted(combined))
    test_encoded = base64.b64encode(test_content.encode('utf-8')).decode('utf-8')
    test_size_mb = len(test_encoded.encode('utf-8')) / (1024 * 1024)
    
    # If would exceed limit AND we have existing data, create new file
    if test_size_mb > MAX_DB_SIZE_MB and existing:
        # Determine next file number
        if "_" in current_file:
            # Extract number from current file (e.g., database_ip_2.txt -> 2)
            base_part = current_file.rsplit("_", 1)[0]
            num_part = current_file.rsplit("_", 1)[1].replace(".txt", "")
            try:
                current_num = int(num_part)
                next_file = f"{base_part}_{current_num + 1}.txt"
            except:
                next_file = f"{base_name}_2.txt"
        else:
            # First split: base.txt -> base_2.txt
            next_file = f"{base_name}_2.txt"
        
        print(f"  ⚠️  {current_file} would be {test_size_mb:.2f}MB (limit: {MAX_DB_SIZE_MB}MB)")
        print(f"  ✅ Creating new database file: {next_file}")
        
        # Save ONLY new configs to new file
        save_database(next_file, set(new_configs_list))
        return next_file
    else:
        # Save combined to current file
        save_database(current_file, combined)
        print(f"  ✅ Updated {current_file} ({test_size_mb:.2f}MB, {len(combined)} total configs)")
        return current_file

def save_active_file(filepath, configs_list):
    """Save active file (base64 encoded, capped at MAX_ACTIVE_CONFIGS)"""
    try:
        configs_to_save = configs_list[-MAX_ACTIVE_CONFIGS:] if len(configs_list) > MAX_ACTIVE_CONFIGS else configs_list
        content = "\n".join(configs_to_save)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(encoded)
        return len(configs_to_save)
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return 0

def load_list_from_file(filepath):
    """Load a list from base64 encoded file"""
    if not os.path.exists(filepath): 
        return []
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            if content: 
                return base64.b64decode(content).decode('utf-8').splitlines()
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return []
    return []

def merge_active_by_fingerprint(existing_list, new_list):
    """
    Merge existing + new (in order), deduplicate by fingerprint keeping the LAST occurrence (newer),
    then cap to newest MAX_ACTIVE_CONFIGS.
    """
    combined = existing_list + new_list
    seen = set()
    dedup_rev = []
    for cfg in reversed(combined):
        fp = get_config_fingerprint(cfg)
        key = fp if fp else f"RAW::{cfg}"
        if key not in seen:
            dedup_rev.append(cfg)
            seen.add(key)
    dedup = list(reversed(dedup_rev))
    if len(dedup) > MAX_ACTIVE_CONFIGS:
        dedup = dedup[-MAX_ACTIVE_CONFIGS:]
    return dedup

# =========================
# Resolution & parsing
# =========================
def country_code_to_flag(iso_code):
    return COUNTRY_FLAGS.get(iso_code, "🌐")

def resolve_domain_to_ip(hostname):
    if not hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    if hostname in dns_cache:
        return dns_cache[hostname]
    try:
        res = resolver.Resolver()
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        ip_addr = res.resolve(hostname, 'A')[0].to_text()
        dns_cache[hostname] = ip_addr
        return ip_addr
    except Exception:
        dns_cache[hostname] = None
        return None

def parse_vmess_config(config_str):
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
                if 'add' in parsed and 'port' in parsed and 'id' in parsed:
                    return parsed
            except Exception:
                continue
        return None
    except Exception:
        return None

def get_config_fingerprint(config_str):
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return None
            return f"vmess|{vmess_data.get('add', '')}|{vmess_data.get('port', '')}|{vmess_data.get('id', '')}"
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            try:
                port = parsed.port or ''
            except:
                port = ''
            return f"{parsed.scheme}|{parsed.hostname}|{port}|{parsed.username}"
        elif config_str.startswith('ss://'):
            parts = config_str.split('@')
            if len(parts) == 2:
                return f"ss|{parts[1].split('#')[0]}|{parts[0].replace('ss://', '')}"
        else:
            parsed = urlparse(config_str)
            try:
                port = parsed.port or ''
            except:
                port = ''
            return f"{parsed.scheme}|{parsed.hostname}|{port}|{parsed.username}"
    except Exception:
        return None

def replace_address_with_sni(config_str):
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return config_str
            sni = vmess_data.get('sni', '').strip()
            host = vmess_data.get('host', '').strip()
            current_addr = vmess_data.get('add', '').strip()
            new_addr = sni or host
            if new_addr and new_addr != current_addr:
                vmess_data['add'] = new_addr
                new_json = json.dumps(vmess_data, separators=(',', ':'))
                return f"vmess://{base64.b64encode(new_json.encode('utf-8')).decode('utf-8')}"
            return config_str
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            sni = params.get('sni', [''])[0].strip()
            host = params.get('host', [''])[0].strip()
            new_addr = sni or host
            if new_addr and new_addr != (parsed.hostname or ''):
                new_netloc = new_addr
                try:
                    if parsed.port:
                        new_netloc = f"{new_addr}:{parsed.port}"
                except:
                    pass
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                return parsed._replace(netloc=new_netloc).geturl()
            return config_str
        return config_str
    except Exception:
        return config_str

def replace_domain_with_ip(config_str):
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return config_str
            domain = vmess_data.get('add', '')
            ip_addr = resolve_domain_to_ip(domain)
            if ip_addr and ip_addr != domain:
                if vmess_data.get('tls') == 'tls' and not vmess_data.get('sni'):
                    vmess_data['sni'] = domain
                vmess_data['add'] = ip_addr
                new_json = json.dumps(vmess_data, separators=(',', ':'))
                return f"vmess://{base64.b64encode(new_json.encode('utf-8')).decode('utf-8')}"
            return config_str
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            domain = parsed.hostname
            if not domain:
                return config_str
            ip_addr = resolve_domain_to_ip(domain)
            if ip_addr and ip_addr != domain:
                params = parse_qs(parsed.query)
                security = params.get('security', [''])[0]
                if security in ['tls', 'reality'] and 'sni' not in params:
                    params['sni'] = [domain]
                network_type = params.get('type', [''])[0]
                if network_type in ['http', 'ws'] and 'host' not in params:
                    params['host'] = [domain]
                new_query = urlencode(params, doseq=True)
                new_netloc = ip_addr
                try:
                    if parsed.port:
                        new_netloc = f"{ip_addr}:{parsed.port}"
                except:
                    pass
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                return parsed._replace(netloc=new_netloc, query=new_query).geturl()
            return config_str
        elif config_str.startswith('ss://'):
            parts = config_str.split('@')
            if len(parts) != 2:
                return config_str
            prefix, suffix = parts[0], parts[1]
            fragment = ''
            if '#' in suffix:
                suffix, fragment = suffix.split('#', 1)
                fragment = f'#{fragment}'
            domain, port = suffix.rsplit(':', 1) if ':' in suffix else (suffix, '443')
            ip_addr = resolve_domain_to_ip(domain)
            if ip_addr and ip_addr != domain:
                return f"{prefix}@{ip_addr}:{port}{fragment}"
            return config_str
        return config_str
    except Exception:
        return config_str

def get_country_from_hostname(hostname):
    if not hostname:
        return "XX"
    ip_addr = resolve_domain_to_ip(hostname)
    if not ip_addr or not geoip_reader:
        return "XX"
    try:
        return geoip_reader.country(ip_addr).country.iso_code or "XX"
    except Exception:
        return "XX"

def get_config_attributes(config_str):
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return None
            protocol = 'vmess'
            network = vmess_data.get('net', 'tcp').lower().strip()
            security = vmess_data.get('tls', 'none').lower().strip()
            country = get_country_from_hostname(vmess_data.get('add', '')).upper()
        else:
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            protocol = parsed.scheme.lower().strip()
            hostname = parsed.hostname
            network = params.get('type', ['tcp'])[0].lower().strip()
            security = params.get('security', ['none'])[0].lower().strip()
            if security != 'reality' and 'pbk' in params:
                security = 'reality'
            country = get_country_from_hostname(hostname).upper()
        valid_protocols = ['vmess', 'vless', 'trojan', 'ss', 'hy2', 'hysteria', 'tuic', 'juicity']
        if not protocol or protocol not in valid_protocols:
            return None
        valid_networks = ['tcp', 'kcp', 'ws', 'http', 'quic', 'grpc', 'h2', 'httpupgrade', 'splithttp']
        if not network or network not in valid_networks:
            network = 'tcp'
        valid_security = ['none', 'tls', 'reality', 'xtls']
        if not security or security not in valid_security:
            security = 'none'
        if not country or len(country) != 2 or not country.isalpha():
            country = 'XX'
        return {'protocol': protocol, 'network': network, 'security': security, 'country': country}
    except Exception:
        return None

def rename_config(config_str, country_code):
    try:
        flag = country_code_to_flag(country_code)
        new_name = f"{flag} @MoboNetPC {flag}"
        return f"{config_str.split('#')[0]}#{quote(new_name)}"
    except Exception:
        return config_str

# --- FS helpers ---
def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './protocols', './networks', './countries', './security']
    for d in dirs:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    print("INFO: Directories ready.")

def json_load_safe(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR loading {path}: {e}")
        return []

def find_configs_raw(text):
    if not text:
        return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

def check_host_port_with_socket(host_port):
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except:
        return None

def write_chunked_subscription_files(base_filepath, configs):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f:
            f.write("")
        return
    chunks = [configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(configs), CONFIG_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(
            os.path.dirname(base_filepath), 
            f"{os.path.basename(base_filepath)}{i + 1}"
        )
        content = base64.b64encode("\n".join(chunk).encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

# --- TIER 1: DIRECT AGGREGATORS ---
def fetch_from_direct_aggregators():
    print("\n--- [TIER 1] Direct Aggregators ---")
    configs = set()
    aggregators = [
        'https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity',
        'https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt',
        'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt',
        'https://raw.githubusercontent.com/AzadNetCH/Clash/main/V2Ray.txt',
        'https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray',
        'https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all',
        'https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2',
        'https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub',
    ]
    for url in aggregators:
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                content = response.text
                if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                    try:
                        content = base64.b64decode(content).decode('utf-8', 'ignore')
                    except:
                        pass
                found = find_configs_raw(content)
                if found:
                    configs.update(found)
                    print(f"  ✓ {url.split('/')[-3]}: {len(found)} configs")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ {url}: {e}")
            continue
    print(f"Collected {len(configs)} from aggregators")
    return configs

# --- TIER 2: CODE SEARCH ---
def fetch_from_github_code_search():
    print("\n--- [TIER 2] GitHub Code Search ---")
    if not COLLECTOR_TOKEN:
        print("  ⚠ No token, skipping")
        return set()
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'}
    queries = [
        '"vless" "کانفیگ" "رایگان"', '"vmess" "ایرانسل"', '"trojan" "همراه اول"',
        '"v2ray" "رایتل"', 'filename:subscribe "v2ray" "ایران"', '"reality" "کانفیگ"',
        '"vmess://" "subscription"', '"vless://" "subscription"', '"trojan://" "free"',
        '"vmess" "免费"', '"v2ray" "订阅"', '"节点" "分享"', '"翻墙" "配置"',
        '"vmess" "бесплатно"', '"v2ray" "подписка"', '"прокси" "бесплатно"',
        'filename:subscription.txt "vmess"', 'filename:sub.txt "vless"',
        'filename:all.txt "vmess://"', 'path:subscribe "vmess://"',
        '"hy2://"', '"tuic://"', '"reality" "grpc"', '"vless" "xtls"',
        '"clash" "proxies:" extension:yaml', '"vmess://" pushed:>2024-06-01',
        'size:>10000 "vmess://"', '"collector" "vmess"', '"aggregator" "v2ray"',
    ]
    query_count = 0
    for query in queries:
        if query_count >= 30:
            break
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6)
            res = requests.get(search_url, headers=headers, timeout=30)
            if res.status_code == 403:
                print(f"  Rate limit hit, stopping code search")
                break
            res.raise_for_status()
            items = res.json().get('items', [])
            if items:
                print(f"  Query {query_count + 1}: {len(items)} files")
            for item in items:
                time.sleep(0.5)
                try:
                    content_res = requests.get(item.get('url'), headers=headers, timeout=10)
                    if content_res.status_code == 200:
                        content = content_res.text
                        if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                            try:
                                content = base64.b64decode(content).decode('utf-8', 'ignore')
                            except:
                                pass
                        configs.update(find_configs_raw(content))
                except:
                    continue
            query_count += 1
        except Exception as e:
            if 'rate limit' in str(e).lower():
                break
            continue
    print(f"Collected {len(configs)} from code search")
    return configs

# --- TIER 2: SMART REPO SEARCH ---
def fetch_from_github_repos_smart():
    print("\n--- [TIER 2] Smart Repo Search ---")
    if not COLLECTOR_TOKEN:
        return set()
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    repo_queries = ['v2ray subscription', 'proxy subscription', 'v2ray collector']
    for query in repo_queries[:2]:
        try:
            time.sleep(6)
            search_url = f"https://api.github.com/search/repositories?q={query}&sort=updated&per_page=10"
            res = requests.get(search_url, headers=headers, timeout=30)
            if res.status_code != 200:
                continue
            repos = res.json().get('items', [])
            print(f"  '{query}': {len(repos)} repos")
            for repo in repos:
                try:
                    time.sleep(1)
                    default_branch = repo.get('default_branch', 'main')
                    tree_url = f"https://api.github.com/repos/{repo['full_name']}/git/trees/{default_branch}?recursive=1"
                    tree_res = requests.get(tree_url, headers=headers, timeout=10)
                    if tree_res.status_code != 200:
                        continue
                    tree = tree_res.json().get('tree', [])
                    promising_files = []
                    for file_obj in tree:
                        path = file_obj.get('path', '')
                        if file_obj.get('type') == 'blob':
                            lower_path = path.lower()
                            if any(k in lower_path for k in ['sub', 'config', 'node', 'proxy', 'v2ray', 'all', 'merge']) and path.endswith(('.txt', '.yaml', '.yml')):
                                promising_files.append(path)
                    for file_path in promising_files[:5]:
                        try:
                            time.sleep(0.5)
                            raw_url = f"https://raw.githubusercontent.com/{repo['full_name']}/{default_branch}/{file_path}"
                            content_res = requests.get(raw_url, timeout=10)
                            if content_res.status_code == 200:
                                content = content_res.text
                                if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                                    try:
                                        content = base64.b64decode(content).decode('utf-8', 'ignore')
                                    except:
                                        pass
                                found = find_configs_raw(content)
                                if found:
                                    configs.update(found)
                                    print(f"    ✓ {repo['name']}/{file_path}: {len(found)}")
                        except:
                            continue
                except:
                    continue
        except:
            continue
    print(f"Collected {len(configs)} from smart repo search")
    return configs

# --- TIER 3: VALIDATED LINKS CACHE ---
def load_validated_links():
    try:
        with open(VALIDATED_LINKS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_validated_links(links_data):
    try:
        with open(VALIDATED_LINKS_FILE, 'w') as f:
            json.dump(links_data, f, indent=2)
    except:
        pass

def fetch_and_validate_readme_links():
    print("\n--- [TIER 3] README Links ---")
    if not COLLECTOR_TOKEN:
        return set()
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    validated_links = load_validated_links()
    print("  Testing cached links...")
    working_links = {}
    for link, metadata in validated_links.items():
        try:
            response = requests.get(link, timeout=10)
            if response.status_code == 200:
                found = find_configs_raw(response.text)
                if found:
                    configs.update(found)
                    working_links[link] = {'last_success': time.time(), 'total_configs': len(found)}
            time.sleep(0.3)
        except:
            continue
    save_validated_links(working_links)
    print(f"Collected {len(configs)} from validated links")
    return configs

# --- PRE-FILTERING ---
def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs ---")
    fingerprint_to_config = {}
    for config in all_configs:
        fp = get_config_fingerprint(config)
        if fp and fp not in fingerprint_to_config:
            fingerprint_to_config[fp] = config
    print(f"After deduplication: {len(fingerprint_to_config)} unique")
    
    host_port_to_fingerprint = {}
    parse_errors = 0
    for fp, config in fingerprint_to_config.items():
        try:
            if config.startswith('vmess://'):
                vmess_data = parse_vmess_config(config)
                if not vmess_data:
                    continue
                host, port = vmess_data.get('add'), vmess_data.get('port')
            else:
                parsed = urlparse(config)
                host = parsed.hostname
                try:
                    port = parsed.port
                except:
                    parse_errors += 1
                    continue
            if not host or not port:
                continue
            try:
                port = int(port)
            except:
                parse_errors += 1
                continue
            if port < 1 or port > 65535:
                parse_errors += 1
                continue
            ip_addr = resolve_domain_to_ip(host)
            if not ip_addr:
                continue
            host_port_key = f"{ip_addr}:{port}"
            if host_port_key not in host_port_to_fingerprint:
                host_port_to_fingerprint[host_port_key] = fp
        except:
            parse_errors += 1
            continue
    
    if parse_errors > 0:
        print(f"Skipped {parse_errors} malformed")
    print(f"Testing {len(host_port_to_fingerprint)} unique host:port pairs...")
    
    live_host_ports = set()
    hosts_to_test = list(host_port_to_fingerprint.keys())
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {executor.submit(check_host_port_with_socket, hp): hp for hp in hosts_to_test}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0:
                print(f"  Tested {i+1}/{len(hosts_to_test)}...")
            result = future.result()
            if result:
                live_host_ports.add(result)
    
    live_fingerprints = {host_port_to_fingerprint[hp] for hp in live_host_ports if hp in host_port_to_fingerprint}
    live_configs = [fingerprint_to_config[fp] for fp in live_fingerprints if fp in fingerprint_to_config]
    print(f"Pre-filter complete: {len(live_configs)} live configs")
    return live_configs

# --- PROCESSING ---
def process_and_convert_configs(configs):
    print(f"\n--- Processing {len(configs)} configs ---")
    processed = []
    stats = {'converted': 0, 'failed_attrs': 0}
    for config in configs:
        ip_config = replace_domain_with_ip(config)
        if ip_config != config:
            stats['converted'] += 1
        attrs = get_config_attributes(ip_config)
        if not attrs:
            stats['failed_attrs'] += 1
            continue
        final_config = rename_config(ip_config, attrs['country'])
        processed.append({'config': final_config, 'attrs': attrs})
    print(f"Converted {stats['converted']} to IP, failed {stats['failed_attrs']}")
    return processed

# --- MAIN EXECUTION ---
def main():
    global geoip_reader
    
    print("DEBUG: main() function started")
    print(f"DEBUG: Current directory: {os.getcwd()}")
    print(f"DEBUG: COLLECTOR_TOKEN exists: {bool(COLLECTOR_TOKEN)}")
    
    try:
        files_in_dir = os.listdir('.')
        print(f"DEBUG: Files in directory ({len(files_in_dir)} total): {files_in_dir[:30]}")
    except Exception as e:
        print(f"ERROR listing directory: {e}")
    
    try:
        setup_directories()
        print("DEBUG: Directories setup complete")
    except Exception as e:
        print(f"ERROR in setup_directories: {e}")
        traceback.print_exc()
        return
    
    # Download GeoIP
    db_path = "./geoip.mmdb"
    if not os.path.exists(db_path):
        print("Downloading GeoIP...")
        for url in [
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
            "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
        ]:
            try:
                r = requests.get(url, allow_redirects=True, timeout=30)
                if r.status_code == 200:
                    with open(db_path, 'wb') as f:
                        f.write(r.content)
                    print(f"✓ GeoIP downloaded from {url}")
                    break
            except Exception as e:
                print(f"Failed to download from {url}: {e}")
                continue
    else:
        print(f"DEBUG: GeoIP database already exists ({os.path.getsize(db_path)} bytes)")
    
    try:
        geoip_reader = geoip2.database.Reader(db_path)
        print("DEBUG: GeoIP reader initialized")
    except Exception as e:
        print(f"Warning: GeoIP load failed: {e}")
    
    # === CLEANUP OLD DATABASE FILES ===
    print(f"\n{'='*70}")
    print(f"  DATABASE CLEANUP")
    print(f"{'='*70}")
    
    try:
        cleanup_old_database_files(DATABASE_SNI_BASE, keep_latest=MAX_DB_FILES_TO_KEEP)
        cleanup_old_database_files(DATABASE_IP_BASE, keep_latest=MAX_DB_FILES_TO_KEEP)
        print("DEBUG: Cleanup complete")
    except Exception as e:
        print(f"ERROR during cleanup: {e}")
        traceback.print_exc()
    
    # Collect from all sources
    all_raw_configs = set()
    
    print("\n--- Collecting from subscription links.json ---")
    subs_links = json_load_safe('subscription links.json')
    print(f"DEBUG: Loaded {len(subs_links)} subscription links")
    
    for i, link in enumerate(subs_links):
        try:
            print(f"  Fetching link {i+1}/{len(subs_links)}: {link}")
            content = requests.get(link, timeout=15).text
            if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                try:
                    content = base64.b64decode(content).decode('utf-8', 'ignore')
                except:
                    pass
            found = find_configs_raw(content)
            all_raw_configs.update(found)
            print(f"    Found {len(found)} configs")
        except Exception as e:
            print(f"  ERROR fetching {link}: {e}")
            continue
    print(f"✓ Local: {len(all_raw_configs)} configs")
    
    print("DEBUG: About to fetch from aggregators...")
    try:
        agg_configs = fetch_from_direct_aggregators()
        all_raw_configs.update(agg_configs)
        print(f"DEBUG: Aggregators returned {len(agg_configs)} configs")
    except Exception as e:
        print(f"ERROR in aggregators: {e}")
        traceback.print_exc()
    
    print("DEBUG: About to fetch from code search...")
    try:
        code_configs = fetch_from_github_code_search()
        all_raw_configs.update(code_configs)
        print(f"DEBUG: Code search returned {len(code_configs)} configs")
    except Exception as e:
        print(f"ERROR in code search: {e}")
        traceback.print_exc()
    
    print("DEBUG: About to fetch from smart repos...")
    try:
        repo_configs = fetch_from_github_repos_smart()
        all_raw_configs.update(repo_configs)
        print(f"DEBUG: Smart repos returned {len(repo_configs)} configs")
    except Exception as e:
        print(f"ERROR in smart repos: {e}")
        traceback.print_exc()
    
    print("DEBUG: About to fetch from README links...")
    try:
        readme_configs = fetch_and_validate_readme_links()
        all_raw_configs.update(readme_configs)
        print(f"DEBUG: README links returned {len(readme_configs)} configs")
    except Exception as e:
        print(f"ERROR in README links: {e}")
        traceback.print_exc()
    
    print(f"\n{'='*70}")
    print(f"  COLLECTION COMPLETE: {len(all_raw_configs)} raw configs")
    print(f"{'='*70}\n")
    
    if not all_raw_configs:
        print("⚠️ No configs collected. This might be normal if nothing changed.")
        print("DEBUG: Exiting normally with no changes")
        return
    
    # Pre-filter
    print("DEBUG: Starting pre-filter...")
    try:
        live_configs = pre_filter_live_hosts(list(all_raw_configs))
        print(f"DEBUG: Pre-filter complete, {len(live_configs)} live configs")
    except Exception as e:
        print(f"ERROR in pre-filter: {e}")
        traceback.print_exc()
        return
    
    if not live_configs:
        print("⚠️ No live configs after filtering.")
        return
    
    # === SNI DATABASE PROCESSING ===
    print(f"\n{'='*70}")
    print(f"  SNI DATABASE PROCESSING")
    print(f"{'='*70}")
    
    db_sni_all = load_all_databases(DATABASE_SNI_BASE)
    print(f"Total historical SNI configs across all databases: {len(db_sni_all)}")
    
    # Build SNI-based configs (SNI/host as address) and rename
    sni_configs_in_order = []
    for cfg in live_configs:
        sni_cfg = replace_address_with_sni(cfg)
        attrs = get_config_attributes(sni_cfg)
        if attrs:
            sni_configs_in_order.append(rename_config(sni_cfg, attrs['country']))
        else:
            sni_configs_in_order.append(sni_cfg)
    
    # New vs ALL DBs (string-level)
    sni_new = [c for c in sni_configs_in_order if c not in db_sni_all]
    print(f"Found {len(sni_new)} NEW SNI configs")
    
    if sni_new:
        saved_to = save_database_smart(DATABASE_SNI_BASE, sni_new)
        
        # Accumulate Active SNI
        existing_active_sni = load_list_from_file(ACTIVE_FILE_SNI) or []
        active_sni_merged = merge_active_by_fingerprint(existing_active_sni, sni_new)
        saved_count = save_active_file(ACTIVE_FILE_SNI, active_sni_merged)
        print(f"  ✅ Saved {saved_count} to {ACTIVE_FILE_SNI} (accumulated)")
    else:
        print("  ℹ️  No new SNI configs this run (active file unchanged)")
    
    # === IP DATABASE PROCESSING ===
    print(f"\n{'='*70}")
    print(f"  IP DATABASE PROCESSING")
    print(f"{'='*70}")
    
    db_ip_all = load_all_databases(DATABASE_IP_BASE)
    print(f"Total historical IP configs across all databases: {len(db_ip_all)}")
    
    processed = process_and_convert_configs(live_configs)
    ip_configs_in_order = [item['config'] for item in processed]
    
    ip_new = [c for c in ip_configs_in_order if c not in db_ip_all]
    print(f"Found {len(ip_new)} NEW IP configs")
    
    if ip_new:
        saved_to = save_database_smart(DATABASE_IP_BASE, ip_new)
        
        # Accumulate Active IP
        existing_active_ip = load_list_from_file(ACTIVE_FILE_IP) or []
        active_ip_merged = merge_active_by_fingerprint(existing_active_ip, ip_new)
        saved_count = save_active_file(ACTIVE_FILE_IP, active_ip_merged)
        print(f"  ✅ Saved {saved_count} to {ACTIVE_FILE_IP} (accumulated)")
    else:
        print("  ℹ️  No new IP configs this run (active file unchanged)")
    
    # === CATEGORIZATION (using ALL processed configs) ===
    print(f"\n{'='*70}")
    print(f"  CATEGORIZATION")
    print(f"{'='*70}")
    
    by_protocol, by_network, by_security, by_country = {}, {}, {}, {}
    for item in processed:
        config, attrs = item['config'], item['attrs']
        by_protocol.setdefault(attrs['protocol'], []).append(config)
        by_network.setdefault(attrs['network'], []).append(config)
        by_security.setdefault(attrs['security'], []).append(config)
        by_country.setdefault(attrs['country'].lower(), []).append(config)
    
    for proto, configs in by_protocol.items():
        write_chunked_subscription_files(f'./protocols/{proto}', configs)
    for net, configs in by_network.items():
        write_chunked_subscription_files(f'./networks/{net}', configs)
    for sec, configs in by_security.items():
        write_chunked_subscription_files(f'./security/{sec}', configs)
    for country, configs in by_country.items():
        write_chunked_subscription_files(f'./countries/{country}', configs)
    
    all_final = [item['config'] for item in processed]
    write_chunked_subscription_files('./splitted/mixed', all_final)
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"  Raw collected          : {len(all_raw_configs)}")
    print(f"  Live filtered          : {len(live_configs)}")
    print(f"  SNI DB total (all)     : {len(db_sni_all)}")
    print(f"  IP  DB total (all)     : {len(db_ip_all)}")
    print(f"  Active SNI (current)   : {len(load_list_from_file(ACTIVE_FILE_SNI))}")
    print(f"  Active IP (current)    : {len(load_list_from_file(ACTIVE_FILE_IP))}")
    print(f"  SNI DB files           : {', '.join(get_database_files(DATABASE_SNI_BASE)) or 'None'}")
    print(f"  IP  DB files           : {', '.join(get_database_files(DATABASE_IP_BASE)) or 'None'}")
    print(f"  Protocol groups        : {len(by_protocol)}")
    print(f"  Network groups         : {len(by_network)}")
    print(f"  Security groups        : {len(by_security)}")
    print(f"  Country groups         : {len(by_country)}")
    print(f"{'='*70}")
    print("\n✓ COLLECTION COMPLETE - Databases & Active Files Updated!")


if __name__ == "__main__":
    print("DEBUG: __name__ == '__main__' block reached")
    try:
        main()
        print("DEBUG: main() completed successfully")
    except Exception as e:
        print(f"\n--- FATAL ERROR ---")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {e}")
        traceback.print_exc()
        exit(1)
    
    print("DEBUG: Script ending normally")
