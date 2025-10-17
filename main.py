# FILE: main.py (for your GitHub scraper repo: v2ray-collector)
# VERSION 39.2: SNI→Address for filtered-for-refiner.txt, IP for others

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse, parse_qs, quote, urlencode, urlunparse
import concurrent.futures
import geoip2.database
from dns import resolver

print("--- GITHUB COLLECTOR v39.2 (SNI→Address for refiner) START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 44444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')

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

# --- HELPER FUNCTIONS ---

def country_code_to_flag(iso_code):
    return COUNTRY_FLAGS.get(iso_code, "🌐")

def resolve_domain_to_ip(hostname):
    """Resolves domain to IP with caching. Returns IP or None."""
    if not hostname:
        return None
    
    # Check if already an IP
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    
    # Check cache
    if hostname in dns_cache:
        return dns_cache[hostname]
    
    # Resolve
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
    """Parses VMess config with multi-encoding support. Returns dict or None."""
    try:
        encoded = config_str.replace('vmess://', '').strip()
        encoded = encoded.rstrip('.,;!?')
        
        # Add padding
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        # Decode base64
        decoded_bytes = base64.b64decode(encoded, validate=True)
        
        # Try multiple encodings
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']:
            try:
                decoded = decoded_bytes.decode(encoding, errors='ignore')
                parsed = json.loads(decoded)
                
                # Validate required fields
                if 'add' in parsed and 'port' in parsed and 'id' in parsed:
                    return parsed
                    
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        
        return None
        
    except Exception:
        return None

def get_config_fingerprint(config_str):
    """Creates unique fingerprint for deduplication."""
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return None
            addr = vmess_data.get('add', '')
            port = vmess_data.get('port', '')
            uuid = vmess_data.get('id', '')
            return f"vmess|{addr}|{port}|{uuid}"
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            protocol = parsed.scheme
            uuid = parsed.username or ''
            host = parsed.hostname or ''
            
            # Handle port parsing errors
            try:
                port = parsed.port or ''
            except (ValueError, AttributeError, TypeError):
                port = ''
            
            return f"{protocol}|{host}|{port}|{uuid}"
        
        elif config_str.startswith('ss://'):
            parts = config_str.split('@')
            if len(parts) == 2:
                server_part = parts[1].split('#')[0]
                method_pass = parts[0].replace('ss://', '')
                return f"ss|{server_part}|{method_pass}"
        
        # For other protocols
        else:
            parsed = urlparse(config_str)
            try:
                port = parsed.port or ''
            except (ValueError, AttributeError, TypeError):
                port = ''
            return f"{parsed.scheme}|{parsed.hostname}|{port}|{parsed.username}"
        
        return None
    except Exception:
        return None

# --- NEW: Replace Address with SNI (for filtered-for-refiner.txt) ---

def replace_address_with_sni(config_str):
    """
    Replaces the address with SNI/host parameter.
    Opposite of domain→IP conversion. For filtered-for-refiner.txt only.
    """
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return config_str
            
            # Check if has SNI
            sni = vmess_data.get('sni', '').strip()
            host = vmess_data.get('host', '').strip()
            current_addr = vmess_data.get('add', '')
            
            # Use SNI or host as new address
            new_addr = sni or host
            
            if new_addr and new_addr != current_addr:
                vmess_data['add'] = new_addr
                # Keep SNI/host parameters intact
                
                # Re-encode
                new_json = json.dumps(vmess_data, separators=(',', ':'))
                new_encoded = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{new_encoded}"
            
            return config_str
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            
            # Get SNI or host
            sni = params.get('sni', [''])[0].strip()
            host = params.get('host', [''])[0].strip()
            current_addr = parsed.hostname
            
            # Use SNI or host as new address
            new_addr = sni or host
            
            if new_addr and new_addr != current_addr:
                # Rebuild netloc with SNI/host as address
                new_netloc = new_addr
                
                try:
                    if parsed.port:
                        new_netloc = f"{new_addr}:{parsed.port}"
                except (ValueError, AttributeError, TypeError):
                    pass
                
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                
                # Keep query intact (SNI/host params stay)
                new_parsed = parsed._replace(netloc=new_netloc)
                return new_parsed.geturl()
            
            return config_str
        
        # For other protocols, return as-is
        else:
            return config_str
        
    except Exception:
        return config_str

# --- Domain→IP Conversion (for categorized outputs) ---

def replace_domain_with_ip(config_str):
    """Replaces domain with IP while preserving SNI/host."""
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return config_str
            
            domain = vmess_data.get('add', '')
            ip_addr = resolve_domain_to_ip(domain)
            
            if ip_addr and ip_addr != domain:
                # Preserve SNI
                if vmess_data.get('tls') == 'tls' and not vmess_data.get('sni'):
                    vmess_data['sni'] = domain
                
                vmess_data['add'] = ip_addr
                
                # Re-encode
                new_json = json.dumps(vmess_data, separators=(',', ':'))
                new_encoded = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{new_encoded}"
            
            return config_str
        
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            domain = parsed.hostname
            
            if not domain:
                return config_str
            
            ip_addr = resolve_domain_to_ip(domain)
            
            if ip_addr and ip_addr != domain:
                params = parse_qs(parsed.query)
                
                # Preserve SNI
                security = params.get('security', [''])[0]
                if security in ['tls', 'reality'] and 'sni' not in params:
                    params['sni'] = [domain]
                
                # Preserve host
                network_type = params.get('type', [''])[0]
                if network_type in ['http', 'ws'] and 'host' not in params:
                    params['host'] = [domain]
                
                # Rebuild
                new_query = urlencode(params, doseq=True)
                new_netloc = ip_addr
                
                try:
                    if parsed.port:
                        new_netloc = f"{ip_addr}:{parsed.port}"
                except (ValueError, AttributeError, TypeError):
                    pass
                
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                
                new_parsed = parsed._replace(netloc=new_netloc, query=new_query)
                return new_parsed.geturl()
            
            return config_str
        
        elif config_str.startswith('ss://'):
            parts = config_str.split('@')
            if len(parts) != 2:
                return config_str
            
            prefix = parts[0]
            suffix = parts[1]
            
            fragment = ''
            if '#' in suffix:
                suffix, fragment = suffix.split('#', 1)
                fragment = f'#{fragment}'
            
            if ':' in suffix:
                domain, port = suffix.rsplit(':', 1)
            else:
                domain, port = suffix, '443'
            
            ip_addr = resolve_domain_to_ip(domain)
            
            if ip_addr and ip_addr != domain:
                return f"{prefix}@{ip_addr}:{port}{fragment}"
            
            return config_str
        
        # For other protocols
        else:
            parsed = urlparse(config_str)
            domain = parsed.hostname
            
            if not domain:
                return config_str
            
            ip_addr = resolve_domain_to_ip(domain)
            
            if ip_addr and ip_addr != domain:
                new_netloc = ip_addr
                
                try:
                    if parsed.port:
                        new_netloc = f"{ip_addr}:{parsed.port}"
                except (ValueError, AttributeError, TypeError):
                    pass
                
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                
                new_parsed = parsed._replace(netloc=new_netloc)
                return new_parsed.geturl()
            
            return config_str
        
    except Exception:
        return config_str

def get_country_from_hostname(hostname):
    """Get country code from hostname/IP."""
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
    """Extracts and validates protocol, network, security, country."""
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
            
            # Reality detection
            if security != 'reality' and 'pbk' in params:
                security = 'reality'
            
            country = get_country_from_hostname(hostname).upper()
        
        # Validation
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
        
        return {
            'protocol': protocol,
            'network': network,
            'security': security,
            'country': country
        }
    
    except Exception:
        return None

def rename_config(config_str, country_code):
    """Adds country flag to config name."""
    try:
        flag = country_code_to_flag(country_code)
        
        # Extract existing name if present
        if '#' in config_str:
            base, existing_name = config_str.rsplit('#', 1)
            # Avoid adding flag if already present
            if flag in existing_name:
                return config_str
            new_name = f"{flag} {existing_name}"
        else:
            new_name = f"{flag} {country_code}"
        
        return f"{config_str.split('#')[0]}#{quote(new_name)}"
    except Exception:
        return config_str

# --- ORIGINAL HELPER FUNCTIONS ---

def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './protocols', './networks', './countries', './security']
    for d in dirs:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    print("INFO: All necessary directories are clean.")

def json_load_safe(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def find_configs_raw(text):
    if not text:
        return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

def check_host_port_with_socket(host_port):
    """Tests if host:port is reachable."""
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except Exception:
        return None

def write_chunked_subscription_files(base_filepath, configs):
    """Writes configs to base64-encoded files."""
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

# --- GITHUB FETCHING ---

def fetch_from_github():
    print("\n--- Fetching configs from GitHub ---")
    if not COLLECTOR_TOKEN:
        print("WARNING: COLLECTOR_TOKEN not found. Skipping GitHub scrape.")
        return set()
    
    configs = set()
    headers = {
        'Authorization': f'token {COLLECTOR_TOKEN}',
        'Accept': 'application/vnd.github.v3.raw'
    }
    
    queries = [
        '"vless" "کانفیگ" "رایگان"', '"vmess" "ایرانسل"', '"trojan" "همراه اول"',
        '"v2ray" "رایتل"', 'filename:subscribe "v2ray" "ایران"', 
        'path:config "vless" "رایگان"', '"ss://"', '"reality" "کانفیگ"', 
        'filename:all.txt "vmess://"', 'path:nodes "vless://"'
    ]
    
    for query in queries:
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6)
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            items = res.json().get('items', [])
            print(f"Found {len(items)} files for query: '{query[:30]}...'")
            
            for item in items:
                time.sleep(0.5)
                raw_url = item.get('url')
                try:
                    content_res = requests.get(raw_url, headers=headers, timeout=10)
                    if content_res.status_code == 200:
                        content = content_res.text
                        
                        # Decode if base64
                        if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                            try:
                                content = base64.b64decode(content).decode('utf-8', 'ignore')
                            except Exception:
                                pass
                        
                        found = find_configs_raw(content)
                        if found:
                            configs.update(found)
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"ERROR: GitHub query failed: {e}")
            if 'rate limit' in str(e).lower():
                print("Rate limit hit. Sleeping 60s...")
                time.sleep(60)
            continue

    print(f"Collected {len(configs)} configs from GitHub.")
    return configs

# --- PRE-FILTERING ---

def pre_filter_live_hosts(all_configs):
    """Pre-filters configs by testing unique host:port pairs."""
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live hosts ---")
    
    # Deduplication
    fingerprint_to_config = {}
    
    for config in all_configs:
        fp = get_config_fingerprint(config)
        if fp and fp not in fingerprint_to_config:
            fingerprint_to_config[fp] = config
    
    print(f"After deduplication: {len(fingerprint_to_config)} unique configs")
    
    # Build host:port mapping
    host_port_to_fingerprint = {}
    parse_errors = 0
    
    for fp, config in fingerprint_to_config.items():
        try:
            # Get hostname and port
            if config.startswith('vmess://'):
                vmess_data = parse_vmess_config(config)
                if not vmess_data:
                    continue
                host = vmess_data.get('add')
                port = vmess_data.get('port')
            else:
                parsed = urlparse(config)
                host = parsed.hostname
                
                try:
                    port = parsed.port
                except (ValueError, AttributeError, TypeError):
                    parse_errors += 1
                    continue
            
            if not host or not port:
                continue
            
            # Validate port
            try:
                port = int(port)
            except (ValueError, TypeError):
                parse_errors += 1
                continue
            
            if port < 1 or port > 65535:
                parse_errors += 1
                continue
            
            # Resolve to IP
            ip_addr = resolve_domain_to_ip(host)
            if not ip_addr:
                continue
            
            host_port_key = f"{ip_addr}:{port}"
            if host_port_key not in host_port_to_fingerprint:
                host_port_to_fingerprint[host_port_key] = fp
                
        except Exception:
            parse_errors += 1
            continue
    
    if parse_errors > 0:
        print(f"Skipped {parse_errors} configs with parsing errors")
    
    print(f"Testing {len(host_port_to_fingerprint)} unique host:port pairs...")
    
    # Test connectivity
    live_host_ports = set()
    hosts_to_test = list(host_port_to_fingerprint.keys())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {
            executor.submit(check_host_port_with_socket, hp): hp 
            for hp in hosts_to_test
        }
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0:
                print(f"Tested {i+1}/{len(hosts_to_test)} hosts...")
            
            result = future.result()
            if result:
                live_host_ports.add(result)
    
    # Map back to configs
    live_fingerprints = {
        host_port_to_fingerprint[hp] 
        for hp in live_host_ports 
        if hp in host_port_to_fingerprint
    }
    
    live_configs = [
        fingerprint_to_config[fp] 
        for fp in live_fingerprints 
        if fp in fingerprint_to_config
    ]
    
    print(f"Pre-filter complete: {len(live_configs)} live configs")
    return live_configs

# --- CONFIG PROCESSING ---

def process_and_convert_configs(configs):
    """Processes configs: Domain→IP + GeoIP + Renaming."""
    print(f"\n--- Processing {len(configs)} configs for categorized outputs ---")
    
    processed = []
    stats = {
        'converted': 0,
        'failed_attrs': 0
    }
    
    for config in configs:
        # Convert domain to IP
        ip_config = replace_domain_with_ip(config)
        if ip_config != config:
            stats['converted'] += 1
        
        # Get attributes
        attrs = get_config_attributes(ip_config)
        if not attrs:
            stats['failed_attrs'] += 1
            continue
        
        # Rename with country flag
        final_config = rename_config(ip_config, attrs['country'])
        processed.append({
            'config': final_config,
            'attrs': attrs
        })
    
    print(f"Converted {stats['converted']} configs to IP")
    print(f"Failed to parse {stats['failed_attrs']} configs")
    
    return processed

# --- MAIN EXECUTION ---

def main():
    global geoip_reader
    
    setup_directories()
    
    # Download GeoIP
    db_path = "./geoip.mmdb"
    if not os.path.exists(db_path):
        print("Downloading GeoIP database...")
        urls = [
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
            "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
            "https://git.io/GeoLite2-Country.mmdb"
        ]
        
        for url in urls:
            try:
                r = requests.get(url, allow_redirects=True, timeout=30)
                if r.status_code == 200 and len(r.content) > 1000:
                    with open(db_path, 'wb') as f:
                        f.write(r.content)
                    print(f"✓ GeoIP downloaded ({len(r.content)} bytes)")
                    break
            except Exception:
                continue
    
    try:
        geoip_reader = geoip2.database.Reader(db_path)
    except Exception as e:
        print(f"Warning: Could not load GeoIP: {e}")
    
    # Collect configs
    all_raw_configs = set()
    
    print("\n--- Collecting from subscription links.json ---")
    subs_links = json_load_safe('subscription links.json')
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            
            # Decode if base64
            if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                try:
                    content = base64.b64decode(content).decode('utf-8', 'ignore')
                except Exception:
                    pass
            
            all_raw_configs.update(find_configs_raw(content))
        except Exception:
            continue
    
    print(f"Collected {len(all_raw_configs)} configs from subscriptions")
    
    # Fetch from GitHub
    all_raw_configs.update(fetch_from_github())
    
    print(f"\n{'='*60}")
    print(f"  COLLECTION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total raw configs collected: {len(all_raw_configs)}")
    print(f"{'='*60}\n")
    
    if not all_raw_configs:
        print("No configs collected. Exiting.")
        return
    
    # Pre-filter for live hosts
    live_configs = pre_filter_live_hosts(list(all_raw_configs))
    
    if not live_configs:
        print("No live configs found. Exiting.")
        return
    
    # --- NEW: Convert to SNI-as-address for filtered-for-refiner.txt ---
    print("\n--- Converting configs to SNI-as-address for refiner ---")
    sni_configs = []
    conversion_count = 0
    
    for config in live_configs:
        sni_config = replace_address_with_sni(config)
        if sni_config != config:
            conversion_count += 1
        sni_configs.append(sni_config)
    
    print(f"Converted {conversion_count} configs to use SNI/host as address")
    
    # Save SNI-based configs to filtered-for-refiner.txt
    with open('filtered-for-refiner.txt', 'w', encoding='utf-8') as f:
        for config in sni_configs:
            f.write(config + '\n')
    print(f"✓ Saved {len(sni_configs)} SNI-based configs to filtered-for-refiner.txt")
    
    # Find REALITY+gRPC configs
    print("\n--- Searching for REALITY+gRPC configs ---")
    reality_grpc_configs = []
    
    for config in live_configs:
        attrs = get_config_attributes(config)
        if attrs and attrs['security'] == 'reality' and attrs['network'] == 'grpc':
            reality_grpc_configs.append(config)
    
    if reality_grpc_configs:
        with open('reality-grpc-configs.txt', 'w', encoding='utf-8') as f:
            for cfg in reality_grpc_configs:
                f.write(cfg + '\n')
        print(f"Found {len(reality_grpc_configs)} REALITY+gRPC configs")
    else:
        print("No REALITY+gRPC configs found")
    
    # Process with IP conversion for categorized outputs
    processed_configs = process_and_convert_configs(live_configs)
    
    # Categorize
    print("\n--- Categorizing configs ---")
    
    by_protocol = {}
    by_network = {}
    by_security = {}
    by_country = {}
    
    for item in processed_configs:
        config = item['config']
        attrs = item['attrs']
        
        # By protocol
        proto = attrs['protocol']
        if proto not in by_protocol:
            by_protocol[proto] = []
        by_protocol[proto].append(config)
        
        # By network
        net = attrs['network']
        if net not in by_network:
            by_network[net] = []
        by_network[net].append(config)
        
        # By security
        sec = attrs['security']
        if sec not in by_security:
            by_security[sec] = []
        by_security[sec].append(config)
        
        # By country
        country = attrs['country'].lower()
        if country not in by_country:
            by_country[country] = []
        by_country[country].append(config)
    
    # Write files
    print("\n--- Writing subscription files ---")
    
    for proto, configs in by_protocol.items():
        write_chunked_subscription_files(f'./protocols/{proto}', configs)
    
    for net, configs in by_network.items():
        write_chunked_subscription_files(f'./networks/{net}', configs)
    
    for sec, configs in by_security.items():
        write_chunked_subscription_files(f'./security/{sec}', configs)
    
    for country, configs in by_country.items():
        write_chunked_subscription_files(f'./countries/{country}', configs)
    
    # Write mixed file
    all_final_configs = [item['config'] for item in processed_configs]
    write_chunked_subscription_files('./splitted/mixed', all_final_configs)
    
    # Final summary
    print(f"\n{'='*60}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*60}")
    print(f"  Raw configs collected           : {len(all_raw_configs)}")
    print(f"  Live configs (filtered)         : {len(live_configs)}")
    print(f"  SNI-based (for refiner)         : {len(sni_configs)}")
    print(f"  IP-based (categorized)          : {len(processed_configs)}")
    print(f"  REALITY+gRPC configs            : {len(reality_grpc_configs)}")
    print(f"  DNS cache entries               : {len(dns_cache)}")
    print(f"  Protocols                       : {len(by_protocol)}")
    print(f"  Networks                        : {len(by_network)}")
    print(f"  Security types                  : {len(by_security)}")
    print(f"  Countries                       : {len(by_country)}")
    print(f"{'='*60}")
    print("\n--- COLLECTOR FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(f"\n--- FATAL ERROR ---")
        traceback.print_exc()
        exit(1)
