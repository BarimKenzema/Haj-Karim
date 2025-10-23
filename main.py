# FILE: main.py (for your GitHub scraper repo: v2ray-collector)
# VERSION 40.0: Massively Expanded Search - All 3 Phases

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse, parse_qs, quote, urlencode, urlunparse
import concurrent.futures
import geoip2.database
from dns import resolver

print("--- GITHUB COLLECTOR v40.0 (MASSIVELY EXPANDED SEARCH) START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 44444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')
SUCCESS_CACHE_FILE = 'successful_sources.json'

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

# --- HELPER FUNCTIONS (Same as before) ---

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
            except (UnicodeDecodeError, json.JSONDecodeError):
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
            addr = vmess_data.get('add', '')
            port = vmess_data.get('port', '')
            uuid = vmess_data.get('id', '')
            return f"vmess|{addr}|{port}|{uuid}"
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            protocol = parsed.scheme
            uuid = parsed.username or ''
            host = parsed.hostname or ''
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

def replace_address_with_sni(config_str):
    try:
        if config_str.startswith('vmess://'):
            vmess_data = parse_vmess_config(config_str)
            if not vmess_data:
                return config_str
            sni = vmess_data.get('sni', '').strip()
            host = vmess_data.get('host', '').strip()
            current_addr = vmess_data.get('add', '')
            new_addr = sni or host
            if new_addr and new_addr != current_addr:
                vmess_data['add'] = new_addr
                new_json = json.dumps(vmess_data, separators=(',', ':'))
                new_encoded = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{new_encoded}"
            return config_str
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            sni = params.get('sni', [''])[0].strip()
            host = params.get('host', [''])[0].strip()
            current_addr = parsed.hostname
            new_addr = sni or host
            if new_addr and new_addr != current_addr:
                new_netloc = new_addr
                try:
                    if parsed.port:
                        new_netloc = f"{new_addr}:{parsed.port}"
                except (ValueError, AttributeError, TypeError):
                    pass
                if parsed.username:
                    new_netloc = f"{parsed.username}@{new_netloc}"
                new_parsed = parsed._replace(netloc=new_netloc)
                return new_parsed.geturl()
            return config_str
        else:
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
        return {
            'protocol': protocol,
            'network': network,
            'security': security,
            'country': country
        }
    except Exception:
        return None

def rename_config(config_str, country_code):
    try:
        flag = country_code_to_flag(country_code)
        new_name = f"{flag} @MoboNetPC {flag}"
        return f"{config_str.split('#')[0]}#{quote(new_name)}"
    except Exception:
        return config_str

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
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except Exception:
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

# --- PHASE 3: SUCCESS TRACKING ---

def load_success_cache():
    """Load successful sources cache."""
    try:
        with open(SUCCESS_CACHE_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_success_cache(cache):
    """Save successful sources cache."""
    try:
        with open(SUCCESS_CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except:
        pass

def update_source_success(cache, source, config_count):
    """Track which sources yield configs."""
    if source not in cache:
        cache[source] = {'total_configs': 0, 'last_success': None, 'attempts': 0}
    cache[source]['total_configs'] += config_count
    cache[source]['attempts'] += 1
    if config_count > 0:
        cache[source]['last_success'] = time.time()

# --- PHASE 1: EXPANDED CODE SEARCH ---

def fetch_from_github_code():
    print("\n--- [PHASE 1] Fetching from GitHub Code Search (EXPANDED) ---")
    if not COLLECTOR_TOKEN:
        print("WARNING: COLLECTOR_TOKEN not found.")
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'}
    
    # MASSIVELY EXPANDED QUERIES
    queries = [
        # Persian
        '"vless" "کانفیگ" "رایگان"', '"vmess" "ایرانسل"', '"trojan" "همراه اول"',
        '"v2ray" "رایتل"', 'filename:subscribe "v2ray" "ایران"', 
        'path:config "vless" "رایگان"', '"ss://"', '"reality" "کانفیگ"', 
        'filename:all.txt "vmess://"', 'path:nodes "vless://"',
        
        # English
        '"vmess://" "subscription"', '"vless://" "subscription"',
        '"trojan://" "free"', '"reality" "proxy"',
        'filename:subscription.txt "vless"', 'filename:sub.txt "vmess"',
        'path:subscribe "vmess://"', 'path:subscription "vless://"',
        '"v2ray" "free" "nodes"', '"proxy" "subscription" "auto"',
        
        # Chinese
        '"vmess" "免费"', '"v2ray" "订阅"', '"节点" "分享"',
        '"翻墙" "配置"', '"代理" "免费"', '"vless" "免费节点"',
        
        # Russian
        '"vmess" "бесплатно"', '"v2ray" "подписка"', '"прокси" "бесплатно"',
        
        # Protocol-specific
        '"hy2://" OR "hysteria2://"', '"tuic://"', '"juicity://"',
        '"reality" "grpc"', '"vless" "xtls"', '"trojan" "reality"',
        
        # File patterns
        'filename:config.txt "vmess"', 'filename:nodes.txt "vless"',
        'filename:proxies.txt', 'path:sub extension:txt',
        
        # YAML configs
        '"clash" "proxies" extension:yaml', '"xray" extension:json',
        
        # Aggregators
        '"v2ray collector"', '"proxy collector"', '"subscription aggregator"',
        
        # Recent
        '"vmess://" pushed:>2024-01-01', '"vless://" pushed:>2024-01-01',
    ]
    
    success_cache = load_success_cache()
    
    for query in queries:
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6)
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            items = res.json().get('items', [])
            print(f"Found {len(items)} files for: '{query[:40]}...'")
            
            for item in items:
                time.sleep(0.5)
                raw_url = item.get('url')
                try:
                    content_res = requests.get(raw_url, headers=headers, timeout=10)
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
                            update_source_success(success_cache, item.get('repository', {}).get('full_name', 'unknown'), len(found))
                except:
                    continue
        except Exception as e:
            print(f"ERROR: {e}")
            if 'rate limit' in str(e).lower():
                print("Rate limit hit. Sleeping 60s...")
                time.sleep(60)
            continue
    
    save_success_cache(success_cache)
    print(f"Collected {len(configs)} configs from code search")
    return configs

# --- PHASE 1: REPOSITORY SEARCH ---

def fetch_from_github_repos():
    print("\n--- [PHASE 1] Searching GitHub Repositories ---")
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    
    repo_queries = [
        'v2ray subscription', 'proxy subscription', 'free proxy',
        'vmess nodes', 'v2ray collector', 'clash subscription',
        'v2ray 节点', 'free vpn configs', 'xray subscription',
        'shadowsocks subscription', 'trojan subscription'
    ]
    
    for query in repo_queries:
        try:
            time.sleep(6)
            search_url = f"https://api.github.com/search/repositories?q={query}&sort=updated&per_page=30"
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            repos = res.json().get('items', [])
            print(f"Found {len(repos)} repos for: {query}")
            
            for repo in repos:
                common_paths = [
                    'subscription.txt', 'sub.txt', 'nodes.txt', 'all.txt',
                    'README.md', 'config.txt', 'proxies.txt', 'v2ray.txt',
                    'clash.yaml', 'base64.txt', 'subscribe/all.txt', 'Sub.txt'
                ]
                
                for path in common_paths:
                    try:
                        time.sleep(0.3)
                        file_url = f"https://api.github.com/repos/{repo['full_name']}/contents/{path}"
                        file_res = requests.get(file_url, headers=headers, timeout=10)
                        
                        if file_res.status_code == 200:
                            content = file_res.json().get('content', '')
                            try:
                                decoded = base64.b64decode(content).decode('utf-8', 'ignore')
                                found = find_configs_raw(decoded)
                                if found:
                                    configs.update(found)
                                    print(f"  ✓ {repo['name']}/{path}: {len(found)} configs")
                            except:
                                pass
                    except:
                        continue
        except Exception as e:
            print(f"Repo search error: {e}")
            continue
    
    print(f"Collected {len(configs)} configs from repository search")
    return configs

# --- PHASE 1: KNOWN PATTERNS ---

def fetch_from_known_patterns():
    print("\n--- [PHASE 1] Fetching from Known User Patterns ---")
    
    configs = set()
    
    known_users = [
        'mahdibland', 'yebekhe', 'MrPooyaX', 'barry-far', 'coldwater-10',
        'sashalsk', 'aiboboxx', 'Bardiafa', 'freefq', 'Pawdroid',
        'mfuu', 'Leon406', 'tbbatbb', 'peasoft', 'AzadNetCH',
        'soroushmirzaei', 'MhdiTaheri', 'itsyebekhe', 'Surfboardv2ray'
    ]
    
    common_paths = [
        'Sub.txt', 'subscription.txt', 'all.txt', 'v2ray.txt',
        'clash.yaml', 'nodes.txt', 'base64.txt', 'config.txt'
    ]
    
    branches = ['main', 'master']
    
    for user in known_users:
        for branch in branches:
            for path in common_paths:
                try:
                    url = f"https://raw.githubusercontent.com/{user}/v2ray/{branch}/{path}"
                    content = requests.get(url, timeout=10).text
                    found = find_configs_raw(content)
                    if found:
                        configs.update(found)
                        print(f"  ✓ {user}/{branch}/{path}: {len(found)} configs")
                    time.sleep(0.2)
                except:
                    pass
    
    print(f"Collected {len(configs)} configs from known patterns")
    return configs

# --- PHASE 2: README PARSING ---

def fetch_subscription_links_from_readmes():
    print("\n--- [PHASE 2] Extracting Subscription Links from READMEs ---")
    if not COLLECTOR_TOKEN:
        return set()
    
    new_subscription_links = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    
    search_query = 'filename:README.md "subscription" "http"'
    
    try:
        time.sleep(6)
        search_url = f"https://api.github.com/search/code?q={search_query}&per_page=100"
        res = requests.get(search_url, headers=headers, timeout=30)
        res.raise_for_status()
        items = res.json().get('items', [])
        print(f"Found {len(items)} READMEs")
        
        url_pattern = r'https?://[^\s<>"\'`\)]+(?:sub|subscription|v2ray|clash|base64|config)[^\s<>"\'`\)]*'
        
        for item in items:
            try:
                time.sleep(0.5)
                raw_url = item.get('url')
                content_res = requests.get(raw_url, headers=headers, timeout=10)
                if content_res.status_code == 200:
                    content = content_res.text
                    try:
                        decoded = base64.b64decode(content).decode('utf-8', 'ignore')
                        urls = re.findall(url_pattern, decoded)
                        new_subscription_links.update(urls)
                    except:
                        urls = re.findall(url_pattern, content)
                        new_subscription_links.update(urls)
            except:
                continue
    except Exception as e:
        print(f"README parsing error: {e}")
    
    print(f"Extracted {len(new_subscription_links)} potential subscription links")
    return new_subscription_links

# --- PHASE 2: FORK CHECKING ---

def fetch_from_popular_forks():
    print("\n--- [PHASE 2] Checking Forks of Popular Repos ---")
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    
    popular_repos = [
        'mahdibland/ShadowsocksAggregator',
        'yebekhe/TelegramV2rayCollector',
        'barry-far/V2ray-Configs',
        'peasoft/NoMoreWalls'
    ]
    
    for repo in popular_repos:
        try:
            time.sleep(6)
            forks_url = f"https://api.github.com/repos/{repo}/forks?sort=newest&per_page=20"
            res = requests.get(forks_url, headers=headers, timeout=30)
            res.raise_for_status()
            forks = res.json()
            print(f"Checking {len(forks)} forks of {repo}")
            
            for fork in forks:
                common_paths = ['Sub.txt', 'all.txt', 'subscription.txt', 'config.txt']
                for path in common_paths:
                    try:
                        time.sleep(0.3)
                        file_url = f"https://api.github.com/repos/{fork['full_name']}/contents/{path}"
                        file_res = requests.get(file_url, headers=headers, timeout=10)
                        if file_res.status_code == 200:
                            content = file_res.json().get('content', '')
                            decoded = base64.b64decode(content).decode('utf-8', 'ignore')
                            found = find_configs_raw(decoded)
                            if found:
                                configs.update(found)
                                print(f"  ✓ Fork {fork['name']}/{path}: {len(found)} configs")
                    except:
                        continue
        except Exception as e:
            print(f"Fork checking error for {repo}: {e}")
            continue
    
    print(f"Collected {len(configs)} configs from forks")
    return configs

# --- PHASE 2: TOPIC SEARCH ---

def fetch_from_topics():
    print("\n--- [PHASE 2] Searching by GitHub Topics ---")
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    
    topic_combos = [
        'topic:v2ray topic:subscription',
        'topic:xray topic:nodes',
        'topic:proxy topic:free',
        'topic:clash topic:subscription',
        'topic:shadowsocks topic:free'
    ]
    
    for topic_query in topic_combos:
        try:
            time.sleep(6)
            search_url = f"https://api.github.com/search/repositories?q={topic_query}&sort=updated&per_page=20"
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            repos = res.json().get('items', [])
            print(f"Found {len(repos)} repos for: {topic_query}")
            
            for repo in repos:
                for path in ['Sub.txt', 'all.txt', 'subscription.txt']:
                    try:
                        time.sleep(0.3)
                        file_url = f"https://api.github.com/repos/{repo['full_name']}/contents/{path}"
                        file_res = requests.get(file_url, headers=headers, timeout=10)
                        if file_res.status_code == 200:
                            content = file_res.json().get('content', '')
                            decoded = base64.b64decode(content).decode('utf-8', 'ignore')
                            found = find_configs_raw(decoded)
                            if found:
                                configs.update(found)
                    except:
                        continue
        except Exception as e:
            print(f"Topic search error: {e}")
            continue
    
    print(f"Collected {len(configs)} configs from topic search")
    return configs

# --- PHASE 3: GRAPHQL API ---

def fetch_with_graphql():
    print("\n--- [PHASE 3] Using GitHub GraphQL API ---")
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'bearer {COLLECTOR_TOKEN}'}
    graphql_url = 'https://api.github.com/graphql'
    
    queries_gql = [
        'vmess OR vless in:file',
        'trojan OR reality in:file',
        'subscription filename:sub.txt'
    ]
    
    for search_term in queries_gql:
        query = f'''
        {{
          search(query: "{search_term}", type: CODE, first: 100) {{
            edges {{
              node {{
                ... on Blob {{
                  text
                }}
              }}
            }}
          }}
        }}
        '''
        
        try:
            time.sleep(6)
            res = requests.post(graphql_url, headers=headers, json={'query': query}, timeout=30)
            res.raise_for_status()
            data = res.json()
            
            if 'data' in data and 'search' in data['data']:
                edges = data['data']['search'].get('edges', [])
                print(f"GraphQL found {len(edges)} results for: {search_term}")
                
                for edge in edges:
                    try:
                        text = edge.get('node', {}).get('text', '')
                        if text:
                            found = find_configs_raw(text)
                            if found:
                                configs.update(found)
                    except:
                        continue
        except Exception as e:
            print(f"GraphQL error: {e}")
            continue
    
    print(f"Collected {len(configs)} configs from GraphQL")
    return configs

# --- PRE-FILTERING (Same as before) ---

def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live hosts ---")
    fingerprint_to_config = {}
    for config in all_configs:
        fp = get_config_fingerprint(config)
        if fp and fp not in fingerprint_to_config:
            fingerprint_to_config[fp] = config
    print(f"After deduplication: {len(fingerprint_to_config)} unique configs")
    
    host_port_to_fingerprint = {}
    parse_errors = 0
    
    for fp, config in fingerprint_to_config.items():
        try:
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
            
            try:
                port = int(port)
            except (ValueError, TypeError):
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
        print(f"Skipped {parse_errors} configs with parsing errors")
    
    print(f"Testing {len(host_port_to_fingerprint)} unique host:port pairs...")
    
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
            except:
                continue
    
    try:
        geoip_reader = geoip2.database.Reader(db_path)
    except Exception as e:
        print(f"Warning: Could not load GeoIP: {e}")
    
    # Collect configs from ALL sources
    all_raw_configs = set()
    
    print("\n--- Collecting from subscription links.json ---")
    subs_links = json_load_safe('subscription links.json')
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                try:
                    content = base64.b64decode(content).decode('utf-8', 'ignore')
                except:
                    pass
            all_raw_configs.update(find_configs_raw(content))
        except:
            continue
    print(f"Collected {len(all_raw_configs)} configs from local subscriptions")
    
    # PHASE 1
    all_raw_configs.update(fetch_from_github_code())
    all_raw_configs.update(fetch_from_github_repos())
    all_raw_configs.update(fetch_from_known_patterns())
    
    # PHASE 2
    all_raw_configs.update(fetch_from_popular_forks())
    all_raw_configs.update(fetch_from_topics())
    
    # Extract new subscription links from READMEs
    new_links = fetch_subscription_links_from_readmes()
    print(f"\n--- Testing {len(new_links)} newly discovered subscription links ---")
    for link in list(new_links)[:50]:  # Test first 50
        try:
            content = requests.get(link, timeout=10).text
            found = find_configs_raw(content)
            if found:
                all_raw_configs.update(found)
                print(f"  ✓ {link[:60]}: {len(found)} configs")
        except:
            continue
    
    # PHASE 3
    all_raw_configs.update(fetch_with_graphql())
    
    print(f"\n{'='*70}")
    print(f"  COLLECTION SUMMARY (ALL PHASES)")
    print(f"{'='*70}")
    print(f"  Total raw configs collected: {len(all_raw_configs)}")
    print(f"{'='*70}\n")
    
    if not all_raw_configs:
        print("No configs collected. Exiting.")
        return
    
    # Pre-filter
    live_configs = pre_filter_live_hosts(list(all_raw_configs))
    
    if not live_configs:
        print("No live configs found. Exiting.")
        return
    
    # Convert for refiner
    print("\n--- Converting configs for filtered-for-refiner.txt ---")
    sni_configs = []
    conversion_count = 0
    rename_count = 0
    
    for config in live_configs:
        sni_config = replace_address_with_sni(config)
        if sni_config != config:
            conversion_count += 1
        attrs = get_config_attributes(sni_config)
        if attrs:
            renamed_config = rename_config(sni_config, attrs['country'])
            sni_configs.append(renamed_config)
            rename_count += 1
        else:
            sni_configs.append(sni_config)
    
    print(f"Converted {conversion_count} to SNI, renamed {rename_count}")
    
    with open('filtered-for-refiner.txt', 'w', encoding='utf-8') as f:
        for config in sni_configs:
            f.write(config + '\n')
    print(f"✓ Saved {len(sni_configs)} configs to filtered-for-refiner.txt")
    
    # REALITY+gRPC
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
    
    # Process for categorization
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
        
        proto = attrs['protocol']
        if proto not in by_protocol:
            by_protocol[proto] = []
        by_protocol[proto].append(config)
        
        net = attrs['network']
        if net not in by_network:
            by_network[net] = []
        by_network[net].append(config)
        
        sec = attrs['security']
        if sec not in by_security:
            by_security[sec] = []
        by_security[sec].append(config)
        
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
    
    all_final_configs = [item['config'] for item in processed_configs]
    write_chunked_subscription_files('./splitted/mixed', all_final_configs)
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*70}")
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
    print(f"{'='*70}")
    print(f"\n✓ All 3 phases complete - Massively expanded search!")
    print("--- COLLECTOR FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(f"\n--- FATAL ERROR ---")
        traceback.print_exc()
        exit(1)
