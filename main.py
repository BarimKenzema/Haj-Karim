# FILE: main.py (for your GitHub scraper repo: v2ray-collector)
# VERSION 41.0: Lean & Powerful - Only What Works, Massively Strengthened

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse, parse_qs, quote, urlencode, urlunparse
import concurrent.futures
import geoip2.database
from dns import resolver

print("--- GITHUB COLLECTOR v41.0 (LEAN & POWERFUL) START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 44444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')
VALIDATED_LINKS_FILE = 'validated_subscriptions.json'

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

# --- HELPER FUNCTIONS (Same as before, keeping them compact) ---

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
                return f"vmess://{base64.b64encode(new_json.encode('utf-8')).decode('utf-8')}"
            return config_str
        elif config_str.startswith(('vless://', 'trojan://')):
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            sni = params.get('sni', [''])[0].strip()
            host = params.get('host', [''])[0].strip()
            new_addr = sni or host
            if new_addr and new_addr != parsed.hostname:
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
    except:
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

# --- TIER 1: DIRECT AGGREGATORS (GUARANTEED HIGH YIELD) ---

def fetch_from_direct_aggregators():
    """Fetch from proven, high-yield aggregator URLs."""
    print("\n--- [TIER 1] Fetching from Direct Aggregators ---")
    
    configs = set()
    
    # These are VERIFIED working aggregators (update monthly)
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
                
                # Decode if base64
                if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                    try:
                        content = base64.b64decode(content).decode('utf-8', 'ignore')
                    except:
                        pass
                
                found = find_configs_raw(content)
                if found:
                    configs.update(found)
                    repo_name = url.split('/')[-3]
                    print(f"  ✓ {repo_name}: {len(found)} configs")
            
            time.sleep(0.5)
        except Exception:
            continue
    
    print(f"Collected {len(configs)} configs from aggregators")
    return configs

# --- TIER 2: MASSIVELY EXPANDED CODE SEARCH ---

def fetch_from_github_code_search():
    """Supercharged GitHub code search with 100+ diverse queries."""
    print("\n--- [TIER 2] GitHub Code Search (100+ Queries) ---")
    
    if not COLLECTOR_TOKEN:
        print("WARNING: No COLLECTOR_TOKEN - skipping")
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'}
    
    # MASSIVELY EXPANDED QUERIES (100+)
    queries = [
        # === Persian ===
        '"vless" "کانفیگ" "رایگان"', '"vmess" "ایرانسل"', '"trojan" "همراه اول"',
        '"v2ray" "رایتل"', 'filename:subscribe "v2ray" "ایران"', '"reality" "کانفیگ"',
        '"ss://" "ایران"', '"vless" "رایگان"', '"vmess" "تلگرام"',
        
        # === English ===
        '"vmess://" "subscription"', '"vless://" "subscription"', '"trojan://" "free"',
        '"reality" "proxy"', '"v2ray" "free" "nodes"', '"proxy" "subscription"',
        '"shadowsocks" "subscription"', '"xray" "free"', '"clash" "subscription"',
        
        # === Chinese ===
        '"vmess" "免费"', '"v2ray" "订阅"', '"节点" "分享"', '"翻墙" "配置"',
        '"代理" "免费"', '"vless" "免费节点"', '"机场" "订阅"', '"ss" "免费"',
        '"trojan" "免费"', '"clash" "订阅链接"', '"科学上网"', '"梯子" "分享"',
        
        # === Russian ===
        '"vmess" "бесплатно"', '"v2ray" "подписка"', '"прокси" "бесплатно"',
        '"vless" "бесплатные"', '"trojan" "подписка"',
        
        # === Arabic ===
        '"vmess" "مجاني"', '"v2ray" "اشتراك"', '"بروكسي" "مجاني"',
        '"vless" "مجانا"', '"trojan" "اشتراك"',
        
        # === Turkish ===
        '"vmess" "ücretsiz"', '"v2ray" "abonelik"', '"proxy" "ücretsiz"',
        '"vless" "bedava"',
        
        # === Vietnamese ===
        '"vmess" "miễn phí"', '"v2ray" "đăng ký"', '"proxy" "miễn phí"',
        '"vless" "free"', '"cấu hình" "v2ray"',
        
        # === File-specific searches ===
        'filename:subscription.txt "vmess"', 'filename:sub.txt "vless"',
        'filename:all.txt "vmess://"', 'filename:config.txt "vless://"',
        'filename:nodes.txt "trojan"', 'filename:proxies.txt',
        'filename:v2ray.txt', 'filename:base64.txt "vmess"',
        
        # === Path-specific ===
        'path:subscribe "vmess://"', 'path:subscription "vless://"',
        'path:sub "trojan://"', 'path:config "vmess"',
        'path:nodes "vless"', 'path:proxies',
        
        # === Protocol-specific ===
        '"hy2://"', '"hysteria2://"', '"tuic://"', '"juicity://"',
        '"reality" "grpc"', '"vless" "xtls"', '"trojan" "reality"',
        '"vmess" "ws"', '"vless" "tcp"', '"trojan" "grpc"',
        
        # === YAML/JSON configs ===
        '"clash" "proxies:" extension:yaml', '"clash" "proxy-groups:" extension:yml',
        '"xray" extension:json "vless"', '"v2ray" extension:json "vmess"',
        
        # === Recent activity ===
        '"vmess://" pushed:>2024-06-01', '"vless://" pushed:>2024-06-01',
        '"trojan://" pushed:>2024-06-01', '"reality" pushed:>2024-06-01',
        
        # === Size-based (find substantial files) ===
        'size:>10000 "vmess://"', 'size:>10000 "vless://"',
        'size:>5000 extension:txt "vmess"',
        
        # === Aggregator keywords ===
        '"collector" "vmess"', '"aggregator" "v2ray"', '"subscription" "auto"',
        'filename:README.md "v2ray subscription"', '"daily update" "vmess"',
        
        # === Indonesian ===
        '"vmess" "gratis"', '"v2ray" "langganan"', '"proxy" "gratis"',
        
        # === Spanish/Portuguese ===
        '"vmess" "gratis"', '"proxy" "gratuito"', '"v2ray" "suscripción"',
        
        # === Mixed protocol searches ===
        '"vmess" OR "vless" in:file', '"trojan" OR "reality" in:file',
        '"shadowsocks" OR "v2ray" in:file',
    ]
    
    query_count = 0
    for query in queries:
        if query_count >= 30:  # Respect GitHub API limits
            print(f"  Reached query limit (30), processed {query_count} queries")
            break
            
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6)  # Rate limiting
            res = requests.get(search_url, headers=headers, timeout=30)
            
            if res.status_code == 403:
                print(f"  ⚠ Rate limited, stopping code search")
                break
            
            res.raise_for_status()
            items = res.json().get('items', [])
            
            if items:
                print(f"  Query {query_count + 1}: '{query[:50]}...' → {len(items)} files")
            
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
                            except:
                                pass
                        
                        found = find_configs_raw(content)
                        if found:
                            configs.update(found)
                except:
                    continue
            
            query_count += 1
            
        except Exception as e:
            if 'rate limit' in str(e).lower():
                print(f"  ⚠ Rate limit hit, stopping")
                break
            continue
    
    print(f"Collected {len(configs)} configs from code search ({query_count} queries)")
    return configs

# --- TIER 2: SMART REPOSITORY SEARCH ---

def fetch_from_github_repos_smart():
    """Repository search with smart file discovery."""
    print("\n--- [TIER 2] Smart Repository Search ---")
    
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    
    repo_queries = [
        'v2ray subscription', 'proxy subscription', 'v2ray collector',
        'clash subscription', 'free v2ray', 'xray subscription'
    ]
    
    for query in repo_queries[:3]:  # Limit to avoid rate limits
        try:
            time.sleep(6)
            search_url = f"https://api.github.com/search/repositories?q={query}&sort=updated&per_page=15"
            res = requests.get(search_url, headers=headers, timeout=30)
            
            if res.status_code != 200:
                continue
            
            repos = res.json().get('items', [])
            print(f"  '{query}': {len(repos)} repos")
            
            for repo in repos:
                # Get file tree
                try:
                    time.sleep(1)
                    default_branch = repo.get('default_branch', 'main')
                    tree_url = f"https://api.github.com/repos/{repo['full_name']}/git/trees/{default_branch}?recursive=1"
                    tree_res = requests.get(tree_url, headers=headers, timeout=10)
                    
                    if tree_res.status_code != 200:
                        continue
                    
                    tree = tree_res.json().get('tree', [])
                    
                    # Find promising files
                    promising_files = []
                    for file_obj in tree:
                        path = file_obj.get('path', '')
                        if file_obj.get('type') == 'blob':
                            # Check if filename looks promising
                            lower_path = path.lower()
                            if any(keyword in lower_path for keyword in [
                                'sub', 'config', 'node', 'proxy', 'v2ray', 
                                'all', 'merge', 'eternity', 'base64'
                            ]) and path.endswith(('.txt', '.yaml', '.yml', '.json')):
                                promising_files.append(path)
                    
                    # Download and scan promising files (max 5 per repo)
                    for file_path in promising_files[:5]:
                        try:
                            time.sleep(0.5)
                            raw_url = f"https://raw.githubusercontent.com/{repo['full_name']}/{default_branch}/{file_path}"
                            content_res = requests.get(raw_url, timeout=10)
                            
                            if content_res.status_code == 200:
                                content = content_res.text
                                
                                # Decode if base64
                                if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                                    try:
                                        content = base64.b64decode(content).decode('utf-8', 'ignore')
                                    except:
                                        pass
                                
                                found = find_configs_raw(content)
                                if found:
                                    configs.update(found)
                                    print(f"    ✓ {repo['name']}/{file_path}: {len(found)} configs")
                        except:
                            continue
                            
                except:
                    continue
                    
        except Exception:
            continue
    
    print(f"Collected {len(configs)} configs from smart repo search")
    return configs

# --- TIER 3: VALIDATED SUBSCRIPTION LINKS ---

def load_validated_links():
    """Load previously validated subscription links."""
    try:
        with open(VALIDATED_LINKS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_validated_links(links_data):
    """Save validated links with metadata."""
    try:
        with open(VALIDATED_LINKS_FILE, 'w') as f:
            json.dump(links_data, f, indent=2)
    except:
        pass

def fetch_and_validate_readme_links():
    """Extract and validate subscription links from READMEs."""
    print("\n--- [TIER 3] README Link Extraction & Validation ---")
    
    if not COLLECTOR_TOKEN:
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}'}
    validated_links = load_validated_links()
    
    # First, use previously validated links
    print("  Testing previously validated links...")
    working_links = {}
    for link, metadata in validated_links.items():
        try:
            response = requests.get(link, timeout=10)
            if response.status_code == 200:
                content = response.text
                found = find_configs_raw(content)
                if found:
                    configs.update(found)
                    working_links[link] = {
                        'last_success': time.time(),
                        'total_configs': len(found)
                    }
                    print(f"    ✓ Cached link: {len(found)} configs")
            time.sleep(0.3)
        except:
            continue
    
    # Search for new README links
    try:
        time.sleep(6)
        search_url = 'https://api.github.com/search/code?q=filename:README.md+"subscription"+"http"&per_page=50'
        res = requests.get(search_url, headers=headers, timeout=30)
        
        if res.status_code == 200:
            items = res.json().get('items', [])
            print(f"  Found {len(items)} READMEs to scan")
            
            url_pattern = r'https?://[^\s<>"\'`\)]+(?:sub|subscription|config|base64|v2ray|clash)[^\s<>"\'`\)]*\.(?:txt|yaml|yml)'
            
            for item in items[:20]:  # Limit processing
                try:
                    time.sleep(0.5)
                    raw_url = item.get('url')
                    content_res = requests.get(raw_url, headers=headers, timeout=10)
                    
                    if content_res.status_code == 200:
                        content = content_res.text
                        try:
                            decoded = base64.b64decode(content).decode('utf-8', 'ignore')
                            urls = re.findall(url_pattern, decoded)
                        except:
                            urls = re.findall(url_pattern, content)
                        
                        # Test each found URL
                        for url in urls[:5]:  # Max 5 per README
                            if url in working_links:
                                continue
                            
                            try:
                                time.sleep(0.5)
                                test_res = requests.get(url, timeout=10)
                                if test_res.status_code == 200:
                                    found = find_configs_raw(test_res.text)
                                    if found:
                                        configs.update(found)
                                        working_links[url] = {
                                            'last_success': time.time(),
                                            'total_configs': len(found)
                                        }
                                        print(f"    ✓ New link: {len(found)} configs")
                            except:
                                continue
                except:
                    continue
    except Exception:
        pass
    
    # Save validated links
    save_validated_links(working_links)
    print(f"Collected {len(configs)} configs from validated links ({len(working_links)} working links)")
    return configs

# --- PRE-FILTERING ---

def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs ---")
    
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
        print(f"Skipped {parse_errors} malformed configs")
    
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
                print(f"  Tested {i+1}/{len(hosts_to_test)} hosts...")
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
    
    print(f"Converted {stats['converted']} to IP, failed {stats['failed_attrs']}")
    return processed

# --- MAIN EXECUTION ---

def main():
    global geoip_reader
    setup_directories()
    
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
                    print(f"✓ GeoIP downloaded")
                    break
            except:
                continue
    
    try:
        geoip_reader = geoip2.database.Reader(db_path)
    except Exception as e:
        print(f"Warning: GeoIP load failed: {e}")
    
    # Collect from all sources
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
    print(f"✓ Local subscriptions: {len(all_raw_configs)} configs")
    
    # TIER 1: Direct Aggregators
    all_raw_configs.update(fetch_from_direct_aggregators())
    
    # TIER 2: Code Search
    all_raw_configs.update(fetch_from_github_code_search())
    
    # TIER 2: Smart Repo Search
    all_raw_configs.update(fetch_from_github_repos_smart())
    
    # TIER 3: Validated Links
    all_raw_configs.update(fetch_and_validate_readme_links())
    
    print(f"\n{'='*70}")
    print(f"  COLLECTION COMPLETE")
    print(f"{'='*70}")
    print(f"  Total raw configs: {len(all_raw_configs)}")
    print(f"{'='*70}\n")
    
    if not all_raw_configs:
        print("No configs collected. Exiting.")
        return
    
    # Pre-filter
    live_configs = pre_filter_live_hosts(list(all_raw_configs))
    
    if not live_configs:
        print("No live configs. Exiting.")
        return
    
    # SNI conversion for refiner
    print("\n--- Converting for filtered-for-refiner.txt ---")
    sni_configs = []
    for config in live_configs:
        sni_config = replace_address_with_sni(config)
        attrs = get_config_attributes(sni_config)
        if attrs:
            sni_configs.append(rename_config(sni_config, attrs['country']))
        else:
            sni_configs.append(sni_config)
    
    with open('filtered-for-refiner.txt', 'w', encoding='utf-8') as f:
        for config in sni_configs:
            f.write(config + '\n')
    print(f"✓ Saved {len(sni_configs)} configs to filtered-for-refiner.txt")
    
    # REALITY+gRPC
    reality_grpc = [c for c in live_configs if (a := get_config_attributes(c)) and a['security'] == 'reality' and a['network'] == 'grpc']
    if reality_grpc:
        with open('reality-grpc-configs.txt', 'w', encoding='utf-8') as f:
            for cfg in reality_grpc:
                f.write(cfg + '\n')
        print(f"✓ Found {len(reality_grpc)} REALITY+gRPC configs")
    
    # Process for categorization
    processed = process_and_convert_configs(live_configs)
    
    # Categorize
    print("\n--- Categorizing ---")
    by_protocol, by_network, by_security, by_country = {}, {}, {}, {}
    
    for item in processed:
        config, attrs = item['config'], item['attrs']
        by_protocol.setdefault(attrs['protocol'], []).append(config)
        by_network.setdefault(attrs['network'], []).append(config)
        by_security.setdefault(attrs['security'], []).append(config)
        by_country.setdefault(attrs['country'].lower(), []).append(config)
    
    # Write files
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
    
    # Summary
    print(f"\n{'='*70}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"  Raw collected       : {len(all_raw_configs)}")
    print(f"  Live filtered       : {len(live_configs)}")
    print(f"  Processed (IP)      : {len(processed)}")
    print(f"  REALITY+gRPC        : {len(reality_grpc)}")
    print(f"  Protocols           : {len(by_protocol)}")
    print(f"  Networks            : {len(by_network)}")
    print(f"  Countries           : {len(by_country)}")
    print(f"  DNS cache           : {len(dns_cache)}")
    print(f"{'='*70}")
    print("\n✓ COLLECTION COMPLETE - Lean & Powerful!")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n--- FATAL ERROR ---")
        traceback.print_exc()
        exit(1)
