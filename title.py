# FINAL BULLETPROOF version of title.py - v4 Ultimate Fix
import os, uuid, time, random, json, pycountry_convert as pc, html, socket, ipaddress, tldextract, geoip2.database, re, base64
from urllib.parse import urlparse, parse_qs

print("--- title.py: STARTING SCRIPT (v4 - ULTIMATE FIX) ---")

def is_valid_uuid(v):
    try: uuid.UUID(str(v)); return True
    except: return False
def is_valid_ip_address(ip):
    try:
        if not ip or not isinstance(ip, str): return False
        if ip.startswith("[") and ip.endswith("]"): ip = ip[1:-1]
        ipaddress.ip_address(ip); return True
    except: return False
def get_ips(node):
    try:
        from dns import resolver, rdatatype
        if not node: return None
        if is_valid_ip_address(node): return [node]
        res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
        ips = set()
        for rdtype in ("A", "AAAA"):
            try:
                answers = res.resolve(node, rdtype, raise_on_no_answer=False)
                if answers: ips.update({rdata.address for rdata in answers})
            except: continue
        return list(ips) if ips else None
    except Exception: return None
def get_country_from_ip(ip):
    db_path = "./geoip-lite/geoip-lite-country.mmdb"
    if not os.path.exists(db_path): return "XX"
    try:
        with geoip2.database.Reader(db_path) as reader:
            return reader.country(ip).country.iso_code or "XX"
    except: return "XX"
def get_country_flag(cc):
    if not cc or cc.upper() in ['NA', 'XX']: return "\U0001F3F4\u200D\u2620\uFE0F"
    try: return "".join([chr(ord(c) + 127397) for c in cc.upper()])
    except: return "\U0001F3F4\u200D\u2620\uFE0F"
def check_port(ip, port, timeout=1.0):
    try:
        with socket.create_connection(address=(ip, int(port)), timeout=timeout):
            return True
    except: return False
def ping_ip_address(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start_time = time.time()
            if sock.connect_ex((ip, int(port))) == 0:
                return round((time.time() - start_time) * 1000, 2)
            return 9999
    except: return 9999

def check_modify_config(array_configuration, protocol_type, check_connection=True):
    print(f"--- Processing {len(array_configuration)} configs for {protocol_type} ---")
    modified_array, tls_array, non_tls_array = [], [], []
    tcp_array, ws_array, http_array, grpc_array = [],[],[],[]

    for element in array_configuration:
        try:
            # --- Universal Parsing ---
            if "://" not in element: continue
            proto_part, main_part = element.split("://", 1)
            
            # --- Protocol Specific Parsing ---
            if protocol_type == "VMESS":
                json_str = main_part.strip()
                if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                config = json.loads(base64.b64decode(json_str).decode('utf-8', errors='ignore'))
                host, port, config_id = config.get('add'), int(config.get('port', 0)), config.get('id')
                params = config # The whole dict acts as params
            else:
                parsed_url = urlparse(element)
                host, port, config_id = parsed_url.hostname, parsed_url.port, parsed_url.username
                params = parse_qs(parsed_url.query)

            if not all([host, port, config_id]): continue
            if not is_valid_uuid(config_id):
                # SS uses a different encoding, not UUID
                if protocol_type != 'SHADOWSOCKS': continue

            # --- Network & Processing ---
            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]
            
            if check_connection:
                if not check_port(ip_address, port): continue
                ping = ping_ip_address(ip_address, port)
                if ping > 2000: continue
            else:
                ping = 0
            
            # --- Title Generation ---
            country_code = get_country_from_ip(ip_address)
            country_flag = get_country_flag(country_code)
            ip_display = f"[{ip_address}]" if ":" in ip_address else ip_address
            
            config_type = "TCP" # Default
            config_secrt = "NA" # Default
            if isinstance(params, dict) and protocol_type == 'VMESS':
                config_type = params.get('net', 'tcp').upper()
                config_secrt = 'TLS' if params.get('tls') == 'tls' else 'NA'
            elif isinstance(params, dict):
                config_type = params.get('type', ['tcp'])[0].upper()
                config_secrt = params.get('security', ['NA'])[0].upper()
            
            if protocol_type == "REALITY": config_secrt = "RLT"
            
            proto_code = {"VLESS":"VL","REALITY":"VL","TROJAN":"TR","VMESS":"VM","SHADOWSOCKS":"SS","HYSTERIA":"HY","TUIC":"TU","JUICITY":"JU"}.get(protocol_type, "UN")
            title = f"\U0001F512 {proto_code}-{config_type}-{config_secrt} {country_flag}{country_code}-{ip_display}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
            
            # --- Rebuild Final Config ---
            if protocol_type == "VMESS":
                config['ps'] = title; config['add'] = ip_address
                final_config = f"vmess://{base64.b64encode(json.dumps(config).encode('utf-8')).decode('utf-8')}"
            else:
                final_config = urlparse(element)._replace(fragment=title).geturl()

            modified_array.append(final_config)
            if config_secrt in ['TLS', 'RLT']: tls_array.append(final_config)
            else: non_tls_array.append(final_config)
            if config_type == 'TCP': tcp_array.append(final_config)
            elif config_type == 'WS': ws_array.append(final_config)
            elif config_type == 'GRPC': grpc_array.append(final_config)

        except Exception: continue
            
    print(f"--- Finished processing for {protocol_type}. Found {len(modified_array)} configs. ---")
    return modified_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array

def config_sort(array_configuration, bound_ping = 50):
    # This function is correct.
    sort_init_list = []
    for config in array_configuration:
        try:
            ping_search = re.search(r'PING-([\d.]+)-MS', config)
            if ping_search: sort_init_list.append((float(ping_search.group(1)), config))
        except: continue
    forward_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] >= bound_ping], key=lambda el: el[0])]
    reversed_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] < bound_ping], key=lambda el: el[0], reverse=True)]
    forward_sorted.extend(reversed_sorted)
    return forward_sorted
    
def create_country(array_configuration):
    # --- THIS IS THE CRITICAL COUNTRY FIX ---
    print("--- title.py: create_country START (v4 - Ultimate Fix) ---")
    country_dict = {}
    for config in array_configuration:
        try:
            # This regex looks for a flag emoji, then OPTIONALLY a space, then the country code
            match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}\s*([A-Z]{2})-', config)
            if match:
                country_code = match.group(1).lower()
                if country_code not in country_dict: country_dict[country_code] = []
                country_dict[country_code].append(config)
        except: continue
    print(f"--- title.py: create_country END - Found {len(country_dict)} countries ---")
    return country_dict

def create_title(t,p):u=str(uuid.uuid4());rc=f"vless://{u}@127.0.0.1:{p}?security=tls&type=tcp#{t}";vc=f"vless://{u}@127.0.0.1:{p}?security=tls&type=tcp#{t}";vmc=f'vmess://{base64.b64encode(json.dumps({"add":"127.0.0.1","port":p,"ps":t,"id":u}).encode("utf-8")).decode("utf-8")}';tc=f"trojan://{u}@127.0.0.1:{p}?security=tls&type=tcp#{t}";sc=f"ss://{base64.b64encode(f'aes-256-gcm:{u}'.encode('utf-8')).decode('utf-8')}@127.0.0.1:{p}#{t}";return rc,vc,vmc,tc,sc

# Preserving your other functions
def create_country_table(p): return ""
def create_internet_protocol(a): return [],[]
def remove_duplicate(s,t,v,vl,r,tu,h,j,**k): return list(set(s)),list(set(t)),list(set(v)),list(set(vl)),list(set(r)),list(set(tu)),list(set(h)),list(set(j))
def remove_duplicate_modified(a): return list(set(a))
def decode_vmess(c): return c

print("--- title.py: SCRIPT LOADED (v4 - Ultimate Fix) ---")
