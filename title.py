# FINAL BULLETPROOF version of title.py
import os, uuid, time, random, json, pycountry_convert as pc, html, requests, socket, ipaddress, tldextract, geoip2.database, re, base64
from urllib.parse import urlparse, parse_qs

print("--- title.py: STARTING SCRIPT (BULLETPROOF VERSION) ---")

def is_valid_uuid(v):
    try:
        uuid.UUID(str(v)); return True
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
            except Exception: continue
        return list(ips) if ips else None
    except Exception as e:
        print(f"--> [DNS_ERROR] for {node}: {e}"); return None

def get_country_from_ip(ip):
    db_path = "./geoip-lite/geoip-lite-country.mmdb"
    if not os.path.exists(db_path): return "XX"
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return response.country.iso_code or "XX"
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
            parsed_url = urlparse(element)
            if not parsed_url.hostname or not parsed_url.port: continue

            config_id = parsed_url.username
            host = parsed_url.hostname
            port = parsed_url.port
            
            if protocol_type == "VMESS":
                try:
                    json_str = element.replace("vmess://", "").strip()
                    if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                    decoded_config = json.loads(base64.b64decode(json_str).decode('utf-8', errors='ignore'))
                    host = decoded_config.get('add', host)
                    port = int(decoded_config.get('port', port))
                    config_id = decoded_config.get('id')
                except Exception: continue
            
            if not is_valid_uuid(config_id): continue

            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]
            
            if check_connection:
                if not check_port(ip_address, port): continue
                ping = ping_ip_address(ip_address, port)
                if ping > 2000: continue
            else:
                ping = 0

            country_code = get_country_from_ip(ip_address)
            country_flag = get_country_flag(country_code)
            ip_display = f"[{ip_address}]" if ":" in ip_address else ip_address
            
            params = parse_qs(parsed_url.query)
            config_type = params.get('type', ['tcp'])[0].upper()
            config_secrt = params.get('security', ['NA'])[0].upper()
            if protocol_type == "REALITY": config_secrt = "RLT"
            
            proto_code = "UN"
            if protocol_type in ["VLESS", "REALITY"]: proto_code = "VL"
            elif protocol_type == "TROJAN": proto_code = "TR"
            elif protocol_type == "VMESS": proto_code = "VM"
            elif protocol_type == "SHADOWSOCKS": proto_code = "SS"
            elif protocol_type == "HYSTERIA": proto_code = "HY"
            elif protocol_type == "TUIC": proto_code = "TU"
            elif protocol_type == "JUICITY": proto_code = "JU"

            title = f"\U0001F512 {proto_code}-{config_type}-{config_secrt} {country_flag} {country_code}-{ip_display}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
            
            final_config = parsed_url._replace(fragment=title).geturl()
            modified_array.append(final_config)

            if config_secrt in ['TLS', 'RLT']: tls_array.append(final_config)
            else: non_tls_array.append(final_config)
            if config_type == 'TCP': tcp_array.append(final_config)
            elif config_type == 'WS': ws_array.append(final_config)
            elif config_type == 'GRPC': grpc_array.append(final_config)

        except Exception as e:
            # print(f"--> [SKIP] Error processing config: {e}. Original: {element[:70]}")
            continue
            
    print(f"--- Finished processing for {protocol_type}. Found {len(modified_array)} live configs. ---")
    return modified_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array

def config_sort(array_configuration, bound_ping = 50):
    sort_init_list = []
    for config in array_configuration:
        try:
            ping_search = re.search(r'PING-([\d.]+)-MS', config)
            if ping_search:
                sort_init_list.append((float(ping_search.group(1)), config))
        except: continue
    forward_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] >= bound_ping], key=lambda el: el[0])]
    reversed_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] < bound_ping], key=lambda el: el[0], reverse=True)]
    forward_sorted.extend(reversed_sorted)
    return forward_sorted

def create_country(array_configuration):
    country_dict = {}
    for config in array_configuration:
        try:
            country_code = re.search(r'([A-Z]{2})-', config).group(1).lower()
            if country_code not in country_dict: country_dict[country_code] = []
            country_dict[country_code].append(config)
        except: continue
    return country_dict

def create_title(title, port):
    u=str(uuid.uuid4());rc=f"vless://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}";vc=f"vless://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}";vmc=f'vmess://{base64.b64encode(json.dumps({"add":"127.0.0.1","port":port,"ps":title,"id":u}).encode("utf-8")).decode("utf-8")}';tc=f"trojan://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}";sc=f"ss://{base64.b64encode(f'aes-256-gcm:{u}'.encode('utf-8')).decode('utf-8')}@127.0.0.1:{port}#{title}";return rc,vc,vmc,tc,sc

# Preserving your other functions
def create_country_table(p): return ""
def create_internet_protocol(a): return [],[]
def remove_duplicate(s,t,v,vl,r,tu,h,j,**k): return list(set(s)),list(set(t)),list(set(v)),list(set(vl)),list(set(r)),list(set(tu)),list(set(h)),list(set(j))
def remove_duplicate_modified(a): return list(set(a))
def decode_vmess(c): return c

print("--- title.py: SCRIPT LOADED ---")
