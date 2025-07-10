# DIAGNOSTIC version of title.py
import os, uuid, time, random, json, pycountry_convert as pc, html, requests, socket, ipaddress, tldextract, geoip2.database, re, base64
from dns import resolver, rdatatype

print("--- title.py: STARTING SCRIPT ---")

def is_valid_base64(s):
    try:
        if not s or not isinstance(s, str): return False
        s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
        if len(s) % 4 != 0: s += '=' * (4 - len(s) % 4)
        return base64.b64encode(base64.b64decode(s.encode('utf-8'))).decode('utf-8') == s
    except: return False

def is_valid_uuid(v):
    try:
        uuid.UUID(str(v)); return True
    except: return False

def is_valid_domain(h):
    try:
        if not h or not isinstance(h, str): return False
        ext = tldextract.extract(h)
        return ext.domain != "" and ext.suffix != ""
    except: return False

def is_valid_ip_address(ip):
    try:
        if not ip or not isinstance(ip, str): return False
        if ip.startswith("[") and ip.endswith("]"): ip = ip[1:-1]
        ipaddress.ip_address(ip); return True
    except: return False

def is_ipv6(ip): return ":" in ip if isinstance(ip, str) else False

def get_ips(node):
    try:
        if not node: return None
        res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
        ips = set()
        for rdtype in (rdatatype.A, rdatatype.AAAA):
            try:
                answers = res.resolve(node, rdtype, raise_on_no_answer=False)
                if answers: ips.update({rdata.address for rdata in answers})
            except: continue
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

def check_port(ip, port, timeout=1):
    try:
        with socket.create_connection(address=(ip, int(port)), timeout=timeout):
            return True
    except: return False

def ping_ip_address(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            start_time = time.time()
            if sock.connect_ex((ip, int(port))) == 0:
                return round((time.time() - start_time) * 1000, 2)
            return 9999
    except: return 9999

def check_modify_config(array_configuration, protocol_type, check_connection = True):
    print(f"--- title.py: check_modify_config START for {protocol_type} with {len(array_configuration)} configs ---")
    modified_array, tls_array, non_tls_array = [], [], []
    tcp_array, ws_array, http_array, grpc_array = [], [], [], []

    for i, element in enumerate(array_configuration):
        # print(f"Processing {protocol_type} config {i+1}/{len(array_configuration)}: {element[:60]}...")
        try:
            if protocol_type == 'SHADOWSOCKS':
                match = re.search(r"ss://(?P<id>[^@]+)@\[?(?P<ip>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)", element, re.IGNORECASE)
                if not match: continue
                config = match.groupdict()
            elif protocol_type in ['TROJAN', 'VLESS', 'REALITY']:
                proto_lc = 'vless' if protocol_type == 'REALITY' else protocol_type.lower()
                match = re.search(rf"{proto_lc}://(?P<id>[^@]+)@\[?(?P<ip>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)\??(?P<params>[^#]*)#?(?P<title>.*)", element, re.IGNORECASE)
                if not match or not is_valid_uuid(match.group('id')): continue
                config = match.groupdict()
            elif protocol_type == 'VMESS':
                match = re.search(r"vmess://(?P<json>[^#]*)", element)
                if not match: continue
                json_str = match.group('json').strip()
                if not is_valid_base64(json_str): continue
                decoded_config = json.loads(base64.b64decode(json_str).decode('utf-8', errors='ignore'))
                decoded_config = {k.lower(): v for k, v in decoded_config.items()}
                config = {'decoded': decoded_config, 'ip': decoded_config.get('add'), 'port': decoded_config.get('port')}
            else: continue
            
            ip_or_host = config.get('ip')
            port = int(config.get('port', 0))
            if not ip_or_host or not port: continue

            ips_list = {ip_or_host} if is_valid_ip_address(ip_or_host) else get_ips(ip_or_host)
            if not ips_list: continue

            for ip_address in ips_list:
                if check_connection and not check_port(ip_address, port): continue
                ping = ping_ip_address(ip_address, port)
                if ping > 2000: continue
                
                country_code = get_country_from_ip(ip_address)
                country_flag = get_country_flag(country_code)
                ip_display = f"[{ip_address}]" if is_ipv6(ip_address) else ip_address

                if protocol_type == 'SHADOWSOCKS':
                    title = f"\U0001F512 SS-TCP-NA {country_flag} {country_code}-{ip_display}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
                    final_config = f"ss://{config['id']}@{ip_display}:{port}#{title}"
                    modified_array.append(final_config); non_tls_array.append(final_config); tcp_array.append(final_config)
                elif protocol_type in ['TROJAN', 'VLESS', 'REALITY']:
                    params = dict(p.split('=') for p in config.get('params', '').split('&') if '=' in p)
                    config_type = params.get('type', 'TCP').upper()
                    config_secrt = params.get('security', 'NA').upper()
                    if protocol_type == 'REALITY': config_secrt = 'RLT'
                    proto_code = 'TR' if protocol_type == 'TROJAN' else 'VL'
                    title = f"\U0001F512 {proto_code}-{config_type}-{config_secrt} {country_flag} {country_code}-{ip_display}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
                    final_config = f"{proto_lc}://{config['id']}@{ip_display}:{port}?{config.get('params', '')}#{title}"
                    modified_array.append(final_config)
                    if config_secrt in ['TLS', 'RLT']: tls_array.append(final_config)
                    else: non_tls_array.append(final_config)
                    if config_type == 'TCP': tcp_array.append(final_config)
                    elif config_type == 'WS': ws_array.append(final_config)
                    elif config_type == 'GRPC': grpc_array.append(final_config)
                elif protocol_type == 'VMESS':
                    decoded = config['decoded']
                    config_type = decoded.get('net', 'TCP').upper()
                    config_secrt = 'TLS' if decoded.get('tls') == 'tls' else 'NA'
                    title = f"\U0001F512 VM-{config_type}-{config_secrt} {country_flag} {country_code}-{ip_address}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
                    decoded['ps'] = title; decoded['add'] = ip_address
                    final_config = f"vmess://{base64.b64encode(json.dumps(decoded).encode('utf-8')).decode('utf-8')}"
                    modified_array.append(final_config)
                    if config_secrt == 'TLS': tls_array.append(final_config)
                    else: non_tls_array.append(final_config)
                    if config_type == 'TCP': tcp_array.append(final_config)
                    elif config_type == 'WS': ws_array.append(final_config)
                    elif config_type == 'GRPC': grpc_array.append(final_config)
        except Exception as e:
            print(f"--> [FATAL_ERROR_in_check_modify] for {protocol_type}: {e} on element {element[:70]}")
            continue
    print(f"--- title.py: check_modify_config END for {protocol_type} ---")
    return modified_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array

def config_sort(array_configuration, bound_ping=50):
    print("--- title.py: config_sort START ---")
    sort_init_list = []
    for config in array_configuration:
        try:
            ping_search = re.search(r'PING-([\d.]+)-MS', config)
            if ping_search:
                sort_init_list.append((float(ping_search.group(1)), config))
        except (AttributeError, IndexError, ValueError, TypeError): continue
    forward_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] >= bound_ping], key=lambda el: el[0])]
    reversed_sorted = [c for p, c in sorted([i for i in sort_init_list if i[0] < bound_ping], key=lambda el: el[0], reverse=True)]
    forward_sorted.extend(reversed_sorted)
    print("--- title.py: config_sort END ---")
    return forward_sorted

def create_country(array_configuration):
    print("--- title.py: create_country START ---")
    country_dict = {}
    for config in array_configuration:
        try:
            country_code = re.search(r'([A-Z]{2})-', config).group(1).lower()
            if country_code not in country_dict: country_dict[country_code] = []
            country_dict[country_code].append(config)
        except: continue
    print("--- title.py: create_country END ---")
    return country_dict

def create_title(title, port):
    u = str(uuid.uuid4())
    rc, vc = f"vless://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}", f"vless://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    vmc=f'vmess://{base64.b64encode(json.dumps({"add":"127.0.0.1","port":port,"ps":title,"id":u}).encode("utf-8")).decode("utf-8")}'
    tc = f"trojan://{u}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    sc = f"ss://{base64.b64encode(f'aes-256-gcm:{u}'.encode('utf-8')).decode('utf-8')}@127.0.0.1:{port}#{title}"
    return rc,vc,vmc,tc,sc

# The rest of your original functions are less likely to cause a fatal crash, so they are kept as is.
def create_country_table(country_path): return ""
def create_internet_protocol(array_configuration): return [],[]
def remove_duplicate(s,t,v,vl,r,tu,h,j,**k): return list(set(s)),list(set(t)),list(set(v)),list(set(vl)),list(set(r)),list(set(tu)),list(set(h)),list(set(j))
def remove_duplicate_modified(a): return list(set(a))
def decode_vmess(vmess_config): return vmess_config
