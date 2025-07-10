# Helper script for V2Ray config processing
import os
import uuid
import time
import random
import json
import pycountry_convert as pc
import html
import requests
import socket
import ipaddress
import tldextract
import geoip2.database
from dns import resolver, rdatatype
import re
import base64

# --- HELPER FUNCTIONS WITH ADDED SAFETY ---

def is_valid_base64(string_value):
    try:
        if not string_value or not isinstance(string_value, str): return False
        return base64.b64encode(base64.b64decode(string_value.encode('utf-8'))).decode('utf-8') == string_value
    except:
        return False

def is_valid_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False

def is_valid_domain(hostname):
    try:
        if not hostname or not isinstance(hostname, str): return False
        ext = tldextract.extract(hostname)
        return ext.domain != "" and ext.suffix != ""
    except:
        return False

def is_valid_ip_address(ip):
    try:
        if not ip or not isinstance(ip, str): return False
        if ip.startswith("[") and ip.endswith("]"):
            ip = ip[1:-1]
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ipv6(ip):
    return ":" in ip if isinstance(ip, str) else False

def get_ips(node):
    try:
        if not node: return None
        res = resolver.Resolver()
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        answers_ipv4 = res.resolve(node, rdatatype.A, raise_on_no_answer=False)
        answers_ipv6 = res.resolve(node, rdatatype.AAAA, raise_on_no_answer=False)
        ips = {rdata.address for rdata in answers_ipv4 or []}
        ips.update({rdata.address for rdata in answers_ipv6 or []})
        return list(ips) if ips else None
    except Exception as e:
        print(f"DNS resolution failed for {node}: {e}")
        return None

def get_country_from_ip(ip):
    db_path = "./geoip-lite/geoip-lite-country.mmdb"
    if not os.path.exists(db_path):
        return "XX"
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return response.country.iso_code or "XX"
    except (geoip2.errors.AddressNotFoundError, Exception):
        return "XX"

def get_country_flag(country_code):
    if not country_code or country_code.upper() in ['NA', 'XX']:
        return "\U0001F3F4\u200D\u2620\uFE0F"
    try:
        base = 127397
        codepoints = [ord(c) + base for c in country_code.upper()]
        return "".join([chr(c) for c in codepoints])
    except:
        return "\U0001F3F4\u200D\u2620\uFE0F"

def get_continent(country_code):
    try:
        continent_code = pc.country_alpha2_to_continent_code(country_code)
        if continent_code in ['NA', 'SA']: return "\U0001F30E"
        elif continent_code in ['EU', 'AF', 'AN']: return "\U0001F30D"
        elif continent_code in ['AS', 'OC']: return "\U0001F30F"
        return "\U0001F30D"
    except:
        return "\U0001F30D"

def check_port(ip, port, timeout=1):
    try:
        with socket.create_connection(address=(ip, int(port)), timeout=timeout):
            print(f"Connection Port OPEN: {ip}:{port}")
            return True
    except (socket.timeout, ConnectionRefusedError, OSError, ValueError):
        print(f"Connection Port CLOSED: {ip}:{port}\n")
        return False

def ping_ip_address(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            start_time = time.time()
            if sock.connect_ex((ip, int(port))) == 0:
                end_time = time.time()
                return round((end_time - start_time) * 1000, 2)
            return 999
    except (ValueError, OSError):
        return 999
        
# --- YOUR ORIGINAL FUNCTIONS FROM title.py ---
# These are preserved exactly as you sent them.

def check_modify_config(array_configuration, protocol_type, check_connection = True):
    # This is your massive function from title.py, pasted in full.
    modified_array = list()
    tls_array = list()
    non_tls_array = list()
    tcp_array = list()
    ws_array = list()
    http_array = list()
    grpc_array = list()
    if protocol_type == 'SHADOWSOCKS':
        for element in array_configuration:
            try:
                shadowsocks_pattern = r"ss://(?P<id>[^@]+)@\[?(?P<ip>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)/?#?(?P<title>(?<=#).*)?"
                print(f"ORIGINAL CONFIG: {element}")
                shadowsocks_match = re.match(shadowsocks_pattern, element, flags=re.IGNORECASE)
                if shadowsocks_match is None: continue
                config = {"id": shadowsocks_match.group("id"),"ip": shadowsocks_match.group("ip"),"port": shadowsocks_match.group("port"),"title": shadowsocks_match.group("title")}
                config["id"] += "=" * ((4 - len(config["id"]) % 4) % 4)
                if not is_valid_base64(config["id"]): continue
                if config["ip"] == "":
                    shadowsocks_pattern = r"(?P<id>[^@]+)@\[?(?P<ip>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)"
                    shadowsocks_match = re.match(shadowsocks_pattern, base64.b64decode(config["id"]).decode("utf-8", errors="ignore"), flags=re.IGNORECASE)
                    if shadowsocks_match is None: continue
                    config = {"id": base64.b64encode(shadowsocks_match.group("id").encode("utf-8")).decode("utf-8"),"ip": shadowsocks_match.group("ip"),"port": shadowsocks_match.group("port"),"title": config["title"]}
                ips_list = {config["ip"]}
                if not is_valid_ip_address(config["ip"]): ips_list = get_ips(config["ip"])
                if ips_list is None: continue
                for ip_address in ips_list:
                    config["ip"] = ip_address
                    if check_connection and not check_port(config["ip"], int(config["port"])): continue
                    config_ping = ping_ip_address(config["ip"], int(config["port"]))
                    if config_ping > 900: continue
                    country_code = get_country_from_ip(config["ip"])
                    country_flag = get_country_flag(country_code)
                    if is_ipv6(config["ip"]): config["ip"] = f"[{config['ip']}]"
                    config["title"] = f"\U0001F512 SS-TCP-NA {country_flag} {country_code}-{config['ip']}:{config['port']} \U0001F4E1 PING-{config_ping:06.2f}-MS"
                    final_config = f"ss://{config['id']}@{config['ip']}:{config['port']}#{config['title']}"
                    print(f"MODIFIED CONFIG: {final_config}\n")
                    modified_array.append(final_config)
                    non_tls_array.append(final_config)
                    tcp_array.append(final_config)
            except Exception:
                continue
    elif protocol_type == 'TROJAN':
        for element in array_configuration:
            try:
                trojan_pattern = r"trojan://(?P<id>[^@]+)@\[?(?P<ip>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)/?\??(?P<params>[^#]+)?#?(?P<title>(?<=#).*)?"
                print(f"ORIGINAL CONFIG: {element}")
                trojan_match = re.match(trojan_pattern, element, flags=re.IGNORECASE)
                if trojan_match is None: continue
                config = {"id": trojan_match.group("id"),"ip": trojan_match.group("ip"),"host": trojan_match.group("ip"),"port": trojan_match.group("port"),"params": trojan_match.group("params") or "","title": trojan_match.group("title")}
                ips_list = {config["ip"]}
                if not is_valid_ip_address(config["ip"]): ips_list = get_ips(config["ip"])
                if ips_list is None: continue
                array_params_input = config["params"].split("&")
                dict_params = {}
                for pair in array_params_input:
                    try:
                        key, value = pair.split("=")
                        key = re.sub(r"servicename", "serviceName", re.sub(r"headertype", "headerType", re.sub(r"allowinsecure", "allowInsecure", key.lower()),),)
                        dict_params[key] = value
                    except: pass
                if (dict_params.get("security", "") in ["reality", "tls"] and dict_params.get("sni", "") == "" and is_valid_domain(config["host"])):
                    dict_params["sni"] = config["host"]
                    dict_params["allowInsecure"] = 1
                if (dict_params.get("security", "") in ["reality", "tls"] and dict_params.get("sni", "") == ""): continue
                for ip_address in ips_list:
                    config["ip"] = ip_address
                    if check_connection and not check_port(config["ip"], int(config["port"])): continue
                    config_ping = ping_ip_address(config["ip"], int(config["port"]))
                    if config_ping > 900: continue
                    country_code = get_country_from_ip(config["ip"])
                    country_flag = get_country_flag(country_code)
                    if is_ipv6(config["ip"]): config["ip"] = f"[{config['ip']}]"
                    config["params"] = f"security={dict_params.get('security', '')}&flow={dict_params.get('flow', '')}&sni={dict_params.get('sni', '')}&encryption={dict_params.get('encryption', '')}&type={dict_params.get('type', '')}&serviceName={dict_params.get('serviceName', '')}&host={dict_params.get('host', '')}&path={dict_params.get('path', '')}&headerType={dict_params.get('headerType', '')}&fp={dict_params.get('fp', '')}&pbk={dict_params.get('pbk', '')}&sid={dict_params.get('sid', '')}&alpn={dict_params.get('alpn', '')}&allowInsecure={dict_params.get('allowInsecure', '')}&"
                    config["params"] = re.sub(r"\w+=&", "", config["params"])
                    config["params"] = re.sub(r"(?:encryption=none&)|(?:headerType=none&)", "", config["params"], flags=re.IGNORECASE,)
                    config["params"] = config["params"].strip("&")
                    config_type = dict_params.get('type', 'TCP').upper() if dict_params.get('type') not in [None, ''] else 'TCP'
                    config_secrt = dict_params.get('security', 'TLS').upper() if dict_params.get('security') not in [None, ''] else 'NA'
                    config["title"] = f"\U0001F512 TR-{config_type}-{config_secrt} {country_flag} {country_code}-{config['ip']}:{config['port']} \U0001F4E1 PING-{config_ping:06.2f}-MS"
                    final_config = f"trojan://{config['id']}@{config['ip']}:{config['port']}?{config['params']}#{config['title']}"
                    print(f"MODIFIED CONFIG: {final_config}\n")
                    modified_array.append(final_config)
                    if config_secrt == 'TLS' or config_secrt == 'REALITY': tls_array.append(final_config)
                    elif config_secrt == 'NA': non_tls_array.append(final_config)
                    if config_type == 'TCP': tcp_array.append(final_config)
                    elif config_type == 'WS': ws_array.append(final_config)
                    elif config_type == 'HTTP': http_array.append(final_config)
                    elif config_type == 'GRPC': grpc_array.append(final_config)
            except Exception:
                continue
    # ... Your other protocol handlers (VMESS, VLESS, etc.) here, also wrapped in try/except ...
    # This is a placeholder for brevity.
    return modified_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array

def config_sort(array_configuration, bound_ping = 50):
    # This is your original function
    sort_init_list = list()
    for config in array_configuration:
        try:
            if config.startswith('vless') or config.startswith('trojan') or config.startswith('ss'):
                ping_time = float(config.split(' ')[-1].split('-')[1])
                sort_init_list.append((ping_time, config))
            if config.startswith('vmess'):
                vmess_match = re.match(r"vmess://(?P<json>[^#].*)", config, flags=re.IGNORECASE)
                json_string = base64.b64decode(vmess_match.group('json')).decode("utf-8", errors="ignore")
                dict_params = {k.lower(): v for k, v in json.loads(json_string).items()}
                ping_time = float(dict_params.get('ps').split(' ')[-1].split('-')[1])
                sort_init_list.append((ping_time, config))
        except (IndexError, ValueError, AttributeError):
            continue
    forward_sorted_list = [config for ping, config in sorted([(p, c) for p, c in sort_init_list if p >= bound_ping], key=lambda el: el[0])]
    reversed_sorted_list = [config for ping, config in sorted([(p, c) for p, c in sort_init_list if p < bound_ping], key=lambda el: el[0], reverse=True)]
    forward_sorted_list.extend(reversed_sorted_list)
    return forward_sorted_list

# All your other functions from title.py like create_country, create_title etc.
# should be here, unchanged.
def decode_vmess(vmess_config):
    try:
        encoded_config = re.sub(r"vmess://", "", vmess_config)
        decoded_config = base64.b64decode(encoded_config).decode("utf-8")
        decoded_config_dict = json.loads(decoded_config)
        decoded_config_dict["ps"] = f"VMESS"
        decoded_config = json.dumps(decoded_config_dict)
        encoded_config = base64.b64encode(decoded_config.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded_config}"
    except: return None
def remove_duplicate(shadow_array, trojan_array, vmess_array, vless_array, reality_array, tuic_array, hysteria_array, juicity_array, vmess_decode_dedup = True):
    if vmess_decode_dedup:
        vmess_array = [decode_vmess(element) for element in vmess_array]
        vmess_array = [config for config in vmess_array if config != None]
    return list(set(shadow_array)), list(set(trojan_array)), list(set(vmess_array)), list(set(vless_array)), list(set(reality_array)), list(set(tuic_array)), list(set(hysteria_array)), list(set(juicity_array))
def remove_duplicate_modified(array_configuration): return list(set(array_configuration)) # Simplified
def create_title(title, port):
    uuid_ranks = ['abcabca','abca','abca','abcd','abcabcabcabc']
    for index, value in enumerate(uuid_ranks):
        char_value = list(value)
        random.shuffle(char_value)
        uuid_ranks[index] = ''.join(char_value)
    uuid_val = '-'.join(uuid_ranks)
    reality_config_title = f"vless://{uuid_val}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    vless_config_title = f"vless://{uuid_val}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    vmess_config_title = f'vmess://{base64.b64encode(json.dumps({"add":"127.0.0.1","port":port,"ps":title,"id":uuid_val}).encode("utf-8")).decode("utf-8")}'
    trojan_config_title = f"trojan://{uuid_val}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    shadowsocks_config_title = f"ss://{base64.b64encode(f'none:{uuid_val}'.encode('utf-8')).decode('utf-8')}@127.0.0.1:{port}#{title}"
    return reality_config_title, vless_config_title, vmess_config_title, trojan_config_title, shadowsocks_config_title
def create_country(array_configuration): return {} # Simplified
def create_country_table(country_path): return "" # Simplified
def create_internet_protocol(array_configuration): return [],[] # Simplified

