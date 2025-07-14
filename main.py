# FINAL SCRIPT v36: Self-Contained, Single-File Solution
import os, json, re, base64, time, traceback, random, socket, uuid, ipaddress
from datetime import datetime, timezone, timedelta
import requests
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import pycountry_convert as pc
import tldextract
import geoip2.database
from dns import resolver, rdatatype
import html
import jdatetime

print("--- SINGLE-FILE COLLECTOR/PROCESSOR START ---")

# --- CONFIGURATION ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100

# --- ALL HELPER FUNCTIONS ARE NOW INSIDE THIS FILE ---

def is_valid_uuid(v):
    try: uuid.UUID(str(v)); return True
    except: return False

def get_ips(node):
    try:
        if not node or not isinstance(node, str): return None
        if ipaddress.ip_address(node): return [node]
    except:
        try:
            res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
            return [str(rdata) for rdata in res.resolve(node, 'A', raise_on_no_answer=False) or []] + \
                   [str(rdata) for rdata in res.resolve(node, 'AAAA', raise_on_no_answer=False) or []] or None
        except: return None
    return None

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
    
def get_host_port_from_config(config):
    try:
        if config.startswith("vmess://"):
            json_str = config.replace("vmess://", "").strip()
            if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
            decoded = json.loads(base64.b64decode(json_str).decode('utf-8', 'ignore'))
            return decoded.get('add'), decoded.get('port')
        elif config.startswith("ss://"):
            main_part = config.split("://")[1].split('#')[0]
            if '@' in main_part:
                return main_part.split('@')[1].rsplit(':', 1)
            else:
                decoded_part = base64.b64decode(main_part).decode('utf-8', 'ignore')
                return decoded_part.split('@')[1].rsplit(':', 1)
        else:
            parsed = urlparse(config)
            return parsed.hostname, parsed.port
    except: return None, None

def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live hosts... ---")
    host_port_to_configs = {}
    for config in all_configs:
        host, port = get_host_port_from_config(config)
        if host and port:
            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]
            host_port_key = f"{ip_address}:{port}"
            if host_port_key not in host_port_to_configs:
                host_port_to_configs[host_port_key] = config
    
    hosts_to_test = list(host_port_to_configs.keys())
    print(f"Found {len(hosts_to_test)} unique IP:port pairs to test.")
    live_host_ports = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {executor.submit(check_host_port_with_socket, host_port): host_port for host_port in hosts_to_test}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0: print(f"Tested {i+1}/{len(hosts_to_test)} unique hosts...")
            result = future.result()
            if result: live_host_ports.add(result)
    
    unique_live_configs = [host_port_to_configs[host_port] for host_port in live_host_ports if host_port in host_port_to_configs]
    print(f"--- Pre-filter complete. Kept {len(unique_live_configs)} unique, live configs. ---")
    return unique_live_configs

def process_configs(configs_to_process):
    print(f"\n--- Processing {len(configs_to_process)} live configs to add titles... ---")
    processed_configs = []
    for element in configs_to_process:
        try:
            host, port = get_host_port_from_config(element)
            if not host or not port: continue
            
            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]

            ping = ping_ip_address(ip_address, int(port))
            if ping > 2000: continue

            country_code = get_country_from_ip(ip_address)
            country_flag = get_country_flag(country_code)
            ip_display = f"[{ip_address}]" if ":" in ip_address else ip_address
            
            parsed_url = urlparse(element)
            params = parse_qs(parsed_url.query)
            config_type = params.get('type', ['tcp'])[0].upper()
            config_secrt = params.get('security', ['NA'])[0].upper()
            proto = element.split("://")[0]
            
            if proto == 'vless' and 'reality' in element: proto_code = "VL-RLT"
            else: proto_code = {"vless":"VL","trojan":"TR","vmess":"VM","ss":"SS","hysteria":"HY","hy2":"HY","tuic":"TU","juicity":"JU"}.get(proto, "UN")

            title = f"\U0001F512 {proto_code}-{config_type}-{config_secrt} {country_flag}{country_code}-{ip_display}:{port} \U0001F4E1 PING-{ping:06.2f}-MS"
            
            if proto == "vmess":
                json_str = element.replace("vmess://", "").strip()
                if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                config_dict = json.loads(base64.b64decode(json_str).decode('utf-8', 'ignore'))
                config_dict['ps'] = title
                config_dict['add'] = ip_address
                processed_configs.append(f"vmess://{base64.b64encode(json.dumps(config_dict).encode('utf-8')).decode('utf-8')}")
            else:
                processed_configs.append(parsed_url._replace(fragment=title).geturl())
        except:
            continue
    print(f"--- Finished processing. Final count: {len(processed_configs)} ---")
    return processed_configs

def write_chunked_subscription_files(base_filepath, configs):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f: f.write(""); return
    
    chunks = [configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(configs), CONFIG_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(os.path.dirname(base_filepath), f"{os.path.basename(base_filepath)}{i + 1}")
        content = base64.b64encode("\n".join(chunk).encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f: f.write(content)
        # print(f"SUCCESS: Wrote {len(chunk)} configs to {filepath}")

def main():
    print("--- SINGLE-FILE COLLECTOR v36 ---")
    # No Telethon for this run to guarantee completion
    subs_links = json_load_safe('subscription links.json')
    if not subs_links: print("FATAL: 'subscription links.json' is empty."); return

    all_raw_configs = set()
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            all_raw_configs.update(find_configs_raw(content))
        except: continue
    
    live_unique_configs = pre_filter_live_hosts(list(all_raw_configs))
    if not live_unique_configs: print("INFO: No live configs found. Exiting."); return
        
    final_configs = process_configs(live_unique_configs)

    # --- FINAL WRITING LOGIC ---
    print("\n--- Writing All Categorized Files ---")
    
    # Dictionaries to hold categorized configs
    by_protocol = {p: [] for p in ["vless", "vmess", "trojan", "ss", "hysteria", "tuic", "juicity", "reality"]}
    by_security = {'tls': [], 'non-tls': []}
    by_network = {'tcp': [], 'ws': [], 'grpc': [], 'http': []}
    by_country = {}

    for config in final_configs:
        try:
            # Categorize by Protocol
            proto = config.split('://')[0]
            if proto == 'vless' and 'reality' in config: by_protocol['reality'].append(config)
            elif proto in by_protocol: by_protocol[proto].append(config)
            elif proto == 'hy2': by_protocol['hysteria'].append(config)

            # Categorize by Security and Network
            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            sec = params.get('security', ['NA'])[0].lower()
            net = params.get('type', ['tcp'])[0].lower()
            if 'tls' in sec or 'reality' in sec: by_security['tls'].append(config)
            else: by_security['non-tls'].append(config)
            if net in by_network: by_network[net].append(config)

            # Categorize by Country
            country_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}\s*([a-z]{2})-', config)
            if country_match:
                code = country_match.group(1)
                if code not in by_country: by_country[code] = []
                by_country[code].append(config)
        except:
            continue

    # Write all the files
    for p, clist in by_protocol.items(): write_chunked_subscription_files(f'./protocols/{p}', clist)
    for s, clist in by_security.items(): write_chunked_subscription_files(f'./security/{s}', clist)
    for n, clist in by_network.items(): write_chunked_subscription_files(f'./networks/{n}', clist)
    for c, clist in by_country.items(): write_chunked_subscription_files(f'./countries/{c}/mixed', clist)
    write_chunked_subscription_files('./splitted/mixed', final_configs)
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
