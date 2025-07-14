# FINAL SCRIPT v37: All Functions Restored
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

print("--- SINGLE-FILE COLLECTOR/PROCESSOR v37 START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100

# --- HELPER FUNCTIONS (NOW CORRECTLY INCLUDED) ---

def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './channels', './security', './protocols', './networks', './layers', './countries']
    for d in dirs:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d)
    print("INFO: All necessary directories are clean.")

def json_load_safe(path):
    try:
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    except: return []

def get_last_update(path):
    try:
        with open(path, 'r') as f: return datetime.fromisoformat(f.read().strip())
    except: return datetime.now(timezone.utc) - timedelta(days=3)

def find_configs_raw(text):
    if not text: return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

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
                host_port_part = main_part.split('@')[1]
                if ':' in host_port_part: return host_port_part.rsplit(':', 1)
            else:
                decoded_part = base64.b64decode(main_part).decode('utf-8', 'ignore')
                host_port_part = decoded_part.split('@')[1]
                if ':' in host_port_part: return host_port_part.rsplit(':', 1)
        else:
            parsed = urlparse(config)
            return parsed.hostname, parsed.port
    except: return None, None
    return None, None

def check_host_port_with_socket(host_port):
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except: return None

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
            country_code = get_country_from_ip(ip_address)
            fragment = f"#{country_code}-{host}"
            new_config = urlparse(element)._replace(fragment=fragment).geturl()
            processed_configs.append(new_config)
        except: continue
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

def create_country(configs):
    country_dict = {}
    for config in configs:
        try:
            fragment = urlparse(config).fragment
            country_code = fragment.split('-')[0].lower()
            if country_code:
                if country_code not in country_dict: country_dict[country_code] = []
                country_dict[country_code].append(config)
        except: continue
    return country_dict

def main():
    print("--- SINGLE-FILE COLLECTOR v37 ---")
    setup_directories()
    # Focusing only on subscription links
    all_raw_configs = set()
    subs_links = json_load_safe('subscription links.json')
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            all_raw_configs.update(find_configs_raw(content))
        except: continue
    
    live_unique_configs = pre_filter_live_hosts(list(all_raw_configs))
    if not live_unique_configs:
        print("INFO: No live configs found after filtering. Exiting."); return
        
    final_configs = process_configs(live_unique_configs)

    print("\n--- Writing All Categorized Files ---")
    
    # Dictionaries to hold categorized configs
    by_protocol = {p: [] for p in ["vless", "vmess", "trojan", "ss", "hysteria", "tuic", "juicity", "reality"]}
    by_security = {'tls': [], 'non_tls': []}
    by_network = {'tcp': [], 'ws': [], 'grpc': [], 'http': []}
    by_country = create_country(final_configs)

    for config in final_configs:
        try:
            proto = config.split('://')[0]
            if proto == 'vless' and 'reality' in config: by_protocol['reality'].append(config)
            elif proto in by_protocol: by_protocol[proto].append(config)
            elif proto == 'hy2': by_protocol['hysteria'].append(config)

            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            sec = params.get('security', ['NA'])[0].lower()
            net = params.get('type', ['tcp'])[0].lower()
            if 'tls' in sec or 'reality' in sec: by_security['tls'].append(config)
            else: by_security['non-tls'].append(config)
            if net in by_network: by_network[net].append(config)
        except: continue

    for p, clist in by_protocol.items(): write_chunked_subscription_files(f'./protocols/{p}', clist)
    for s, clist in by_security.items(): write_chunked_subscription_files(f'./security/{s}', clist)
    for n, clist in by_network.items(): write_chunked_subscription_files(f'./networks/{n}', clist)
    for c, clist in by_country.items(): write_chunked_subscription_files(f'./countries/{c}/mixed', clist)
    write_chunked_subscription_files('./splitted/mixed', final_configs)
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
