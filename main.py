# FILE: main.py (for your FIRST repo: v2ray-collector)
# FINAL SCRIPT v38-S1-FULL-RESTORED: All Features and Categorization Combined

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import geoip2.database
from dns import resolver

print("--- BASE COLLECTOR & PRE-FILTERER v38-S1-FULL-RESTORED START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 44444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')

# --- YOUR CUSTOM GITHUB SCRAPING FUNCTION (PRESERVED) ---
def fetch_from_github():
    print("--- Fetching configs from GitHub with enhanced search queries ---")
    if not COLLECTOR_TOKEN:
        print("WARNING: COLLECTOR_TOKEN secret not found or empty. Skipping GitHub scrape.")
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'}
    
    queries = [
        '"vless" "کانفیگ" "رایگان"', '"vmess" "ایرانسل"', '"trojan" "همراه اول"',
        '"v2ray" "رایتل"', 'filename:subscribe "v2ray" "ایران"', 'path:config "vless" "رایگان"',
        '"ss://"', '"reality" "کانفیگ"', 'filename:all.txt "vmess://"', 'path:nodes "vless://"'
    ]
    
    for query in queries:
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6) # Avoid hitting the search API rate limit
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            items = res.json().get('items', [])
            print(f"Found {len(items)} potential files on GitHub for query: '{query}'.")
            
            for item in items:
                time.sleep(0.5) # Avoid hitting the content API rate limit
                raw_url = item.get('url')
                try:
                    content_res = requests.get(raw_url, headers=headers, timeout=10)
                    if content_res.status_code == 200:
                        content = content_res.text
                        if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                            try: content = base64.b64decode(content).decode('utf-8', 'ignore')
                            except Exception: pass
                        found_in_file = find_configs_raw(content)
                        if found_in_file: configs.update(found_in_file)
                except Exception:
                    continue
        except Exception as e:
            print(f"ERROR: Failed to fetch from GitHub with query '{query}': {e}")
            if 'rate limit' in str(e).lower():
                print("--- GitHub API rate limit likely exceeded. Sleeping for 60 seconds. ---")
                time.sleep(60)
            continue

    print(f"Found {len(configs)} new unique configs from GitHub.")
    return configs

# --- HELPER FUNCTIONS ---
def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './protocols', './networks', './countries', './security']
    for d in dirs:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d)
    print("INFO: All necessary directories are clean.")

def json_load_safe(path):
    try:
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    except: return []

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
        else:
            parsed = urlparse(config)
            return parsed.hostname, parsed.port
    except: return None, None

def get_ips(node):
    try:
        if not node or not isinstance(node, str): return None
        if ipaddress.ip_address(node): return [node]
    except ValueError:
        try:
            res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
            return [str(rdata) for rdata in res.resolve(node, 'A', raise_on_no_answer=False) or []] or None
        except: return None
    return None

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

def get_country_from_ip(ip, geoip_reader):
    if not geoip_reader: return "XX"
    try: return geoip_reader.country(ip).country.iso_code or "XX"
    except: return "XX"

def process_configs(configs_to_process, geoip_reader):
    processed_configs = []; print(f"\n--- Processing {len(configs_to_process)} live configs... ---")
    for element in configs_to_process:
        try:
            host, port = get_host_port_from_config(element)
            if not host or not port: continue
            ips = get_ips(host);
            if not ips: continue
            country_code = get_country_from_ip(ips[0], geoip_reader)
            processed_configs.append(urlparse(element)._replace(fragment=f"#{country_code}-{host}").geturl())
        except: continue
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

# --- MAIN EXECUTION ---
def main():
    setup_directories()

    all_raw_configs = set()
    print("--- Collecting from subscription links.json ---")
    subs_links = json_load_safe('subscription links.json')
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                try: content = base64.b64decode(content).decode('utf-8', 'ignore')
                except: pass
            all_raw_configs.update(find_configs_raw(content))
        except: continue
    print(f"Found {len(all_raw_configs)} configs from local subscription file.")
    
    all_raw_configs.update(fetch_from_github())
    print(f"--- Total unique configs from all sources: {len(all_raw_configs)} ---")
    
    live_unique_configs = pre_filter_live_hosts(list(all_raw_configs))
    if not live_unique_configs:
        print("INFO: No live configs found after filtering. Exiting."); return
        
    with open('filtered-for-refiner.txt', 'w', encoding='utf-8') as f:
        for config in live_unique_configs: f.write(config + '\n')
    print(f"--- Saved {len(live_unique_configs)} pre-filtered configs to filtered-for-refiner.txt ---")
    
    print("\n--- Searching for REALITY+gRPC configs from the live set... ---")
    reality_grpc_configs = []
    for config in live_unique_configs:
        text_to_check = ""
        if config.startswith("vmess://"):
            try:
                json_str = config.replace("vmess://", "").strip()
                if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                text_to_check = base64.b64decode(json_str).decode('utf-8', 'ignore')
            except Exception: continue
        else:
            text_to_check = config
        
        if "reality" in text_to_check.lower() and "grpc" in text_to_check.lower():
            reality_grpc_configs.append(config)

    if reality_grpc_configs:
        with open('reality-grpc-configs.txt', 'w', encoding='utf-8') as f:
            for cfg in reality_grpc_configs: f.write(cfg + '\n')
        print(f"--- Found and saved {len(reality_grpc_configs)} REALITY+gRPC configs to reality-grpc-configs.txt ---")
    else:
        print("--- No live REALITY+gRPC configs were found. ---")
    
    print("\n--- Starting full categorization for this repo's output files... ---")
    db_path = "./geoip.mmdb"
    if not os.path.exists(db_path):
        try:
            r = requests.get("https://git.io/GeoLite2-Country.mmdb", allow_redirects=True)
            with open(db_path, 'wb') as f: r.raise_for_status(); f.write(r.content)
            print("INFO: GeoIP database downloaded successfully.")
        except Exception: db_path = None; print("ERROR: Could not download GeoIP database.")
    
    geoip_reader = None
    if db_path:
        try: geoip_reader = geoip2.database.Reader(db_path)
        except Exception: pass
    
    final_configs = process_configs(live_unique_configs, geoip_reader)
    
    print("\n--- Performing Full Categorization ---")
    by_protocol = {p: [] for p in ["vless", "vmess", "trojan", "ss", "reality"]}
    by_network = {'tcp': [], 'ws': [], 'grpc': [], 'http': []}
    by_security = {'tls': [], 'non_tls': []}
    by_country = {}

    for config in final_configs:
        try:
            proto = config.split('://')[0]
            if proto in by_protocol: by_protocol[proto].append(config)
            if 'reality' in config.lower(): by_protocol['reality'].append(config)

            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            
            net = params.get('type', ['tcp'])[0].lower()
            if net in by_network: by_network[net].append(config)
            
            sec = params.get('security', ['none'])[0].lower()
            if 'tls' in sec or 'reality' in sec: by_security['tls'].append(config)
            else: by_security['non_tls'].append(config)

            country_code = parsed.fragment.split('-')[0].lower()
            if country_code:
                if country_code not in by_country: by_country[country_code] = []
                by_country[country_code].append(config)
        except Exception: continue

    print("\n--- Writing All Categorized Subscription Files ---")
    for p, clist in by_protocol.items(): write_chunked_subscription_files(f'./protocols/{p}', clist)
    for n, clist in by_network.items(): write_chunked_subscription_files(f'./networks/{n}', clist)
    for s, clist in by_security.items(): write_chunked_subscription_files(f'./security/{s}', clist)
    for c, clist in by_country.items(): write_chunked_subscription_files(f'./countries/{c}', clist)
    write_chunked_subscription_files('./splitted/mixed', final_configs)
    
    print("\n--- COLLECTOR SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(f"\n--- FATAL UNHANDLED ERROR ---")
        traceback.print_exc()
        exit(1)
