# FINAL SCRIPT v30: Simple & Robust
import os, json, re, base64, time, traceback, random, socket
from datetime import datetime, timezone, timedelta
import requests
import concurrent.futures
from urllib.parse import urlparse

try:
    from title import check_modify_config, config_sort, create_country, create_internet_protocol
    print("INFO: Successfully imported title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing. Error: {e}"); exit(1)

# --- Configuration ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100

# --- Helper Functions ---
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
        try:
            host, port = None, None
            parsed_url = urlparse(config)
            host, port = parsed_url.hostname, parsed_url.port
            if not host or not port:
                 if config.startswith("vmess://"):
                    json_str = config.replace("vmess://", "").strip()
                    if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                    decoded = json.loads(base64.b64decode(json_str).decode('utf-8', 'ignore'))
                    host, port = decoded.get('add'), decoded.get('port')
            if host and port:
                host_port_key = f"{host}:{port}"
                if host_port_key not in host_port_to_configs:
                    host_port_to_configs[host_port_key] = config # Only keep the first config for each host:port
        except: continue
    hosts_to_test = list(host_port_to_configs.keys())
    print(f"Found {len(hosts_to_test)} unique host:port pairs to test.")
    live_host_ports = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {executor.submit(check_host_port_with_socket, host_port): host_port for host_port in hosts_to_test}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0: print(f"Tested {i+1}/{len(hosts_to_test)} unique hosts...")
            result = future.result()
            if result: live_host_ports.add(result)
    
    unique_live_configs = [host_port_to_configs[host_port] for host_port in live_host_ports]
    print(f"--- Pre-filter complete. Kept {len(unique_live_configs)} unique, live configs. ---")
    return unique_live_configs

def write_chunked_subscription_files(base_filepath, configs):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f: f.write(""); return
    chunks = [configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(configs), CONFIG_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(os.path.dirname(base_filepath), f"{os.path.basename(base_filepath)}{i + 1}")
        content = base64.b64encode("\n".join(chunk).encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f: f.write(content)
    print(f"SUCCESS: Wrote {len(configs)} configs to {base_filepath} (and chunks if needed)")

def main():
    print("--- HYBRID COLLECTOR v30: Final Simple ---")
    setup_directories()
    # No Telethon for now, focus on subscription links which we know work
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
    
    # 1. Pre-filter to get a clean, unique, and live list
    live_unique_configs = pre_filter_live_hosts(list(all_raw_configs))
    
    if not live_unique_configs:
        print("INFO: No live configs found after filtering. Exiting."); return
        
    # 2. Process the clean list to add country data
    processed_configs, *_ = check_modify_config(live_unique_configs, "ALL", check_connection=False)
    
    # 3. Create categories from the final processed list
    print("\n--- Writing All Categorized Subscription Files ---")
    
    # By Protocol
    protocols = ["VLESS", "VMESS", "TROJAN", "SHADOWSOCKS", "REALITY", "HYSTERIA", "TUIC", "JUICITY"]
    for p in protocols:
        p_configs = []
        if p == "VLESS": p_configs = [c for c in processed_configs if c.startswith('vless://') and 'reality' not in c]
        elif p == "REALITY": p_configs = [c for c in processed_configs if c.startswith('vless://') and 'security=reality' in c]
        elif p == "HYSTERIA": p_configs = [c for c in processed_configs if c.startswith('hy')]
        else: p_configs = [c for c in processed_configs if c.startswith(p.lower())]
        write_chunked_subscription_files(f"./protocols/{p.lower()}", p_configs)

    # By Country
    country_dict = create_country(processed_configs)
    for code, configs in country_dict.items():
        write_chunked_subscription_files(f'./countries/{code}/mixed', configs)
        
    # By IP Version
    ipv4, ipv6 = create_internet_protocol(processed_configs)
    write_chunked_subscription_files('./layers/ipv4', ipv4)
    write_chunked_subscription_files('./layers/ipv6', ipv6)
    
    # Write the main mixed file
    write_chunked_subscription_files('./splitted/mixed', processed_configs)
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
