# FINAL SCRIPT v35: Simplified & Direct Logic
import os, json, re, base64, time, traceback, random, socket
from datetime import datetime, timezone, timedelta
import requests
import jdatetime
from urllib.parse import urlparse
import concurrent.futures

try:
    from title import (
        check_modify_config, config_sort, create_country,
        create_internet_protocol
    )
    print("INFO: Successfully imported title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing. Error: {e}"); exit(1)

# --- Configuration ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100

# --- Helper Functions (These are all correct) ---
def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './channels', './security', './protocols', './networks', './layers', './countries']
    for d in dirs:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d)
    print("INFO: All necessary directories are present.")

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
            main_part = config.split("://")[1]
            if '@' in main_part:
                host_port_part = main_part.split('@')[1].split('#')[0]
                if ':' in host_port_part: return host_port_part.rsplit(':', 1)
            else:
                decoded_part = base64.b64decode(main_part.split('#')[0]).decode('utf-8', 'ignore')
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
            from title import get_ips
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

def write_chunked_subscription_files(base_filepath, configs):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f: f.write(""); return
    from title import config_sort
    sorted_configs = config_sort(configs)
    chunks = [sorted_configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(sorted_configs), CONFIG_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(os.path.dirname(base_filepath), f"{os.path.basename(base_filepath)}{i + 1}")
        content = base64.b64encode("\n".join(chunk).encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f: f.write(content)

def main():
    print("--- HYBRID COLLECTOR v35: Simplified Logic ---")
    setup_directories()
    # For now, let's focus only on subscription links as they are the reliable source.
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

    # --- NEW, SIMPLIFIED PROCESSING AND WRITING LOGIC ---
    print("\n--- Starting Final Categorization and Writing ---")
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    
    # These dictionaries will hold the final, fully processed configs
    all_processed_configs = []
    
    for p in protocols:
        # Step 1: Filter raw configs for the current protocol
        configs_for_proto = []
        if p == "VLESS": configs_for_proto = [c for c in live_unique_configs if c.startswith('vless://') and 'reality' not in c]
        elif p == "REALITY": configs_for_proto = [c for c in live_unique_configs if c.startswith('vless://') and 'security=reality' in c]
        elif p == "HYSTERIA": configs_for_proto = [c for c in live_unique_configs if c.startswith('hy')]
        else: configs_for_proto = [c for c in live_unique_configs if c.startswith(p.lower())]

        if not configs_for_proto:
            print(f"No live configs for {p}, creating empty files.")
            # Create empty files for this protocol to avoid 404s
            write_chunked_subscription_files(f"./protocols/{p.lower()}", [])
            continue

        # Step 2: Process this batch to get final names and sub-categories
        p_mod, p_tls, p_nontls, p_tcp, p_ws, p_http, p_grpc = check_modify_config(configs_for_proto, p, check_connection=True)
        
        # Step 3: Write the files for this protocol immediately
        print(f"--- Writing files for {p} ---")
        write_chunked_subscription_files(f"./protocols/{p.lower()}", p_mod)
        write_chunked_subscription_files("./security/tls", p_tls)
        write_chunked_subscription_files("./security/non-tls", p_nontls)
        write_chunked_subscription_files("./networks/tcp", p_tcp)
        write_chunked_subscription_files("./networks/ws", p_ws)
        write_chunked_subscription_files("./networks/http", p_http)
        write_chunked_subscription_files("./networks/grpc", p_grpc)
        
        # Add the processed configs to our final master list
        all_processed_configs.extend(p_mod)

    # --- Now create the combined files from the master list ---
    print(f"\n--- Writing Combined and Global Category Files ---")
    
    # Write country files
    country_dict = create_country(all_processed_configs)
    print(f"--- Writing {len(country_dict)} country-specific files... ---")
    for country_code, configs in country_dict.items():
        write_chunked_subscription_files(f'./countries/{country_code}/mixed', configs)
        
    # Write IP Version files
    ipv4_list, ipv6_list = create_internet_protocol(all_processed_configs)
    write_chunked_subscription_files('./layers/ipv4', ipv4_list)
    write_chunked_subscription_files('./layers/ipv6', ipv6_list)
    
    # Write main mixed file
    write_chunked_subscription_files('./splitted/mixed', all_processed_configs)
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
