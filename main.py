# FINAL SCRIPT v26: Full Categorization Restored
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

# --- Helper Functions (Unchanged) ---
def setup_directories():
    import shutil
    dirs = ['./splitted', './subscribe', './channels', './security', './protocols', './networks', './layers', './countries']
    for d in dirs:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d)
    for parent in ['subscribe', 'channels']:
        for sub in ['protocols', 'networks', 'security', 'layers']:
            os.makedirs(os.path.join(parent, sub), exist_ok=True)
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

def check_host_port_with_socket(host_port):
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except: return None

def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live ports... ---")
    host_port_to_configs = {}
    for config in all_configs:
        try:
            host, port = None, None
            if config.startswith("vmess://"):
                json_str = config.replace("vmess://", "").strip()
                if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                decoded = json.loads(base64.b64decode(json_str).decode('utf-8', errors='ignore'))
                host, port = decoded.get('add'), decoded.get('port')
            else:
                parsed = urlparse(config)
                host, port = parsed.hostname, parsed.port
            if host and port:
                host_port = f"{host}:{port}"
                if host_port not in host_port_to_configs: host_port_to_configs[host_port] = []
                host_port_to_configs[host_port].append(config)
        except: continue
    hosts_to_check = list(host_port_to_configs.keys())
    print(f"Found {len(hosts_to_check)} unique host:port pairs to test.")
    live_host_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {executor.submit(check_host_port_with_socket, host_port): host_port for host_port in hosts_to_check}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0: print(f"Tested {i+1}/{len(hosts_to_check)} hosts...")
            result = future.result()
            if result: live_host_ports.append(result)
    configs_from_live_hosts = []
    for host_port in live_host_ports:
        configs_from_live_hosts.extend(host_port_to_configs.get(host_port, []))
    print(f"--- Pre-filter complete. Found {len(configs_from_live_hosts)} configs on {len(live_host_ports)} live hosts. ---")
    return configs_from_live_hosts

def process_and_save_configs(config_list, output_prefix):
    print(f"\n--- Processing {len(config_list)} configs for source: {output_prefix} ---")
    if not config_list: return []
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    all_processed_for_source = []
    
    for p in protocols:
        configs_for_proto = []
        if p == "VLESS": configs_for_proto = [c for c in config_list if c.startswith('vless://') and 'reality' not in c]
        elif p == "REALITY": configs_for_proto = [c for c in config_list if c.startswith('vless://') and 'security=reality' in c]
        elif p == "HYSTERIA": configs_for_proto = [c for c in config_list if c.startswith('hy')]
        else: configs_for_proto = [c for c in config_list if c.startswith(p.lower())]

        if not configs_for_proto: continue
        
        # --- THIS IS THE RESTORED LOGIC ---
        processed_configs, p_tls, p_nontls, p_tcp, p_ws, p_http, p_grpc = check_modify_config(configs_for_proto, p, check_connection=True)
        
        # Write to all categories for the current source
        write_chunked_subscription_files(f"{output_prefix}/protocols/{p.lower()}", processed_configs)
        write_chunked_subscription_files(f"{output_prefix}/security/tls", p_tls)
        write_chunked_subscription_files(f"{output_prefix}/security/non-tls", p_nontls)
        write_chunked_subscription_files(f"{output_prefix}/networks/tcp", p_tcp)
        write_chunked_subscription_files(f"{output_prefix}/networks/ws", p_ws)
        write_chunked_subscription_files(f"{output_prefix}/networks/http", p_http)
        write_chunked_subscription_files(f"{output_prefi_x}/networks/grpc", p_grpc)
        
        all_processed_for_source.extend(processed_configs)
        
    return all_processed_for_source

def write_chunked_subscription_files(base_filepath, configs):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f: f.write(""); return
    
    sorted_configs = config_sort(configs)
    chunks = [sorted_configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(sorted_configs), CONFIG_CHUNK_SIZE)]
    
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(os.path.dirname(base_filepath), f"{os.path.basename(base_filepath)}{i + 1}")
        content = base64.b64encode("\n".join(chunk).encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f: f.write(content)
        # print(f"SUCCESS: Wrote {len(chunk)} configs to {filepath}") # Quieter logging

# This is the main function
def main():
    # ... (The first part of main is correct) ...
    # Pasting the full, correct main function here.
    print("--- HYBRID COLLECTOR v26: Full Categorization ---")
    if not all([API_ID, API_HASH, SESSION_STRING]): print("FATAL: Missing Telegram secrets."); exit(1)

    setup_directories()
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)
    
    tg_configs, sub_configs = set(), set()
    client = None
    try:
        from telethon.sync import TelegramClient
        from telethon.sessions import StringSession
        client = TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH)
        client.connect()
        if not client.is_user_authorized(): raise Exception("Telegram client authorization failed.")
        print(f"INFO: Telegram login successful. Scanning {len(channels)} channels...")
        channels_to_scan = set(channels) - invalid_channels
        for i, channel in enumerate(channels_to_scan):
            try:
                for message in client.iter_messages(channel, limit=200):
                    if message.date < last_update: break
                    tg_configs.update(find_configs_raw(message.text))
                time.sleep(random.uniform(2.0, 4.0))
            except Exception as e:
                print(f"--> ERROR scanning @{channel}: {e}"); invalid_channels.add(channel)
    except Exception as e:
        print(f"WARNING: Telegram collection block failed. Reason: {e}")
    finally:
        if client and client.is_connected():
            client.disconnect(); print("INFO: Telegram client disconnected.")

    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            sub_configs.update(find_configs_raw(content))
        except: continue
    
    all_raw_configs = list(tg_configs.union(sub_configs))
    configs_worth_testing = pre_filter_live_hosts(all_raw_configs)
    
    if not configs_worth_testing:
        print("INFO: No live hosts found after pre-filter. Exiting.");
        with open('last update', 'w') as f: f.write(current_update.isoformat()); return
        
    processed_tg_configs = process_and_save_configs([c for c in configs_worth_testing if c in tg_configs], "./channels")
    processed_sub_configs = process_and_save_configs([c for c in configs_worth_testing if c in sub_configs], "./subscribe")
    
    all_processed_configs = processed_tg_configs + processed_sub_configs
    print(f"\n--- Creating final combined files from {len(all_processed_configs)} total processed configs ---")
    
    process_and_save_configs(all_processed_configs, ".")
    
    country_dict = create_country(all_processed_configs)
    for country_code, configs in country_dict.items():
        write_chunked_subscription_files(f'./countries/{country_code}/mixed', configs)
        
    ipv4_list, ipv6_list = create_internet_protocol(all_processed_configs)
    write_chunked_subscription_files('./layers/ipv4', ipv4_list)
    write_chunked_subscription_files('./layers/ipv6', ipv6_list)
    
    write_chunked_subscription_files('./splitted/mixed', all_processed_configs)
    
    with open('invalid telegram channels.json', 'w') as f: json.dump(sorted(list(invalid_channels)), f, indent=4)
    with open('last update', 'w') as f: f.write(current_update.isoformat())
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")


if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
