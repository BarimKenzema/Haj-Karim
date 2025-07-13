# FINAL SCRIPT v23: Python-based Pre-Filtering
import os, json, re, base64, time, traceback, random
from datetime import datetime, timezone, timedelta
import requests
import jdatetime
from urllib.parse import urlparse
import concurrent.futures

try:
    from title import check_modify_config, config_sort, create_country, create_internet_protocol
    print("INFO: Successfully imported title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing. Error: {e}"); exit(1)

# NEW: Import the Python-based ping library
try:
    from tcp_latency import measure_latency
except ImportError:
    print("FATAL: 'python-tcp-ping' not installed. Please add it to requirements.txt"); exit(1)

API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100 # We can use more workers with this library

def setup_directories():
    import shutil
    dirs_to_recreate = ['./splitted', './subscribe', './channels', './security', './protocols', './networks', './layers', './countries']
    for d in dirs_to_recreate:
        if os.path.exists(d): shutil.rmtree(d)
        os.makedirs(d)
    for parent in ['subscribe', 'channels']:
        for sub in ['protocols', 'networks', 'security', 'layers']:
            os.makedirs(os.path.join(parent, sub), exist_ok=True)
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

def check_host_with_py_ping(host_port):
    """
    Checks a single host:port using the python-tcp-ping library.
    Returns the host_port if live, otherwise None.
    """
    try:
        host, port = host_port.rsplit(':', 1)
        port = int(port)
        # Runs 1 test, with a 1-second timeout.
        latency = measure_latency(host=host, port=port, runs=1, timeout=1.0)
        if latency:
            # The library returns a list, we take the first result
            print(f"LIVE: {host_port} | Latency: {latency[0]:.2f}ms")
            return host_port
    except (ValueError, IndexError): # Handles bad ports or results
        pass
    except Exception: # Catch all other errors
        pass
    return None

def pre_filter_live_hosts(all_configs):
    """
    Uses the reliable python-tcp-ping library to find live hosts in parallel.
    """
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
        future_to_host = {executor.submit(check_host_with_py_ping, host_port): host_port for host_port in hosts_to_check}
        for future in concurrent.futures.as_completed(future_to_host):
            result = future.result()
            if result:
                live_host_ports.append(result)
            
    configs_from_live_hosts = []
    for host_port in live_host_ports:
        configs_from_live_hosts.extend(host_port_to_configs.get(host_port, []))
        
    print(f"--- Pre-filter complete. Found {len(configs_from_live_hosts)} configs on {len(live_host_ports)} live hosts. ---")
    return configs_from_live_hosts

def main():
    print("--- HYBRID COLLECTOR v23: Python Ping Pre-Filter ---")
    # ... (The rest of the main function is correct and does not need to be changed) ...
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
    from title import process_and_save_configs, create_country, create_internet_protocol
    all_processed_configs = process_and_save_configs(configs_worth_testing, ".")
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
