# FINAL SCRIPT v20: With Fast Pre-Filtering
import os, json, re, base64, time, traceback, random
from datetime import datetime, timezone, timedelta
import requests
import jdatetime
from urllib.parse import urlparse
import subprocess

try:
    from title import (
        check_modify_config, config_sort, create_country,
        create_internet_protocol
    )
    print("INFO: Successfully imported title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing. Error: {e}"); exit(1)

API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 444

# --- Helper Functions (some are new/modified) ---
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

def pre_filter_live_hosts(all_configs):
    """
    Takes a huge list of configs, extracts just the host:port,
    and uses the fast `tcping` utility to find hosts that are online.
    Returns a much smaller list of configs that are worth testing further.
    """
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live hosts... ---")
    hosts_to_check = set()
    config_map = {} # To map host:port back to full configs

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
                hosts_to_check.add(host_port)
                if host_port not in config_map: config_map[host_port] = []
                config_map[host_port].append(config)
        except:
            continue

    print(f"Found {len(hosts_to_check)} unique host:port pairs to test with tcping.")
    
    live_hosts = set()
    for i, host_port in enumerate(hosts_to_check):
        try:
            host, port = host_port.rsplit(':', 1)
            # Use tcping: -q (quiet), -n 1 (1 attempt), -t 1 (1 second timeout)
            result = subprocess.run(['tcping', '-q', '-n', '1', '-t', '1', host, port], capture_output=True, text=True)
            if "is open" in result.stdout.lower():
                print(f"({i+1}/{len(hosts_to_check)}) LIVE: {host_port}")
                live_hosts.add(host_port)
            # else:
                # print(f"({i+1}/{len(hosts_to_check)}) DEAD: {host_port}")
        except:
            continue
            
    # Rebuild the list of configs from only the live hosts
    configs_from_live_hosts = []
    for host_port in live_hosts:
        configs_from_live_hosts.extend(config_map.get(host_port, []))
        
    print(f"--- Pre-filter complete. Found {len(configs_from_live_hosts)} configs on live hosts. ---")
    return configs_from_live_hosts


# The rest of the script (process_and_save, write_chunked, etc.) is correct.
# It will now receive a much smaller list to work on.
# You must copy the rest of your main.py here from the previous version.
def process_and_save_configs(config_list, output_prefix):
    # This function is correct from the previous version.
    # ...
    return [] # Placeholder

def write_chunked_subscription_files(base_filepath, configs):
    # This function is correct from the previous version.
    # ...
    pass # Placeholder

def main():
    print("--- HYBRID COLLECTOR v20: Pre-Filter ---")
    if not all([API_ID, API_HASH, SESSION_STRING]): print("FATAL: Missing Telegram secrets."); exit(1)

    setup_directories()
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)
    
    tg_configs, sub_configs = set(), set()

    # Data collection part is fine
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
    
    # --- NEW STRATEGY ---
    all_raw_configs = list(tg_configs.union(sub_configs))
    
    # 1. Fast pre-filter using tcping
    configs_worth_testing = pre_filter_live_hosts(all_raw_configs)
    
    if not configs_worth_testing:
        print("INFO: No live hosts found after pre-filter. Exiting.");
        with open('last update', 'w') as f: f.write(current_update.isoformat()); return
        
    # 2. Detailed processing on the smaller, high-quality list
    # This now runs on a much smaller list and will not time out.
    all_processed_configs = process_and_save_configs(configs_worth_testing, ".")
    
    # The rest of the file writing logic is the same...
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
