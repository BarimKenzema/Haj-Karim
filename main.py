# FINAL HYBRID SCRIPT v4: With Config Chunking
import os
import json
import re
import base64
import time
import traceback
from datetime import datetime, timezone, timedelta
import requests
import jdatetime

# --- Import all processing functions from your title.py ---
try:
    from title import (
        check_modify_config, config_sort, create_country, create_country_table,
        create_internet_protocol, remove_duplicate, decode_vmess, create_title
    )
    print("INFO: Successfully imported processing functions from title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing or has an error. It's required for this script. Error: {e}")
    exit(1)

# --- Configuration (from GitHub Secrets) ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 111  # Set the maximum number of configs per file

# --- Helper Functions ---
def setup_directories():
    dirs = [
        './splitted', './subscribe', './channels', './security', './protocols',
        './networks', './layers', './countries'
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
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
    except: return datetime.now(timezone.utc) - timedelta(days=7)

def find_configs_raw(text):
    if not text: return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

# --- NEW HELPER FUNCTION FOR CHUNKING ---
def write_chunked_subscription_files(base_filepath, configs, is_b64=True):
    """
    Writes a list of configs to one or more files, splitting them into
    chunks of a specified size.
    Example: ./protocols/vless -> ./protocols/vless, ./protocols/vless2, ./protocols/vless3
    """
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    
    if not configs:
        # Still create an empty base file to prevent 404 errors
        with open(base_filepath, "w") as f: f.write("")
        return

    sorted_configs = config_sort(configs)
    
    # Split the sorted configs into chunks
    chunks = [sorted_configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(sorted_configs), CONFIG_CHUNK_SIZE)]
    
    for i, chunk in enumerate(chunks):
        # Determine the filename for this chunk
        if i == 0:
            # The first file has the original name
            filepath = base_filepath
        else:
            # Subsequent files get a number suffix (e.g., vless2, vless3)
            directory, filename = os.path.split(base_filepath)
            filepath = os.path.join(directory, f"{filename}{i + 1}")

        content = "\n".join(chunk)
        if is_b64:
            content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"SUCCESS: Wrote {len(chunk)} configs to {filepath}")


def main():
    print("--- HYBRID COLLECTOR/PROCESSOR (WITH CHUNKING) START ---")
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("FATAL: Missing Telegram secrets.")
        exit(1)

    setup_directories()
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)

    all_raw_configs = set()

    # Part 1: DATA COLLECTION
    print(f"\n--- Scanning {len(channels)} Telegram channels... ---")
    try:
        from telethon.sync import TelegramClient
        from telethon.sessions import StringSession
        with TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH) as client:
            channels_to_scan = set(channels) - invalid_channels
            for i, channel in enumerate(channels_to_scan):
                try:
                    print(f"Scanning @{channel} ({i+1}/{len(channels_to_scan)})...")
                    for message in client.iter_messages(channel, limit=200):
                        if message.date < last_update: break
                        all_raw_configs.update(find_configs_raw(message.text))
                    time.sleep(2)
                except Exception as e:
                    print(f"--> ERROR scanning @{channel}: {e}")
                    invalid_channels.add(channel)
    except Exception as e:
        print(f"FATAL: Could not connect to Telegram: {e}")

    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            all_raw_configs.update(find_configs_raw(content))
        except Exception as e:
            print(f"--> ERROR fetching sub link {link}: {e}")
    
    final_configs_to_process = list(all_raw_configs)
    print(f"\n--- Found {len(final_configs_to_process)} total raw configs. Starting processing... ---")
    if not final_configs_to_process:
        print("INFO: No new configs found. Exiting.")
        with open('last update', 'w') as f: f.write(current_update.isoformat())
        return

    # Part 2: DATA PROCESSING
    print("\n--- Processing Configurations (check_connection=False for speed) ---")
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    processed = {p: [] for p in protocols}
    security = {'tls': [], 'non_tls': []}
    network = {'tcp': [], 'ws': [], 'grpc': [], 'http': []}
    
    for p in protocols:
        configs_for_proto = [c for c in final_configs_to_process if p.lower() in c.split('://')[0].lower()]
        if p == "HYSTERIA": configs_for_proto = [c for c in final_configs_to_process if c.startswith('hy')]
            
        p_mod, p_tls, p_nontls, p_tcp, p_ws, p_http, p_grpc = check_modify_config(configs_for_proto, p, check_connection=False)
        
        processed[p].extend(p_mod)
        security['tls'].extend(p_tls)
        security['non_tls'].extend(p_nontls)
        network['tcp'].extend(p_tcp)
        network['ws'].extend(p_ws)
        network['http'].extend(p_http)
        network['grpc'].extend(p_grpc)

    # Part 3: FILE WRITING (Using the new chunking function)
    print("\n--- Writing All Categorized and Chunked Subscription Files ---")
    
    # Write protocol files
    for p_name, p_configs in processed.items():
        write_chunked_subscription_files(f"./protocols/{p_name.lower()}", p_configs)

    # Write security files
    write_chunked_subscription_files("./security/tls", security['tls'])
    write_chunked_subscription_files("./security/non-tls", security['non_tls'])

    # Write network files
    for net_type, configs in network.items():
        write_chunked_subscription_files(f"./networks/{net_type}", configs)

    # Combine all processed configs for country and other mixed files
    all_processed_configs = []
    for p_configs in processed.values():
        all_processed_configs.extend(p_configs)
        
    # Write country files
    country_dict = create_country(all_processed_configs)
    for country_code, configs in country_dict.items():
        write_chunked_subscription_files(f'./countries/{country_code}/mixed', configs)
        
    # Write IPV4/IPV6 files
    ipv4_list, ipv6_list = create_internet_protocol(all_processed_configs)
    write_chunked_subscription_files('./layers/ipv4', ipv4_list)
    write_chunked_subscription_files('./layers/ipv6', ipv6_list)
    
    # Write the main mixed file
    write_chunked_subscription_files('./splitted/mixed', all_processed_configs)

    # Update helper files
    with open('invalid telegram channels.json', 'w') as f: json.dump(sorted(list(invalid_channels)), f, indent=4)
    with open('last update', 'w') as f: f.write(current_update.isoformat())
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---")
        traceback.print_exc()
        exit(1)
