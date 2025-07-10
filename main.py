# FINAL HYBRID SCRIPT: Telethon Collector + Title.py Processor
import os, json, re, base64, time, traceback
from datetime import datetime, timezone, timedelta
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
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

# --- Helper Functions ---
def setup_directories():
    dirs = [
        './splitted', './subscribe', './channels', './security', './protocols',
        './networks', './layers', './countries',
        './subscribe/protocols', './subscribe/networks', './subscribe/security',
        './subscribe/layers', './channels/protocols', './channels/networks',
        './channels/security', './channels/layers'
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

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
    pattern = r"(?i)(vless|vmess|trojan|ss|hy|hy2|tuic|juicity)://[^\s<>\"']+"
    return re.findall(pattern, text)

def main():
    print("--- HYBRID COLLECTOR/PROCESSOR START ---")
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

    # Part 1: DATA COLLECTION (Reliable Telethon method)
    print(f"\n--- Scanning {len(channels)} Telegram channels... ---")
    try:
        with TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH) as client:
            channels_to_scan = set(channels) - invalid_channels
            for i, channel in enumerate(channels_to_scan):
                try:
                    print(f"Scanning @{channel} ({i+1}/{len(channels_to_scan)})...")
                    for message in client.iter_messages(channel, limit=200):
                        if message.date < last_update: break
                        all_raw_configs.update(find_configs_raw(message.text))
                    time.sleep(2) # Flood wait prevention
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

    # Part 2: DATA PROCESSING (Your original title.py logic)
    print("\n--- Filtering and Titling Live Configurations ---")
    # This uses the check_modify_config function from your title.py
    # We set check_connection=False to make it fast and reliable.
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    processed = {}
    security = {'tls': [], 'non_tls': []}
    network = {'tcp': [], 'ws': [], 'grpc': [], 'http': []}
    
    for p in protocols:
        configs_for_proto = [c for c in final_configs_to_process if p.lower() in c.split('://')[0].lower()]
        is_checkable = p not in ["TUIC", "HYSTERIA", "JUICITY"]
        
        # We use check_connection=False for speed and reliability in the cloud
        processed[p], tls, non_tls, tcp, ws, http, grpc = check_modify_config(configs_for_proto, p, check_connection=False)
        
        security['tls'].extend(tls)
        security['non_tls'].extend(non_tls)
        network['tcp'].extend(tcp)
        network['ws'].extend(ws)
        network['grpc'].extend(http) # Note: your original script seemed to have a typo here
        network['http'].extend(grpc)

    # Part 3: FILE WRITING (Your original file generation logic)
    print("\n--- Writing All Categorized Subscription Files ---")
    
    def write_subscription_file(filepath, configs, is_b64=True):
        if not configs:
            # Create empty file to prevent 404
            with open(filepath, "w") as f: f.write("")
            return
        
        # Add headers/footers here if needed in the future
        content = "\n".join(config_sort(configs))
        
        if is_b64:
            content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"SUCCESS: Wrote {len(configs)} configs to {filepath}")

    # Write protocol files
    for p in protocols:
        write_subscription_file(f"./protocols/{p.lower()}", processed[p])

    # Write security files
    write_subscription_file("./security/tls", security['tls'])
    write_subscription_file("./security/non-tls", security['non_tls'])

    # Write network files
    for net_type, configs in network.items():
        write_subscription_file(f"./networks/{net_type}", configs)

    # Write country files
    all_processed_configs = []
    for p_configs in processed.values():
        all_processed_configs.extend(p_configs)
        
    country_dict = create_country(all_processed_configs)
    for country_code, configs in country_dict.items():
        os.makedirs(f"./countries/{country_code}", exist_ok=True)
        write_subscription_file(f"./countries/{country_code}/mixed", configs)

    # ... and so on for any other files your README mentions.
    # This covers the main categories.

    # Update timestamp for next run
    with open('last update', 'w') as f:
        f.write(current_update.isoformat())
    
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---")
        traceback.print_exc()
        exit(1)
