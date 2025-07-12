# FINAL HYBRID SCRIPT v12: The True Ultimate Fix
import os, json, re, base64, time, traceback, random
from datetime import datetime, timezone, timedelta
import requests
import jdatetime

try:
    from title import (
        check_modify_config, config_sort, create_country,
        create_internet_protocol
    )
    print("INFO: Successfully imported processing functions from title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing. Error: {e}"); exit(1)

API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')
CONFIG_CHUNK_SIZE = 111

def setup_directories():
    dirs = ['./splitted', './subscribe', './channels', './security', './protocols', './networks', './layers', './countries']
    for d in dirs: os.makedirs(d, exist_ok=True)
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

def process_and_save_configs(config_list, output_prefix):
    print(f"\n--- Processing {len(config_list)} configs for source: {output_prefix} ---")
    if not config_list: return [] # Return empty list if no configs
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    all_processed_for_source = []
    
    for p in protocols:
        configs_for_proto = []
        if p == "VLESS": configs_for_proto = [c for c in config_list if c.startswith('vless://') and 'reality' not in c]
        elif p == "REALITY": configs_for_proto = [c for c in config_list if c.startswith('vless://') and 'security=reality' in c]
        elif p == "HYSTERIA": configs_for_proto = [c for c in config_list if c.startswith('hy')]
        else: configs_for_proto = [c for c in config_list if c.startswith(p.lower())]
            
        if not configs_for_proto: continue

        processed_configs, *_ = check_modify_config(configs_for_proto, p, check_connection=False)
        write_chunked_subscription_files(f"{output_prefix}/protocols/{p.lower()}", processed_configs)
        all_processed_for_source.extend(processed_configs)
        
    print(f"--- Finished processing for source: {output_prefix} ---")
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
        print(f"SUCCESS: Wrote {len(chunk)} configs to {filepath}")

def main():
    print("--- HYBRID COLLECTOR v12: The Real Fix ---")
    if not all([API_ID, API_HASH, SESSION_STRING]): print("FATAL: Missing Telegram secrets."); exit(1)

    setup_directories()
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)
    
    tg_configs = set()
    sub_configs = set()

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
                        tg_configs.update(find_configs_raw(message.text))
                    time.sleep(random.uniform(2.0, 4.0))
                except Exception as e:
                    print(f"--> ERROR scanning @{channel}: {e}"); invalid_channels.add(channel)
    except Exception as e: print(f"WARNING: Could not connect to Telegram: {e}")

    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            sub_configs.update(find_configs_raw(content))
        except Exception as e: print(f"--> ERROR fetching sub link {link}: {e}")
    
    # --- Part 2: Process and Save Separately ---
    processed_tg_configs = process_and_save_configs(list(tg_configs), "./channels")
    processed_sub_configs = process_and_save_configs(list(sub_configs), "./subscribe")
    
    # --- Part 3: Create Combined and Categorized Files ---
    all_processed_configs = processed_tg_configs + processed_sub_configs
    print(f"\n--- Creating final combined and categorized files from {len(all_processed_configs)} total processed configs ---")

    write_chunked_subscription_files('./splitted/mixed', all_processed_configs)
    
    # Correctly create and write country files
    country_dict = create_country(all_processed_configs)
    for country_code, configs in country_dict.items():
        write_chunked_subscription_files(f'./countries/{country_code}/mixed', configs)

    # Correctly create and write IP version files
    ipv4_list, ipv6_list = create_internet_protocol(all_processed_configs)
    write_chunked_subscription_files('./layers/ipv4', ipv4_list)
    write_chunked_subscription_files('./layers/ipv6', ipv6_list)
    
    # Update helper files
    with open('invalid telegram channels.json', 'w') as f: json.dump(sorted(list(invalid_channels)), f, indent=4)
    with open('last update', 'w') as f: f.write(current_update.isoformat())
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
