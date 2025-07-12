# FINAL HYBRID SCRIPT v11: Separate Categories, Patient & Robust
import os, json, re, base64, time, traceback, random
from datetime import datetime, timezone, timedelta
import requests
import jdatetime

try:
    from title import check_modify_config, config_sort, create_country, create_internet_protocol
    print("INFO: Successfully imported processing functions from title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing or has an error. Error: {e}"); exit(1)

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
    if not config_list: return
    
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    
    for p in protocols:
        configs_for_proto = [c for c in config_list if p.lower() in c.split('://')[0].lower()]
        if p == "HYSTERIA": configs_for_proto = [c for c in config_list if c.startswith('hy')]
        if p == "VLESS": configs_for_proto = [c for c in configs_for_proto if 'reality' not in c]
        if p == "REALITY": configs_for_proto = [c for c in config_list if c.startswith('vless') and 'reality' in c]

        processed_configs, *_ = check_modify_config(configs_for_proto, p, check_connection=False)
        write_chunked_subscription_files(f"{output_prefix}/protocols/{p.lower()}", processed_configs)

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
    print("--- HYBRID COLLECTOR v11: Final ---")
    if not all([API_ID, API_HASH, SESSION_STRING]): print("FATAL: Missing Telegram secrets."); exit(1)

    setup_directories()
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)
    
    tg_configs, sub_configs = set(), set()

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
    
    process_and_save_configs(list(tg_configs), "./channels")
    process_and_save_configs(list(sub_configs), "./subscribe")
    
    all_configs = list(tg_configs.union(sub_configs))
    all_processed, *_ = check_modify_config(all_configs, "VLESS", check_connection=False)
    write_chunked_subscription_files("./splitted/mixed", all_processed)
    
    with open('invalid telegram channels.json', 'w') as f: json.dump(sorted(list(invalid_channels)), f, indent=4)
    with open('last update', 'w') as f: f.write(current_update.isoformat())
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---"); traceback.print_exc(); exit(1)
