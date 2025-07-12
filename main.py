# Meticulous Anonymous Scraper v1
import os, json, re, base64, time, traceback, random
from datetime import datetime, timezone, timedelta
import requests
from bs4 import BeautifulSoup
import jdatetime

try:
    from title import (
        check_modify_config, config_sort, create_country, create_country_table,
        create_internet_protocol, remove_duplicate, decode_vmess, create_title
    )
    print("INFO: Successfully imported processing functions from title.py")
except ImportError as e:
    print(f"FATAL: 'title.py' is missing or has an error. It's required. Error: {e}")
    exit(1)

CONFIG_CHUNK_SIZE = 111

def setup_directories():
    dirs = [
        './splitted', './subscribe', './channels', './security', './protocols',
        './networks', './layers', './countries'
    ]
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

def tg_channel_messages(channel_user):
    try:
        print(f"Scraping channel: @{channel_user}")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        response = requests.get(f"https://t.me/s/{channel_user}", timeout=20, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("div", class_="tgme_widget_message")
    except requests.exceptions.RequestException as e:
        print(f"--> ERROR fetching channel @{channel_user}: {e}")
        return []

def tg_message_time(div_message):
    try:
        time_tag = div_message.find('time', datetime=True)
        return datetime.fromisoformat(time_tag['datetime']).astimezone(timezone.utc)
    except: return datetime.fromtimestamp(0, tz=timezone.utc)

def tg_message_text(div_message):
    try:
        text_div = div_message.find("div", class_="tgme_widget_message_text")
        return text_div.get_text(separator='\n') if text_div else ""
    except: return ""
    
def write_chunked_subscription_files(base_filepath, configs, is_b64=True):
    os.makedirs(os.path.dirname(base_filepath), exist_ok=True)
    if not configs:
        with open(base_filepath, "w") as f: f.write("")
        return
    sorted_configs = config_sort(configs)
    chunks = [sorted_configs[i:i + CONFIG_CHUNK_SIZE] for i in range(0, len(sorted_configs), CONFIG_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        filepath = base_filepath if i == 0 else os.path.join(os.path.dirname(base_filepath), f"{os.path.basename(base_filepath)}{i + 1}")
        content = "\n".join(chunk)
        if is_b64: content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f: f.write(content)
        print(f"SUCCESS: Wrote {len(chunk)} configs to {filepath}")

def main():
    print("--- METICULOUS ANONYMOUS SCRAPER START ---")
    setup_directories()
    
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    last_update = get_last_update('last update')
    current_update = datetime.now(timezone.utc)
    all_raw_configs = set()

    # Part 1: DATA COLLECTION
    print(f"\n--- Scanning {len(channels)} Telegram channels... ---")
    for channel in channels:
        messages = tg_channel_messages(channel)
        for message in messages:
            if tg_message_time(message) > last_update:
                all_raw_configs.update(find_configs_raw(tg_message_text(message)))
        # Meticulous delay
        time.sleep(random.uniform(1.0, 3.0))

    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}).text
            try: content = base64.b64decode(content).decode('utf-8')
            except: pass
            all_raw_configs.update(find_configs_raw(content))
        except Exception as e:
            print(f"--> ERROR fetching sub link {link}: {e}")

    final_configs_to_process = list(all_raw_configs)
    print(f"\n--- Found {len(final_configs_to_process)} total raw configs. Starting processing... ---")
    if not final_configs_to_process:
        with open('last update', 'w') as f: f.write(current_update.isoformat()); return

    # Part 2: DATA PROCESSING
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA", "JUICITY"]
    processed = {p: [] for p in protocols}
    for p in protocols:
        configs_for_proto = [c for c in final_configs_to_process if p.lower() in c.split('://')[0].lower()]
        if p == "HYSTERIA": configs_for_proto = [c for c in final_configs_to_process if c.startswith('hy')]
        if p == "VLESS": configs_for_proto = [c for c in configs_for_proto if 'reality' not in c]
        if p == "REALITY": configs_for_proto = [c for c in final_configs_to_process if c.startswith('vless') and 'reality' in c]
            
        p_mod, *_ = check_modify_config(configs_for_proto, p, check_connection=False)
        processed[p].extend(p_mod)

    # Part 3: FILE WRITING
    for p_name, p_configs in processed.items():
        write_chunked_subscription_files(f"./protocols/{p_name.lower()}", p_configs)

    with open('last update', 'w') as f: f.write(current_update.isoformat())
    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---")
        traceback.print_exc()
        exit(1)
