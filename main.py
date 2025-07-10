import os
import json
import re
import base64
from datetime import datetime, timezone, timedelta
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
import requests

# --- CONFIGURATION ---
# These will be read from GitHub Secrets
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')

# --- HELPER FUNCTIONS ---
def json_load_safe(path):
    try:
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    except: return []

def get_last_update(path):
    try:
        with open(path, 'r') as f: return datetime.fromisoformat(f.read().strip())
    except: return datetime.now(timezone.utc) - timedelta(days=7)

def find_configs(text):
    if not text: return []
    # Universal regex to find any protocol links
    pattern = r"(?i)(vless|vmess|trojan|ss|hy|hy2|tuic|juicity)://[^\s<>\"']+"
    return re.findall(pattern, text)

# --- MAIN SCRIPT ---
def main():
    print("--- Telethon Config Collector START ---")
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("FATAL: Missing TELEGRAM_API_ID, TELEGRAM_API_HASH, or TELETHON_SESSION secrets.")
        exit(1)

    # Load sources
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    last_update = get_last_update('last update')

    all_configs = set()

    # 1. Collect from Telegram Channels using Telethon
    print(f"\n--- Logging into Telegram and scanning {len(channels)} channels... ---")
    try:
        with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
            for channel in channels:
                try:
                    print(f"Scanning @{channel}...")
                    for message in client.iter_messages(channel, limit=200):
                        if message.date < last_update: break
                        all_configs.update(find_configs(message.text))
                except Exception as e:
                    print(f"--> ERROR: Could not access channel @{channel}. Reason: {e}")
    except Exception as e:
        print(f"FATAL: Could not connect to Telegram. Reason: {e}")

    print(f"--- Found {len(all_configs)} configs from Telegram. ---")

    # 2. Collect from Subscription Links
    initial_count = len(all_configs)
    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            try: # Try to decode if it's base64
                content = base64.b64decode(content).decode('utf-8')
            except: pass
            all_configs.update(find_configs(content))
        except Exception as e:
            print(f"--> ERROR: Could not fetch sub link {link}. Reason: {e}")
    
    print(f"--- Found {len(all_configs) - initial_count} configs from subscriptions. ---")

    # 3. Write final file
    final_configs = sorted(list(all_configs))
    print(f"\n--- Writing {len(final_configs)} total unique configs to file... ---")
    
    if final_configs:
        # Create a simple, clean, mixed subscription file
        os.makedirs('subscribe', exist_ok=True)
        with open('subscribe/mixed_all.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_configs))
        
        # Create a base64 version
        with open('subscribe/mixed_all_b64.txt', 'w', encoding='utf-8') as f:
            b64_content = base64.b64encode('\n'.join(final_configs).encode('utf-8'))
            f.write(b64_content.decode('utf-8'))

        print("SUCCESS: Subscription files created.")
    else:
        print("WARNING: No configs were collected in this run.")
    
    # 4. Update timestamp
    with open('last update', 'w') as f:
        f.write(datetime.now(timezone.utc).isoformat())

    print("--- Script finished successfully! ---")

if __name__ == "__main__":
    main()
