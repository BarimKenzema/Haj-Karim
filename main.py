import os
import json
import re
import base64
import time # Import the time module for the delay
from datetime import datetime, timezone, timedelta
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
import requests
import traceback

print("--- Telethon Config Collector START ---")

# --- CONFIGURATION ---
# These will be read from GitHub Secrets
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELETHON_SESSION')

# --- HELPER FUNCTIONS ---
def json_load_safe(path):
    """Safely loads a JSON file, returning an empty list on failure."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"WARNING: Could not read or parse '{path}'. Returning empty list.")
        return []

def get_last_update(path):
    """Safely reads the last update timestamp from a file."""
    try:
        with open(path, 'r') as f:
            return datetime.fromisoformat(f.read().strip())
    except (FileNotFoundError, ValueError):
        # If file not found or invalid, scan the last 7 days for a full refresh.
        print("INFO: 'last_update' file not found or invalid. Collecting from last 7 days.")
        return datetime.now(timezone.utc) - timedelta(days=7)

def find_configs(text):
    """Finds all occurrences of various config protocols in a given text."""
    if not text:
        return []
    # Universal regex to find any protocol links. It's robust and fast.
    pattern = r"(?i)(vless|vmess|trojan|ss|hy|hy2|tuic|juicity)://[^\s<>\"']+"
    return re.findall(pattern, text)

# --- MAIN SCRIPT ---
def main():
    print("--- V2Ray Collector: main() function started ---")
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("FATAL: Missing one or more required secrets: TELEGRAM_API_ID, TELEGRAM_API_HASH, or TELETHON_SESSION.")
        exit(1)

    # Create output directory if it doesn't exist
    os.makedirs('subscribe', exist_ok=True)

    # Load data sources
    channels = json_load_safe('telegram channels.json')
    subs_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('last update')

    all_configs = set()

    # 1. Collect from Telegram Channels using Telethon
    print(f"\n--- Logging into Telegram and scanning {len(channels)} channels since {last_update.date()} ---")
    try:
        with TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH) as client:
            channels_to_scan = set(channels) - invalid_channels
            for i, channel in enumerate(channels_to_scan):
                try:
                    print(f"Scanning channel {i+1}/{len(channels_to_scan)}: @{channel}...")
                    for message in client.iter_messages(channel, limit=200):
                        if message.date < last_update:
                            break # Stop when we reach messages we've already seen
                        all_configs.update(find_configs(message.text))
                    
                    # THIS IS THE CRITICAL FIX FOR TELEGRAM FLOOD WAIT
                    # Pause for 2 seconds between scanning each channel to act more like a human
                    print(f"--- Pausing for 2 seconds... ---")
                    time.sleep(2)

                except Exception as e:
                    print(f"--> ERROR: Could not access or process channel @{channel}. Reason: {e}")
                    # If a channel is consistently failing, we might add it to an invalid list
                    invalid_channels.add(channel)

    except Exception as e:
        print(f"FATAL: Could not connect or login to Telegram. Check your API keys and session string. Reason: {e}")
        # We don't exit here, we can still try subscription links

    print(f"--- Found {len(all_configs)} configs from Telegram. ---")

    # 2. Collect from Subscription Links
    initial_count = len(all_configs)
    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=15).text
            # Try to decode if it's base64 encoded
            try:
                decoded_content = base64.b64decode(content).decode('utf-8', 'ignore')
                all_configs.update(find_configs(decoded_content))
            except Exception:
                # If not base64, parse the plain text
                all_configs.update(find_configs(content))
        except Exception as e:
            print(f"--> ERROR: Could not fetch sub link {link}. Reason: {e}")
    
    print(f"--- Found {len(all_configs) - initial_count} new configs from subscriptions. ---")

    # 3. Write final file
    final_configs = sorted(list(all_configs))
    print(f"\n--- Writing {len(final_configs)} total unique configs to file... ---")
    
    if final_configs:
        # Create a simple, clean, mixed subscription file
        with open('subscribe/mixed_all.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_configs))
        
        # Create a base64 version
        with open('subscribe/mixed_all_b64.txt', 'w', encoding='utf-8') as f:
            b64_content = base64.b64encode('\n'.join(final_configs).encode('utf-8'))
            f.write(b64_content.decode('utf-8'))

        print("SUCCESS: Subscription files created.")
    else:
        print("WARNING: No configs were collected in this run.")
    
    # 4. Update helper files for the next run
    with open('invalid telegram channels.json', 'w', encoding='utf-8') as f:
        json.dump(sorted(list(invalid_channels)), f, indent=4)
        
    with open('last update', 'w', encoding='utf-8') as f:
        f.write(datetime.now(timezone.utc).isoformat())

    print("--- Script finished successfully! ---")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- [FATAL_ERROR] An unhandled exception occurred in main(). Reason: {e} ---")
        traceback.print_exc()
        exit(1)
