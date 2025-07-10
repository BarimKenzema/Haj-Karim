import os
import re
import base64
import requests
import json

print("--- RAW CONFIG COLLECTOR v4 (Final Regex) ---")

# Get the directory where this script itself is located.
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

def json_load_safe(filename):
    """Safely loads a JSON file using an absolute path."""
    absolute_path = os.path.join(SCRIPT_DIR, filename)
    print(f"Attempting to load file from absolute path: {absolute_path}")
    
    try:
        with open(absolute_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"WARNING: Could not load or parse '{absolute_path}'. Error: {e}")
        return []

def find_configs_raw(text):
    """Finds all possible config links using a broad regex."""
    if not text:
        return []
    # --- THIS IS THE CRITICAL FIX ---
    # The (?:...) makes the first group non-capturing, so it returns the whole match.
    pattern = r'(?:vless|vmess|trojan|ss|hy|hy2|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

def main():
    output_dir = os.path.join(SCRIPT_DIR, 'subscribe')
    os.makedirs(output_dir, exist_ok=True)
    
    subs_links = json_load_safe('subscription links.json')
    if not subs_links:
        print("FATAL: 'subscription links.json' is empty or could not be found. No sources to scan.")
        return

    all_raw_configs = set()

    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            print(f"Fetching: {link}")
            content = requests.get(link, timeout=20, headers={'User-Agent': 'Mozilla/5.0'}).text
            
            # Try to decode if it's base64. If not, use the raw text.
            try:
                decoded_content = base64.b64decode(content).decode('utf-8', 'ignore')
                all_raw_configs.update(find_configs_raw(decoded_content))
            except Exception:
                all_raw_configs.update(find_configs_raw(content))

        except Exception as e:
            print(f"--> ERROR fetching sub link {link}: {e}")
    
    final_configs = sorted(list(all_raw_configs))
    
    print(f"\n--- Found {len(final_configs)} total unique configs. Writing to file... ---")

    if final_configs:
        output_path = os.path.join(output_dir, 'all_raw.txt')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_configs))
        print(f"SUCCESS: All {len(final_configs)} configs saved to {output_path}")
    else:
        print("WARNING: No configs were collected in this run.")

    print("\n--- SCRIPT FINISHED ---")

if __name__ == "__main__":
    main()
