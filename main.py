# FINAL HYBRID SCRIPT: Raw Collector + Full Categorization Processor
import os, json, re, base64, traceback
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

# --- Helper Functions ---
def setup_directories():
    dirs = [
        './splitted', './subscribe', './channels', './security', './protocols',
        './networks', './layers', './countries'
    ]
    # Create main directories and all necessary sub-directories
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

def find_configs_raw(text):
    if not text: return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

def main():
    print("--- FULL CATEGORIZATION SCRIPT START ---")
    setup_directories()
    
    # We will only use subscription links as they are the reliable source.
    subs_links = json_load_safe('subscription links.json')
    if not subs_links:
        print("FATAL: 'subscription links.json' is empty or missing. No sources to scan.")
        return

    all_raw_configs = set()
    print(f"\n--- Fetching {len(subs_links)} subscription links... ---")
    for link in subs_links:
        try:
            content = requests.get(link, timeout=20, headers={'User-Agent': 'Mozilla/5.0'}).text
            try:
                decoded_content = base64.b64decode(content).decode('utf-8', 'ignore')
                all_raw_configs.update(find_configs_raw(decoded_content))
            except Exception:
                all_raw_configs.update(find_configs_raw(content))
        except Exception as e:
            print(f"--> ERROR fetching sub link {link}: {e}")
    
    final_configs_to_process = list(all_raw_configs)
    print(f"\n--- Found {len(final_configs_to_process)} total raw configs. Starting full processing... ---")
    if not final_configs_to_process:
        print("INFO: No configs were collected. Exiting.")
        return

    # --- Part 2: DATA PROCESSING (Using your title.py logic) ---
    print("\n--- Filtering and Titling Configurations (check_connection=False) ---")
    
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

    # --- Part 3: FILE WRITING (Your original comprehensive file generation) ---
    print("\n--- Writing All Categorized Subscription Files ---")
    
    def write_subscription_file(filepath, configs, is_b64=True):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        content = "\n".join(config_sort(configs))
        if is_b64:
            content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"SUCCESS: Wrote {len(configs)} configs to {filepath}")

    # Write protocol files
    for p_name, p_configs in processed.items():
        write_subscription_file(f"./protocols/{p_name.lower()}", p_configs)

    # Write security files
    write_subscription_file("./security/tls", security['tls'])
    write_subscription_file("./security/non-tls", security['non_tls'])

    # Write network files
    for net_type, configs in network.items():
        write_subscription_file(f"./networks/{net_type}", configs)

    # Combine all processed configs for country and other mixed files
    all_processed_configs = []
    for p_configs in processed.values():
        all_processed_configs.extend(p_configs)
        
    # Write country files
    country_dict = create_country(all_processed_configs)
    for country_code, configs in country_dict.items():
        write_subscription_file(f'./countries/{country_code}/mixed', configs)
        
    # Write IPV4/IPV6 files
    ipv4_list, ipv6_list = create_internet_protocol(all_processed_configs)
    write_subscription_file('./layers/ipv4', ipv4_list)
    write_subscription_file('./layers/ipv6', ipv6_list)
    
    # Write the main mixed file
    write_subscription_file('./splitted/mixed', all_processed_configs)

    print("\n--- SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- FATAL UNHANDLED ERROR IN MAIN ---")
        traceback.print_exc()
        exit(1)
