# FINAL SCRIPT v38-S1-IRAN-SEARCH: Collector with Enhanced Iranian Search Queries

import os, json, re, base64, time, traceback, socket, ipaddress
import requests
from urllib.parse import urlparse
import concurrent.futures

print("--- BASE COLLECTOR & PRE-FILTERER v38-S1-IRAN-SEARCH START ---")

# --- CONFIGURATION ---
CONFIG_CHUNK_SIZE = 444
MAX_PREFILTER_WORKERS = 100
COLLECTOR_TOKEN = os.environ.get('COLLECTOR_TOKEN')

# --- STRATEGY 1 - GITHUB SCRAPING FUNCTION ---
def fetch_from_github():
    print("--- Fetching configs from GitHub with enhanced search queries ---")
    if not COLLECTOR_TOKEN:
        print("WARNING: COLLECTOR_TOKEN secret not found or empty. Skipping GitHub scrape.")
        return set()
    
    configs = set()
    headers = {'Authorization': f'token {COLLECTOR_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'}
    
    # These queries target repositories and files that use Persian keywords
    # related to circumvention tools and major Iranian ISPs.
    queries = [
        '"vless" "کانفیگ" "رایگان"',
        '"vmess" "ایرانسل"',
        '"trojan" "همراه اول"',
        '"v2ray" "رایتل"',
        'filename:subscribe "v2ray" "ایران"',
        'path:config "vless" "رایگان"',
        '"ss://"',
        '"reality" "کانفیگ"',
        'filename:all.txt "vmess://"',
        'path:nodes "vless://"'
    ]
    
    for query in queries:
        search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=100"
        try:
            time.sleep(6) # Avoid hitting the search API rate limit
            res = requests.get(search_url, headers=headers, timeout=30)
            res.raise_for_status()
            items = res.json().get('items', [])
            print(f"Found {len(items)} potential files on GitHub for query: '{query}'.")
            
            for item in items:
                time.sleep(0.5) # Avoid hitting the content API rate limit
                raw_url = item.get('url')
                try:
                    content_res = requests.get(raw_url, headers=headers, timeout=10)
                    if content_res.status_code == 200:
                        content = content_res.text
                        if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                            try: 
                                content = base64.b64decode(content).decode('utf-8', 'ignore')
                            except Exception:
                                pass
                        
                        found_in_file = find_configs_raw(content)
                        if found_in_file:
                           configs.update(found_in_file)
                except Exception:
                    continue
        except Exception as e:
            print(f"ERROR: Failed to fetch from GitHub with query '{query}': {e}")
            if 'rate limit' in str(e).lower():
                print("--- GitHub API rate limit likely exceeded. Sleeping for 60 seconds. ---")
                time.sleep(60)
            continue

    print(f"Found {len(configs)} new unique configs from GitHub.")
    return configs

# --- HELPER FUNCTIONS ---
def find_configs_raw(text):
    if not text: return []
    pattern = r'(?:vless|vmess|trojan|ss|hy2|hysteria|tuic|juicity)://[^\s<>"\'`]+'
    return re.findall(pattern, text, re.IGNORECASE)

def get_host_port_from_config(config):
    try:
        if config.startswith("vmess://"):
            json_str = config.replace("vmess://", "").strip()
            if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
            decoded = json.loads(base64.b64decode(json_str).decode('utf-8', 'ignore'))
            return decoded.get('add'), decoded.get('port')
        else:
            parsed = urlparse(config)
            return parsed.hostname, parsed.port
    except: return None, None

def get_ips(node):
    from dns import resolver
    try:
        if not node or not isinstance(node, str): return None
        if ipaddress.ip_address(node): return [node]
    except ValueError:
        try:
            res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
            return [str(rdata) for rdata in res.resolve(node, 'A', raise_on_no_answer=False) or []] or None
        except: return None
    return None

def check_host_port_with_socket(host_port):
    try:
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        with socket.create_connection((host, port), timeout=1.5):
            return host_port
    except: return None

def pre_filter_live_hosts(all_configs):
    print(f"\n--- Pre-filtering {len(all_configs)} configs for live hosts... ---")
    host_port_to_configs = {}
    for config in all_configs:
        host, port = get_host_port_from_config(config)
        if host and port:
            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]
            host_port_key = f"{ip_address}:{port}"
            if host_port_key not in host_port_to_configs:
                host_port_to_configs[host_port_key] = config
    
    hosts_to_test = list(host_port_to_configs.keys())
    print(f"Found {len(hosts_to_test)} unique IP:port pairs to test.")
    live_host_ports = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PREFILTER_WORKERS) as executor:
        future_to_host = {executor.submit(check_host_port_with_socket, host_port): host_port for host_port in hosts_to_test}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host)):
            if (i + 1) % 1000 == 0: print(f"Tested {i+1}/{len(hosts_to_test)} unique hosts...")
            result = future.result()
            if result: live_host_ports.add(result)

    unique_live_configs = [host_port_to_configs[host_port] for host_port in live_host_ports if host_port in host_port_to_configs]
    print(f"--- Pre-filter complete. Kept {len(unique_live_configs)} unique, live configs. ---")
    return unique_live_configs

# --- MAIN EXECUTION ---
def main():
    all_raw_configs = set()
    print("--- Collecting from subscription links.json ---")
    try:
        with open('subscription links.json', 'r', encoding='utf-8') as f:
            subs_links = json.load(f)
        for link in subs_links:
            try:
                content = requests.get(link, timeout=15).text
                if re.match(r'^[A-Za-z0-9+/=]{100,}$', content.strip().replace('\n', '')):
                  try: content = base64.b64decode(content).decode('utf-8', 'ignore')
                  except: pass
                all_raw_configs.update(find_configs_raw(content))
            except: continue
        print(f"Found {len(all_raw_configs)} configs from local subscription file.")
    except Exception as e:
        print(f"Could not read 'subscription links.json'. Error: {e}")
    
    all_raw_configs.update(fetch_from_github())
    print(f"--- Total unique configs from all sources: {len(all_raw_configs)} ---")
    
    live_unique_configs = pre_filter_live_hosts(list(all_raw_configs))
    if not live_unique_configs:
        print("INFO: No live configs found after filtering. Exiting."); return
        
    with open('filtered-for-refiner.txt', 'w', encoding='utf-8') as f:
        for config in live_unique_configs: f.write(config + '\n')
    print(f"--- Saved {len(live_unique_configs)} pre-filtered configs to filtered-for-refiner.txt ---")
    
    print("\n--- COLLECTOR SCRIPT FINISHED SUCCESSFULLY ---")

if __name__ == "__main__":
    try: main()
    except Exception: print(f"\n--- FATAL UNHANDLED ERROR ---"); traceback.print_exc(); exit(1)
