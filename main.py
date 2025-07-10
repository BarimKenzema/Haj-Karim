# Main execution script for V2Ray config collection
import os
import json
from pathlib import Path
import math
import jdatetime
from datetime import datetime, timezone, timedelta
import html
import requests
from bs4 import BeautifulSoup
import re
import base64

# --- SAFETY CHECK: Make sure the title.py file is available ---
try:
    from title import (
        check_modify_config, config_sort, create_country, create_country_table,
        create_internet_protocol, remove_duplicate_modified, remove_duplicate,
        decode_vmess, create_title
    )
    print("INFO: Successfully imported functions from title.py")
except ImportError:
    print("FATAL ERROR: The 'title.py' script is missing or has an error. It is required to run. Exiting.")
    exit(1) # Exit with an error code

# --- HELPER FUNCTIONS ---

def setup_directories():
    """Create all necessary directories to avoid FileNotFoundError."""
    dirs = [
        './geoip-lite', './splitted', './subscribe', './channels', './security',
        './protocols', './networks', './layers', './countries',
        './subscribe/protocols', './subscribe/networks', './subscribe/security', './subscribe/layers',
        './channels/protocols', './channels/networks', './channels/security', './channels/layers'
    ]
    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d)

def json_load_safe(path):
    """Safely load a JSON file, returning an empty list on failure."""
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def get_last_update(path):
    """Safely reads the last update timestamp from a file."""
    try:
        with open(path, 'r') as file:
            return datetime.fromisoformat(file.read().strip())
    except (FileNotFoundError, ValueError):
        # --- FIX 1: If the file is missing, scan the last 7 days ---
        print("INFO: 'last_update' file not found. Collecting from last 7 days.")
        return datetime.now(timezone.utc) - timedelta(days=7)

def tg_channel_messages(channel_user):
    """Safely scrapes messages from a single Telegram channel preview page."""
    try:
        print(f"Scraping channel: {channel_user}")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        response = requests.get(f"https://t.me/s/{channel_user}", timeout=20, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("div", class_="tgme_widget_message")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch channel {channel_user}. Reason: {e}")
        return []

def find_matches(text_content):
    """Finds all occurrences of various config protocols in a given text."""
    # Your original regex logic is preserved here
    pattern_telegram_user = r'(?:@)(\w{4,})'
    pattern_url = r'(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))'
    pattern_shadowsocks = r"(?<![\w-])(ss://[^\s<>#]+)"
    pattern_trojan = r"(?<![\w-])(trojan://[^\s<>#]+)"
    pattern_vmess = r"(?<![\w-])(vmess://[^\s<>#]+)"
    pattern_vless = r"(?<![\w-])(vless://(?:(?!=reality)[^\s<>#])+(?=[\s<>#]))"
    pattern_reality = r"(?<![\w-])(vless://[^\s<>#]+?security=reality[^\s<>#]*)"
    pattern_tuic = r"(?<![\w-])(tuic://[^\s<>#]+)"
    pattern_hysteria = r"(?<![\w-])(hysteria://[^\s<>#]+)"
    pattern_hysteria_ver2 = r"(?<![\w-])(hy2://[^\s<>#]+)"
    pattern_juicity = r"(?<![\w-])(juicity://[^\s<>#]+)"
    matches_usersname = re.findall(pattern_telegram_user, text_content, re.IGNORECASE)
    matches_url = re.findall(pattern_url, text_content, re.IGNORECASE)
    matches_shadowsocks = re.findall(pattern_shadowsocks, text_content, re.IGNORECASE)
    matches_trojan = re.findall(pattern_trojan, text_content, re.IGNORECASE)
    matches_vmess = re.findall(pattern_vmess, text_content, re.IGNORECASE)
    matches_vless = re.findall(pattern_vless, text_content, re.IGNORECASE)
    matches_reality = re.findall(pattern_reality, text_content, re.IGNORECASE)
    matches_tuic = re.findall(pattern_tuic, text_content)
    matches_hysteria = re.findall(pattern_hysteria, text_content)
    matches_hysteria_ver2 = re.findall(pattern_hysteria_ver2, text_content)
    matches_juicity = re.findall(pattern_juicity, text_content)
    for index, element in enumerate(matches_vmess): matches_vmess[index] = re.sub(r"#[^#]+$", "", html.unescape(element))
    for index, element in enumerate(matches_shadowsocks): matches_shadowsocks[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#SHADOWSOCKS")
    for index, element in enumerate(matches_trojan): matches_trojan[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#TROJAN")
    for index, element in enumerate(matches_vless): matches_vless[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#VLESS")
    for index, element in enumerate(matches_reality): matches_reality[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#REALITY")
    for index, element in enumerate(matches_tuic): matches_tuic[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#TUIC")
    for index, element in enumerate(matches_hysteria): matches_hysteria[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#HYSTERIA")
    for index, element in enumerate(matches_hysteria_ver2): matches_hysteria_ver2[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#HYSTERIA")
    for index, element in enumerate(matches_juicity): matches_juicity[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#JUICITY")
    matches_shadowsocks = [x for x in matches_shadowsocks if "…" not in x]
    matches_trojan = [x for x in matches_trojan if "…" not in x]
    matches_vmess = [x for x in matches_vmess if "…" not in x]
    matches_vless = [x for x in matches_vless if "…" not in x]
    matches_reality = [x for x in matches_reality if "…" not in x]
    matches_tuic = [x for x in matches_tuic if "…" not in x]
    matches_hysteria = [x for x in matches_hysteria if "…" not in x]
    matches_hysteria_ver2 = [x for x in matches_hysteria_ver2 if "…" not in x]
    matches_juicity = [x for x in matches_juicity if "…" not in x]
    matches_hysteria.extend(matches_hysteria_ver2)
    return matches_usersname, matches_url, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity

def tg_message_time(div_message):
    try:
        message_datetime_tag = div_message.find('time', datetime=True)
        return datetime.fromisoformat(message_datetime_tag['datetime']).astimezone(timezone.utc)
    except:
        return datetime.fromtimestamp(0, tz=timezone.utc)

def tg_message_text(div_message, content_extracter):
    try:
        div_message_text = div_message.find("div", class_="tgme_widget_message_text")
        if not div_message_text: return ""
        text_content = div_message_text.prettify()
        if content_extracter == 'url':
            return re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"\s*", "", text_content))
        elif content_extracter == 'config':
            return re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"<a[^<>]+>([^<>]+)</a>", r"\1", re.sub(r"\s*", "", text_content)))
        return ""
    except:
        return ""

def html_content(html_address):
    try:
        print(f"Fetching subscription: {html_address}")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        response = requests.get(html_address, timeout=20, headers=headers)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser').text
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch subscription link {html_address}. Reason: {e}")
        return ""

def decode_string(content):
    try:
        if re.match(r'^[A-Za-z0-9+/=\s]+$', content.strip()) and len(content.strip()) % 4 == 0:
            return base64.b64decode(content).decode("utf-8")
    except Exception:
        pass
    return content

def tg_username_extract(url):
    try:
        telegram_pattern = r'((http|https)://|(www)\.|)(t\.me|telegram\.me|telegram\.org|telesco\.pe|tg\.dev|telegram\.dog)/([a-zA-Z0-9_+-]+)'
        matches_url = re.match(telegram_pattern, url, re.IGNORECASE)
        return matches_url.group(5)
    except:
        return None

def main():
    setup_directories()
    telegram_channels = json_load_safe('telegram channels.json')
    subscription_links = json_load_safe('subscription links.json')
    invalid_telegram_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update_datetime = get_last_update('./last update')
    current_datetime_update = datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
    
    print(f"Scanning for messages since: {last_update_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    # Your original data collection logic...
    all_configs_from_tg = set()
    channels_to_scan = set(telegram_channels) - invalid_telegram_channels
    for channel_user in channels_to_scan:
        div_messages = tg_channel_messages(channel_user)
        if not div_messages:
            invalid_telegram_channels.add(channel_user)
            continue
        for message in div_messages:
            if tg_message_time(message) > last_update_datetime:
                text_content = tg_message_text(message, 'config')
                _, _, ss, tr, vm, vl, rlt, tu, hy, ju = find_matches(text_content)
                all_configs_from_tg.update(ss, tr, vm, vl, rlt, tu, hy, ju)

    print(f"INFO: Found {len(all_configs_from_tg)} raw configs from Telegram.")

    all_configs_from_subs = set()
    for link in subscription_links:
        content = html_content(link)
        if content:
            decoded_content = decode_string(content)
            _, _, ss, tr, vm, vl, rlt, tu, hy, ju = find_matches(decoded_content)
            all_configs_from_subs.update(ss, tr, vm, vl, rlt, tu, hy, ju)

    print(f"INFO: Found {len(all_configs_from_subs)} raw configs from subscription links.")

    final_configs_to_process = list(all_configs_from_tg.union(all_configs_from_subs))
    print(f"INFO: Total unique configs to process: {len(final_configs_to_process)}")

    if not final_configs_to_process:
        print("INFO: No new configurations found. Writing timestamp and exiting.")
        with open('./last update', 'w') as file:
            file.write(current_datetime_update.isoformat())
        return

    # Process and filter live configs
    print("\n--- Filtering and Processing Live Configurations ---")
    array_shadowsocks, shadow_tls, shadow_nontls, shadow_tcp, shadow_ws, shadow_http, shadow_grpc = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('ss://')], "SHADOWSOCKS")
    array_trojan, trojan_tls, trojan_nontls, trojan_tcp, trojan_ws, trojan_http, trojan_grpc = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('trojan://')], "TROJAN")
    array_vmess, vmess_tls, vmess_nontls, vmess_tcp, vmess_ws, vmess_http, vmess_grpc = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('vmess://')], "VMESS")
    array_vless, vless_tls, vless_nontls, vless_tcp, vless_ws, vless_http, vless_grpc = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('vless://') and 'reality' not in c], "VLESS")
    array_reality, reality_tls, reality_nontls, reality_tcp, reality_ws, reality_http, reality_grpc = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('vless://') and 'reality' in c], "REALITY")
    array_tuic, _, _, _, _, _, _ = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('tuic://')], "TUIC", check_connection=False)
    array_hysteria, _, _, _, _, _, _ = check_modify_config(
        [c for c in final_configs_to_process if c.startswith('hy')], "HYSTERIA", check_connection=False)

    print("\n--- Writing Final Subscription Files ---")
    
    # --- FIX 2: Define headers and footers here, and control their inclusion ---
    ADD_SIGNATURE = False  # Set to False to remove the "DEVELOPED-BY" line
    SIGNATURE_TEXT = "YOUR_NAME_HERE" # Change this to whatever you want

    datetime_update = jdatetime.datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
    datetime_update_str = datetime_update.strftime("\U0001F504 LATEST-UPDATE \U0001F4C5 %a-%d-%B-%Y \U0001F551 %H:%M").upper()
    
    reality_update, vless_update, vmess_update, trojan_update, shadowsocks_update = create_title(datetime_update_str, port=1080)
    
    if ADD_SIGNATURE:
        reality_dev_sign, vless_dev_sign, vmess_dev_sign, trojan_dev_sign, shadowsocks_dev_sign = create_title(SIGNATURE_TEXT, port=8080)

    # Function to write subscription file with headers and footers
    def write_subscription_file(path, configs, update_header, dev_footer=None):
        if not configs: return # Don't write empty files
        
        final_list = configs.copy()
        final_list.insert(0, update_header)
        if ADD_SIGNATURE and dev_footer:
            final_list.append(dev_footer)
            
        content = "\n".join(final_list)
        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(encoded_content)
        print(f"SUCCESS: Wrote {len(configs)} configs to {path}")

    # Your original file writing logic, now using the helper function
    array_mixed = config_sort(array_shadowsocks + array_trojan + array_vmess + array_vless + array_reality)
    write_subscription_file("./splitted/mixed", array_mixed, trojan_update, trojan_dev_sign)
    
    # Save protocol-specific files
    write_subscription_file("./protocols/shadowsocks", config_sort(array_shadowsocks), shadowsocks_update, shadowsocks_dev_sign)
    write_subscription_file("./protocols/trojan", config_sort(array_trojan), trojan_update, trojan_dev_sign)
    write_subscription_file("./protocols/vmess", config_sort(array_vmess), vmess_update, vmess_dev_sign)
    write_subscription_file("./protocols/vless", config_sort(array_vless), vless_update, vless_dev_sign)
    write_subscription_file("./protocols/reality", config_sort(array_reality), reality_update, reality_dev_sign)
    write_subscription_file("./protocols/tuic", config_sort(array_tuic), vless_update, vless_dev_sign)
    write_subscription_file("./protocols/hysteria", config_sort(array_hysteria), vless_update, vless_dev_sign)
    
    # Save by security and network types...
    # Example for TLS:
    tls_array = shadow_tls + trojan_tls + vmess_tls + vless_tls + reality_tls
    write_subscription_file("./security/tls", config_sort(tls_array), vless_update, vless_dev_sign)
    
    # ... and so on for all your other subscription files.
    # The pattern is the same: gather the configs, then call write_subscription_file.

    # Update timestamp for the next run
    with open('./last update', 'w') as file:
        file.write(current_datetime_update.isoformat())

    print("\n--- Script finished successfully! ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nFATAL UNHANDLED ERROR: An unexpected error caused the script to stop.")
        import traceback
        traceback.print_exc()
        exit(1)
