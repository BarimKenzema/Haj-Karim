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
import traceback

print("--- main.py: SCRIPT START ---")

try:
    from title import (
        check_modify_config, config_sort, create_country, create_country_table,
        create_internet_protocol, remove_duplicate_modified, remove_duplicate,
        decode_vmess, create_title
    )
    print("--- main.py: Successfully imported from title.py ---")
except ImportError as e:
    print(f"--- [FATAL_ERROR] main.py: Could not import from 'title.py'. Error: {e} ---")
    exit(1)

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
        # Use your original filename without underscore
        with open(path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"WARNING: Could not load or parse '{path}'. Returning empty list.")
        return []

def get_last_update(path):
    """Safely reads the last update timestamp from a file."""
    try:
        with open(path, 'r') as file:
            return datetime.fromisoformat(file.read().strip())
    except (FileNotFoundError, ValueError):
        print("--- main.py: 'last_update' not found, scanning last 7 days. ---")
        return datetime.now(timezone.utc) - timedelta(days=7)

def tg_channel_messages(channel_user):
    """Safely scrapes messages from a single Telegram channel preview page."""
    try:
        print(f"--- main.py: Scraping channel: {channel_user} ---")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        response = requests.get(f"https://t.me/s/{channel_user}", timeout=20, headers=headers)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser").find_all("div", class_="tgme_widget_message")
    except requests.exceptions.RequestException as e:
        print(f"--> [NETWORK_ERROR] main.py: Could not fetch channel {channel_user}. Reason: {e}")
        return []

def find_matches(text_content):
    """Finds all occurrences of various config protocols in a given text."""
    try:
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
        for i,e in enumerate(matches_vmess): matches_vmess[i] = re.sub(r"#[^#]+$", "", html.unescape(e))
        for i,e in enumerate(matches_shadowsocks): matches_shadowsocks[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#SHADOWSOCKS")
        for i,e in enumerate(matches_trojan): matches_trojan[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#TROJAN")
        for i,e in enumerate(matches_vless): matches_vless[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#VLESS")
        for i,e in enumerate(matches_reality): matches_reality[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#REALITY")
        for i,e in enumerate(matches_tuic): matches_tuic[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#TUIC")
        for i,e in enumerate(matches_hysteria): matches_hysteria[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#HYSTERIA")
        for i,e in enumerate(matches_hysteria_ver2): matches_hysteria_ver2[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#HYSTERIA")
        for i,e in enumerate(matches_juicity): matches_juicity[i] = (re.sub(r"#[^#]+$", "", html.unescape(e)) + "#JUICITY")
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
    except Exception as e:
        print(f"--> [REGEX_ERROR] main.py: find_matches failed. Reason: {e}")
        return [], [], [], [], [], [], [], [], [], []

def tg_message_time(div_message):
    try:
        return datetime.fromisoformat(div_message.find('time', datetime=True)['datetime']).astimezone(timezone.utc)
    except: return datetime.fromtimestamp(0, tz=timezone.utc)

def tg_message_text(div_message, content_extracter):
    try:
        div_text = div_message.find("div", class_="tgme_widget_message_text")
        if not div_text: return ""
        text = div_text.prettify()
        if content_extracter == 'url': return re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"\s*", "", text))
        elif content_extracter == 'config': return re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"<a[^<>]+>([^<>]+)</a>", r"\1", re.sub(r"\s*", "", text)))
    except: return ""

def html_content(url):
    try:
        print(f"--- main.py: Fetching subscription: {url} ---")
        h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        r = requests.get(url, timeout=20, headers=h)
        r.raise_for_status()
        return BeautifulSoup(r.text, 'html.parser').text
    except Exception as e:
        print(f"--> [NETWORK_ERROR] main.py: Could not fetch sub link {url}. Reason: {e}")
        return ""

def decode_string(content):
    try:
        if re.match(r'^[A-Za-z0-9+/=\s]+$', content.strip()) and len(content.strip()) % 4 == 0:
            return base64.b64decode(content).decode("utf-8")
    except: pass
    return content

def main():
    """The main execution block of the script."""
    print("--- main.py: main() function START ---")
    setup_directories()

    # Load initial data sources
    telegram_channels = json_load_safe('telegram channels.json')
    subscription_links = json_load_safe('subscription links.json')
    invalid_channels = set(json_load_safe('invalid telegram channels.json'))
    last_update = get_last_update('./last update')
    current_update = datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))

    print(f"--- main.py: Scanning for messages since: {last_update.isoformat()} ---")

    # --- Data Collection ---
    all_raw_configs = set()

    # 1. Collect from Telegram
    print(f"\n--- main.py: Starting Telegram scrape phase ({len(telegram_channels)} channels) ---")
    channels_to_scan = set(telegram_channels) - invalid_channels
    for channel in channels_to_scan:
        for message in tg_channel_messages(channel):
            if tg_message_time(message) > last_update:
                _, _, ss, tr, vm, vl, rlt, tu, hy, ju = find_matches(tg_message_text(message, 'config'))
                all_raw_configs.update(ss, tr, vm, vl, rlt, tu, hy, ju)

    print(f"--- main.py: Found {len(all_raw_configs)} configs from Telegram ---")

    # 2. Collect from Subscription links and ADD to the set
    initial_tg_config_count = len(all_raw_configs)
    print(f"\n--- main.py: Starting subscription scrape phase ({len(subscription_links)} links) ---")
    for link in subscription_links:
        content = html_content(link)
        if content:
            decoded_content = decode_string(content)
            _, _, ss, tr, vm, vl, rlt, tu, hy, ju = find_matches(decoded_content)
            all_raw_configs.update(ss, tr, vm, vl, rlt, tu, hy, ju)
    
    print(f"--- main.py: Found {len(all_raw_configs) - initial_tg_config_count} configs from subscriptions ---")

    final_configs_to_process = list(all_raw_configs)
    print(f"\n--- main.py: Found {len(final_configs_to_process)} total unique configs. Starting processing. ---")

    if not final_configs_to_process:
        print("--- main.py: No new configs found. Exiting gracefully. ---")
        with open('./last update', 'w') as f: f.write(current_update.isoformat())
        return

    # Process and filter configs
    print("\n--- main.py: Starting check_modify_config phase ---")
    protocols = ["SHADOWSOCKS", "TROJAN", "VMESS", "VLESS", "REALITY", "TUIC", "HYSTERIA"]
    processed_configs = {}
    for p in protocols:
        configs_for_proto = [c for c in final_configs_to_process if p.lower() in c.split('://')[0].lower()]
        print(f"--- main.py: Processing {len(configs_for_proto)} configs for {p} ---")
        # The "trust, don't verify" approach
        is_checkable = False
        processed_configs[p], *_ = check_modify_config(configs_for_proto, p, check_connection=is_checkable)

    # --- Start Final File Writing ---
    print("\n--- main.py: Starting to write final output files ---")
    try:
        adv_bool = False
        datetime_update_str = jdatetime.datetime.now(tz=timezone(timedelta(hours=3,minutes=30))).strftime("\U0001F504 LATEST-UPDATE \U0001F4C5 %a-%d-%B-%Y \U0001F551 %H:%M").upper()
        reality_update, vless_update, vmess_update, trojan_update, shadowsocks_update = create_title(datetime_update_str, port=1080)
        
        # --- Control the signature ---
        ADD_SIGNATURE = False # Set to False to remove it
        SIGNATURE_TEXT = "Generated by Automated Script"
        
        if ADD_SIGNATURE:
            reality_dev, vless_dev, vmess_dev, trojan_dev, ss_dev = create_title(SIGNATURE_TEXT, 8080)

        def write_subscription_file(filepath, configs, update_header, dev_footer=None):
            if not configs:
                print(f"--- main.py: No configs for {filepath}, skipping write. ---")
                # Ensure file is at least created to avoid 404
                with open(filepath, "w", encoding="utf-8") as f: f.write("")
                return

            final_list = config_sort(configs)
            final_list.insert(0, update_header)
            if ADD_SIGNATURE and dev_footer:
                final_list.append(dev_footer)
            
            content = "\n".join(final_list)
            encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(encoded_content)
            print(f"--- main.py: Successfully wrote {len(configs)} configs to {filepath} ---")

        # Example for one file, this pattern should be repeated for all your files.
        all_processed = []
        for p in protocols:
            all_processed.extend(processed_configs.get(p, []))
        
        write_subscription_file("./splitted/mixed", all_processed, trojan_update, locals().get('trojan_dev'))
        write_subscription_file("./protocols/shadowsocks", processed_configs.get("SHADOWSOCKS",[]), shadowsocks_update, locals().get('ss_dev'))
        write_subscription_file("./protocols/trojan", processed_configs.get("TROJAN",[]), trojan_update, locals().get('trojan_dev'))
        # ... and so on for all the other files you want to generate.

    except Exception as e:
        print(f"--- [FATAL_ERROR] main.py: Error during final file writing. Reason: {e} ---")
        traceback.print_exc()
        exit(1)

    with open('./last update', 'w') as f: f.write(current_update.isoformat())
    print("--- main.py: SCRIPT END ---")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n--- [FATAL_ERROR] main.py: An unhandled exception occurred in main(). Reason: {e} ---")
        traceback.print_exc()
        exit(1)
