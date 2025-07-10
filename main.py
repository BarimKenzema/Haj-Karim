#import requirement libraries
import os
import wget
import json
from pathlib import Path

import math
import string
import random

import jdatetime
from datetime import datetime, timezone, timedelta

#import web-based libraries
import html
import requests
from bs4 import BeautifulSoup

#import regex and encoding libraries
import re
import base64

#import custom python script
# NOTE: Make sure the 'title.py' file exists and is correct.
try:
    from title import check_modify_config, config_sort, create_country, create_country_table, create_internet_protocol
except ImportError as e:
    print(f"FATAL ERROR: Could not import from 'title.py'. Make sure this file exists and is correct. Error: {e}")
    exit()


# --- START OF FIX ---
# This section is disabled as it will cause network errors on your system.
# You need to manually ensure 'geoip-lite/geoip-lite-country.mmdb' exists.
# print("Skipping GeoIP database download.")
# # Create the geoip-lite folder if it doesn't exist
# if not os.path.exists('./geoip-lite'):
#     os.mkdir('./geoip-lite')
#
# if os.path.exists('./geoip-lite/geoip-lite-country.mmdb'):
#     os.remove('./geoip-lite/geoip-lite-country.mmdb')
#
# # Download the file and rename it
# url = 'https://git.io/GeoLite2-Country.mmdb'
# filename = 'geoip-lite-country.mmdb'
# try:
#    wget.download(url, filename)
#    # Move the file to the geoip folder
#    os.rename(filename, os.path.join('./geoip-lite', filename))
# except Exception as e:
#    print(f"WARNING: Could not download GeoIP database. Country detection will fail. Error: {e}")
# --- END OF FIX ---


# Clean up unmatched file
try:
    with open("./splitted/no-match", "w") as no_match_file:
        no_match_file.write("#Non-Adaptive Configurations\n")
except FileNotFoundError:
    print("Warning: Directory './splitted/' not found. Could not create 'no-match' file.")


# --- START OF FIX ---
# Safely load last update time
last_update_datetime = datetime.fromtimestamp(0, tz=timezone.utc) # Default to the beginning of time
try:
    with open('./last update', 'r') as file:
        last_update_str = file.readline().strip()
        if last_update_str:
            last_update_datetime = datetime.strptime(last_update_str, '%Y-%m-%d %H:%M:%S.%f%z')
except (FileNotFoundError, ValueError):
    print("Warning: 'last update' file not found or invalid. Starting from scratch.")
    last_update_datetime = datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30))) - timedelta(days=365) # Go back a year on first run
# --- END OF FIX ---

# Write the current date and time update
with open('./last update', 'w') as file:
    current_datetime_update = datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))
    jalali_current_datetime_update = jdatetime.datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))
    file.write(f'{current_datetime_update}')

print(f"Latest Update: {last_update_datetime.strftime('%a, %d %b %Y %X %Z')}\nCurrent Update: {current_datetime_update.strftime('%a, %d %b %Y %X %Z')}")


def get_absolute_paths(start_path):
    abs_paths = []
    if not os.path.exists(start_path):
        return []
    for root, dirs, files in os.walk(start_path):
        for file in files:
            abs_path = Path(root).joinpath(file).resolve()
            abs_paths.append(str(abs_path))
    return abs_paths

dirs_list = ['./security', './protocols', './networks', './layers',
            './subscribe', './splitted', './channels']

if (int(jalali_current_datetime_update.day) == 1 and int(jalali_current_datetime_update.hour) == 0) or (int(jalali_current_datetime_update.day) == 15 and int(jalali_current_datetime_update.hour) == 0):
    print("The All Collected Configurations Cleared Based On Scheduled Day".title())
    last_update_datetime = last_update_datetime - timedelta(days=3)
    print(f"The Latest Update Time Is Set To {last_update_datetime.strftime('%a, %d %b %Y %X %Z')}".title())
    for root_dir in dirs_list:
        for path in get_absolute_paths(root_dir):
            if not path.endswith('readme.md'):
                with open(path, 'w') as file:
                    file.write('')
                    file.close
            else:
                continue


def json_load_safe(path):
    try:
        with open(path, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Warning: Could not load or parse JSON from '{path}'. Returning empty list.")
        return []


def tg_channel_messages(channel_user):
    # --- START OF FIX ---
    # Safely get channel messages
    try:
        print(f"Scraping channel: {channel_user}")
        # Add a timeout and user-agent to the request
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(f"https://t.me/s/{channel_user}", timeout=15, headers=headers)
        response.raise_for_status() # Will raise an error for 4xx/5xx responses
        soup = BeautifulSoup(response.text, "html.parser")
        div_messages = soup.find_all("div", class_="tgme_widget_message")
        return div_messages
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch channel {channel_user}. Error: {e}")
        return [] # Return empty list on failure
    # --- END OF FIX ---


def find_matches(text_content):
    # Initialize configuration type patterns
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

    # Find all matches of patterns in text
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

    # Iterate over matches to subtract titles
    for index, element in enumerate(matches_vmess):
        matches_vmess[index] = re.sub(r"#[^#]+$", "", html.unescape(element))

    for index, element in enumerate(matches_shadowsocks):
        matches_shadowsocks[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#SHADOWSOCKS")

    for index, element in enumerate(matches_trojan):
        matches_trojan[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#TROJAN")

    for index, element in enumerate(matches_vless):
        matches_vless[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#VLESS")

    for index, element in enumerate(matches_reality):
        matches_reality[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#REALITY")

    for index, element in enumerate(matches_tuic):
        matches_tuic[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#TUIC")

    for index, element in enumerate(matches_hysteria):
        matches_hysteria[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#HYSTERIA")

    for index, element in enumerate(matches_hysteria_ver2):
        matches_hysteria_ver2[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#HYSTERIA")

    for index, element in enumerate(matches_juicity):
        matches_juicity[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#JUICITY")

    matches_shadowsocks = [x for x in matches_shadowsocks if "…" not in x]
    matches_trojan = [x for x in matches_trojan if "…" not in x]
    matches_vmess = [x for x in matches_vmess if "…" not in x]
    matches_vless = [x for x in matches_vless if "…" not in x]
    matches_reality = [x for x in matches_reality if "…" not in x]
    matches_tuic = [x for x in matches_tuic if "…" not in x]
    matches_hysteria = [x for x in matches_hysteria if "…" not in x]
    matches_hysteria_ver2 = [x for x in matches_hysteria_ver2 if "…" not in x]
    matches_juicity = [x for x in matches_juicity if "…" not in x]

    # Extend hysteria versions
    matches_hysteria.extend(matches_hysteria_ver2)
    
    return matches_usersname, matches_url, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity


def tg_message_time(div_message):
    try:
        # Retrieve channel message info
        div_message_info = div_message.find('div', class_='tgme_widget_message_info')
        # Retrieve channel message datetime
        message_datetime_tag = div_message_info.find('time')
        message_datetime = message_datetime_tag.get('datetime')

        # Change message datetime type into object and convert into Iran datetime
        datetime_object = datetime.fromisoformat(message_datetime)
        datetime_object = datetime.astimezone(datetime_object, tz = timezone(timedelta(hours = 3, minutes = 30)))

        # Retrieve now datetime based on Iran timezone
        datetime_now = datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))
        
        return datetime_object, datetime_now, datetime_now - datetime_object
    except:
        # Return a default old datetime if parsing fails
        fallback_time = datetime.fromtimestamp(0, tz=timezone.utc)
        return fallback_time, datetime.now(tz=timezone.utc), timedelta(days=9999)


def tg_message_text(div_message, content_extracter):
    try:
        # Retrieve message text class from telegram messages widget
        div_message_text = div_message.find("div", class_="tgme_widget_message_text")
        if not div_message_text: return ""
        text_content = div_message_text.prettify()
        if content_extracter == 'url':
            text_content = re.sub(r"<code>([^<>]+)</code>", r"\1",re.sub(r"\s*", "", text_content),)
        elif content_extracter == 'config':
            text_content = re.sub(r"<code>([^<>]+)</code>", r"\1",
                                re.sub(r"<a[^<>]+>([^<>]+)</a>", r"\1",re.sub(r"\s*", "", text_content),),)
        
        return text_content
    except:
        return ""


# Load telegram channels usernames
telegram_channels = json_load_safe('telegram_channels.json')

# Initial channels messages array
channel_messages_array = list()
removed_channel_array = list()
channel_check_messages_array = list()

# Iterate over all public telegram chanels and store twenty latest messages
for channel_user in telegram_channels:
    div_messages = tg_channel_messages(channel_user)
    
    if len(div_messages) == 0:
        removed_channel_array.append(channel_user)
        continue

    channel_check_messages_array.append((channel_user, div_messages))
    
    for div_message in div_messages:
        datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
        if datetime_object > last_update_datetime:
            print(f"\tFound new message from: {datetime_object.strftime('%a, %d %b %Y %X %Z')}")
            channel_messages_array.append((channel_user, div_message))

# Print out total new messages counter
print(f"\nTotal New Messages From {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(channel_messages_array)}\n")


# Initial arrays for protocols
array_usernames = list()
array_url = list()
array_shadowsocks = list()
array_trojan = list()
array_vmess = list()
array_vless = list()
array_reality = list()
array_tuic = list()
array_hysteria = list()
array_juicity = list()

for channel_user, message in channel_messages_array:
    # Iterate over channel messages to extract text content
    url_text_content = tg_message_text(message, 'url')
    config_text_content = tg_message_text(message, 'config')
    # Iterate over each message to extract configuration protocol types and subscription links
    matches_username, matches_url, _ , _ , _ , _ , _ , _ , _ , _ = find_matches(url_text_content)
    _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)

    # Extend protocol type arrays and subscription link array
    array_usernames.extend([element.lower() for element in matches_username if len(element) >= 5])
    array_url.extend(matches_url)
    array_shadowsocks.extend(matches_shadowsocks)
    array_trojan.extend(matches_trojan)
    array_vmess.extend(matches_vmess)
    array_vless.extend(matches_vless)
    array_reality.extend(matches_reality)
    array_tuic.extend(matches_tuic)
    array_hysteria.extend(matches_hysteria)
    array_juicity.extend(matches_juicity)


# Initialize Telegram channels list without configuration
channel_without_config = set()

for channel_user, messages in channel_check_messages_array:
    total_config = 0
    for message in messages:
        config_text_content = tg_message_text(message, 'config')
        _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)
        total_config += len(matches_shadowsocks) + len(matches_trojan) + len(matches_vmess) + len(matches_vless) + len(matches_reality) + len(matches_tuic) + len(matches_hysteria) + len(matches_juicity)

    if total_config == 0:
        channel_without_config.add(channel_user)


def tg_username_extract(url):
    try:
        telegram_pattern = r'((http|Http|HTTP)://|(https|Https|HTTPS)://|(www|Www|WWW)\.|https://www\.|)(?P<telegram_domain>(t|T)\.(me|Me|ME)|(telegram|Telegram|TELEGRAM)\.(me|Me|ME)|(telegram|Telegram|TELEGRAM).(org|Org|ORG)|telesco.pe|(tg|Tg|TG).(dev|Dev|DEV)|(telegram|Telegram|TELEGRAM).(dog|Dog|DOG))/(?P<username>[a-zA-Z0-9_+-]+)'
        matches_url = re.match(telegram_pattern, url)
        return matches_url.group('username')
    except:
        return None

# Split Telegram usernames and subscription url links
tg_username_list = set()
url_subscription_links = set()

for url in array_url:
    tg_user = tg_username_extract(url)
    if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user)>=5:
        tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
        tg_username_list.add(tg_user.lower())
    else:
        url_subscription_links.add(url.split("\"")[0])

for index, tg_user in enumerate(array_usernames):
    tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
    array_usernames[index] = tg_user


# --- START OF FIX ---
# This network call is disabled. It now safely loads the local file if it exists.
# url = 'https://raw.githubusercontent.com/konabalan/TelConCol/main/telegram_channels.json'
# filename = 'telegram proxies channel.json'
# print(f"[*] DEBUG: Attempting to download file from this URL: {url}")
# # wget.download(url, filename)

tg_username_list.update(array_usernames)
telegram_proxies_channel = json_load_safe('./telegram proxies channel.json')
tg_username_list.update(telegram_proxies_channel)
# os.remove('./telegram proxies channel.json') # Don't remove if we didn't download it
# --- END OF FIX ---


# Subtract and get new telegram channels
new_telegram_channels = tg_username_list.difference(telegram_channels)

# Initial channels messages array
new_channel_messages = list()
invalid_array_channels = set(json_load_safe('invalid telegram_channels.json'))


# Iterate over all public telegram chanels and store twenty latest messages
for channel_user in new_telegram_channels:
    if channel_user not in invalid_array_channels:
        div_messages = tg_channel_messages(channel_user)
        channel_messages = list()
        for div_message in div_messages:
            datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
            print(f"\tNew msg from new channel {channel_user}: {datetime_object.strftime('%a, %d %b %Y %X %Z')}")
            channel_messages.append(div_message)
        if channel_messages:
            new_channel_messages.append((channel_user, channel_messages))

# Messages Counter
print(f"\nTotal New Messages From New Channels {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(new_channel_messages)}\n")


# Initial arrays for protocols
new_array_shadowsocks = list()
new_array_trojan = list()
new_array_vmess = list()
new_array_vless = list()
new_array_reality = list()
new_array_tuic = list()
new_array_hysteria = list()
new_array_juicity = list()

# Initialize array for channelswith configuration contents
new_array_channels = set()

for channel, messages in new_channel_messages:
    # Set Iterator to estimate each channel configurations
    total_config = 0
    new_array_url = set()
    new_array_usernames = set()

    for message in messages:
        # Iterate over channel messages to extract text content
        url_text_content = tg_message_text(message, 'url')
        config_text_content = tg_message_text(message, 'config')
        # Iterate over each message to extract configuration protocol types and subscription links
        matches_username, matches_url, _ , _ , _ , _ , _ , _ , _ , _ = find_matches(url_text_content)
        _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)
        total_config += len(matches_shadowsocks) + len(matches_trojan) + len(matches_vmess) + len(matches_vless) + len(matches_reality) + len(matches_tuic) + len(matches_hysteria) + len(matches_juicity)

        # Extend protocol type arrays and subscription link array
        new_array_usernames.update([element.lower() for element in matches_username if len(element) >= 5])
        new_array_url.update(matches_url)
        new_array_shadowsocks.extend(matches_shadowsocks)
        new_array_trojan.extend(matches_trojan)
        new_array_vmess.extend(matches_vmess)
        new_array_vless.extend(matches_vless)
        new_array_reality.extend(matches_reality)
        new_array_tuic.extend(matches_tuic)
        new_array_hysteria.extend(matches_hysteria)
        new_array_juicity.extend(matches_juicity)

    # Append to channels that conatins configurations
    if total_config != 0:
        new_array_channels.add(channel)
    else:
        invalid_array_channels.add(channel)

    # Split Telegram usernames and subscription url links
    tg_username_list_new = set()

    for url in new_array_url:
        tg_user = tg_username_extract(url)
        if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user)>=5:
            tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
            tg_username_list_new.add(tg_user.lower())
        else:
            url_subscription_links.add(url.split("\"")[0])

    new_array_usernames = list(new_array_usernames)
    for index, tg_user in enumerate(new_array_usernames):
        tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
        new_array_usernames[index] = tg_user

    # Subtract and get new telegram channels
    tg_username_list_new.update([element.lower() for element in new_array_usernames])
    tg_username_list_new = tg_username_list_new.difference(telegram_channels)
    tg_username_list_new = tg_username_list_new.difference(new_telegram_channels)
    updated_new_channel = set(list(map(lambda element : element[0], new_channel_messages)))
    tg_username_list_new = tg_username_list_new.difference(updated_new_channel)

    # Iterate over all public telegram chanels and store twenty latest messages
    for channel_user in tg_username_list_new:
        if channel_user not in invalid_array_channels:
            div_messages = tg_channel_messages(channel_user)
            channel_messages = list()
            for div_message in div_messages:
                datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
                channel_messages.append(div_message)


# Extend new configurations into list previous ones
array_shadowsocks.extend(new_array_shadowsocks)
array_trojan.extend(new_array_trojan)
array_vmess.extend(new_array_vmess)
array_vless.extend(new_array_vless)
array_reality.extend(new_array_reality)
array_tuic.extend(new_array_tuic)
array_hysteria.extend(new_array_hysteria)
array_juicity.extend(new_array_juicity)

print("New Telegram Channels Found")
for channel in new_array_channels:
    print(f'\t{channel}')

print("Destroyed Telegram Channels Found")
for channel in removed_channel_array:
    print(f'\t{channel}')

print("No Config Telegram Channels Found")
for channel in channel_without_config:
    print(f'\t{channel}')

# Extend new channels into previous channels
telegram_channels.extend(list(new_array_channels))
telegram_channels = [channel for channel in telegram_channels if channel not in removed_channel_array]
telegram_channels = list(set(telegram_channels))
telegram_channels = sorted(telegram_channels)

invalid_telegram_channels = list(set(invalid_array_channels))
invalid_telegram_channels = sorted(invalid_telegram_channels)

with open('./telegram_channels.json', 'w') as telegram_channels_file:
    json.dump(telegram_channels, telegram_channels_file, indent = 4)

with open('./invalid telegram_channels.json', 'w') as invalid_telegram_channels_file:
    json.dump(invalid_telegram_channels, invalid_telegram_channels_file, indent = 4)

def html_content(html_address):
    # --- START OF FIX ---
    # Safely get subscription link content
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(html_address, timeout = 15, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser').text
        return soup
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch subscription link {html_address}. Error: {e}")
        return "" # Return empty string on failure
    # --- END OF FIX ---


def is_valid_base64(string_value):
    try:
        # Decode the string using base64
        return base64.b64encode(base64.b64decode(string_value)).decode("utf-8") == string_value
    except:
        return False


def decode_string(content):
    # Decode strings and append to array
    if is_valid_base64(content):
        try:
            content = base64.b64decode(content).decode("utf-8")
        except:
            return "" # Return empty if decoding fails
    return content


def decode_vmess(vmess_config):
    try:
        encoded_config = re.sub(r"vmess://", "", vmess_config)
        decoded_config = base64.b64decode(encoded_config).decode("utf-8")
        decoded_config_dict = json.loads(decoded_config)
        
        decoded_config_dict["ps"] = f"VMESS"
        decoded_config = json.dumps(decoded_config_dict)

        encoded_config = base64.b64encode(decoded_config.encode('utf-8')).decode('utf-8')
        encoded_config = f"vmess://{encoded_config}"
        return encoded_config
    except:
        return None


# Update url subscription links
url_subscription_links = list(url_subscription_links)

new_tg_username_list = set()
new_url_subscription_links = set()

for url in url_subscription_links:
    tg_user = tg_username_extract(url)
    if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat']:
        new_tg_username_list.add(tg_user.lower())
    else:
        new_url_subscription_links.add(url.split("\"")[0])

# Chnage type of url subscription links into list to be hashable
new_url_subscription_links = list(new_url_subscription_links)


accept_chars = ['sub', 'subscribe', 'token', 'workers', 'worker', 'dev', 'txt', 'vmess', 'vless', 'reality', 'trojan', 'shadowsocks']
avoid_chars = ['github', 'githubusercontent', 'gist', 'git', 'google', 'play', 'apple', 'microsoft']

new_subscription_links = set()

for index, element in enumerate(new_url_subscription_links):
    acc_cond = [char in element.lower() for char in accept_chars]
    avoid_cond = [char in element.lower() for char in avoid_chars]
    if any(acc_cond):
        if not any(avoid_cond):
            new_subscription_links.add(element)


# Load subscription links
subscription_links = json_load_safe('subscription_links.json')
# subscription_links.extend(new_subscription_links)

# Initial links contents array decoded content array
array_links_content = list()
array_links_content_decoded = list()

raw_array_links_content = list()
raw_array_links_content_decoded = list()

channel_array_links_content = list()
channel_array_links_content_decoded = list()

for url_link in subscription_links:
    links_content = html_content(url_link)
    if not links_content: continue # Skip if content is empty
    
    array_links_content.append((url_link, links_content))
    if 'konabalan/TelConCol' not in url_link:
        raw_array_links_content.append((url_link, links_content))
    elif 'konabalan/TelConCol' in url_link and 'channels' in url_link:
        channel_array_links_content.append((url_link, links_content))


# Separate encoded and unencoded strings
decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), array_links_content))
# Separate encoded and unencoded strings
raw_decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), raw_array_links_content))
# Separate encoded and unencoded strings
channel_decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), channel_array_links_content))

for url_link, content in decoded_contents:
    # Split each link contents into array and split by lines
    link_contents = content.splitlines()
    link_contents = [element for element in link_contents if element.strip()]
    # Iterate over link contents to subtract titles
    for index, element in enumerate(link_contents):
        link_contents[index] = re.sub(r"#[^#]+$", "", element)
    array_links_content_decoded.append((url_link, link_contents))


for url_link, content in raw_decoded_contents:
    # Split each link contents into array and split by lines
    link_contents = content.splitlines()
    link_contents = [element for element in link_contents if element.strip()]
    # Iterate over link contents to subtract titles
    for index, element in enumerate(link_contents):
        link_contents[index] = re.sub(r"#[^#]+$", "", element)
    raw_array_links_content_decoded.append((url_link, link_contents))


for url_link, content in channel_decoded_contents:
    # Split each link contents into array and split by lines
    link_contents = content.splitlines()
    link_contents = [element for element in link_contents if element.strip()]
    # Iterate over link contents to subtract titles
    for index, element in enumerate(link_contents):
        link_contents[index] = re.sub(r"#[^#]+$", "", element)
    channel_array_links_content_decoded.append((url_link, link_contents))

# --- END OF COPY-PASTE FOR PART 2 ---
# (The rest of the file continues from here)