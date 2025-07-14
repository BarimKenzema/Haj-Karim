# FINAL SCRIPT v30: Simple & Robust
import os, uuid, time, random, json, pycountry_convert as pc, html, socket, ipaddress, tldextract, geoip2.database, re, base64
from urllib.parse import urlparse, parse_qs

print("--- title.py: STARTING SCRIPT (v30 - Simple & Robust) ---")

def get_ips(node):
    try:
        from dns import resolver, rdatatype
        if not node or not isinstance(node, str): return None
        if ipaddress.ip_address(node): return [node]
    except:
        try:
            res = resolver.Resolver(); res.nameservers = ["8.8.8.8", "1.1.1.1"]
            ips = set()
            for rdtype in ("A", "AAAA"):
                try:
                    answers = res.resolve(node, rdtype, raise_on_no_answer=False)
                    if answers: ips.update({rdata.address for rdata in answers})
                except: continue
            return list(ips) if ips else None
        except Exception: return None
    return None

def get_country_from_ip(ip):
    db_path = "./geoip-lite/geoip-lite-country.mmdb"
    if not os.path.exists(db_path): return "XX"
    try:
        with geoip2.database.Reader(db_path) as reader:
            return reader.country(ip).country.iso_code or "XX"
    except: return "XX"

def config_sort(configs):
    return sorted(configs) # Simple sort is enough

def check_modify_config(config_list, protocol_type, check_connection=True):
    modified_array = []
    print(f"--- Processing {len(config_list)} configs for {protocol_type} ---")
    for element in config_list:
        try:
            if "://" not in element: continue
            host, port = None, None
            parsed_url = urlparse(element)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                if element.startswith("vmess://"):
                    json_str = element.replace("vmess://", "").strip()
                    if len(json_str) % 4 != 0: json_str += '=' * (4 - len(json_str) % 4)
                    decoded = json.loads(base64.b64decode(json_str).decode('utf-8', 'ignore'))
                    host, port = decoded.get('add'), decoded.get('port')
                if not host or not port: continue
            
            # Since we pre-filter, we just need to get the IP
            ips = get_ips(host)
            if not ips: continue
            ip_address = ips[0]
            
            country_code = get_country_from_ip(ip_address)
            
            # Rebuild the fragment with the country code for later use
            fragment = f"#{country_code}-{host}"
            new_config = parsed_url._replace(fragment=fragment).geturl()
            modified_array.append(new_config)
        except:
            continue
    print(f"--- Finished processing for {protocol_type}. Kept {len(modified_array)} configs. ---")
    return modified_array, [],[],[],[],[],[] # Return dummy lists for other categories

def create_country(configs):
    country_dict = {}
    for config in configs:
        try:
            fragment = urlparse(config).fragment
            country_code = fragment.split('-')[0].lower()
            if country_code:
                if country_code not in country_dict: country_dict[country_code] = []
                country_dict[country_code].append(config)
        except:
            continue
    return country_dict
    
# Keep other functions as placeholders
def create_internet_protocol(a): return [],[]
