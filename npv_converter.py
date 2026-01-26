import json
import base64
import os
from urllib.parse import quote, unquote, parse_qs, urlparse

def json_to_vless_uri(json_data):
    """Convert NPV JSON to vless:// URI"""
    data = json.loads(json_data) if isinstance(json_data, str) else json_data
    
    outbound = data['outbounds'][0]
    protocol = outbound['protocol']
    remarks = data.get('remarks', 'config')
    
    if protocol == 'vless':
        return convert_vless(outbound, remarks)
    elif protocol == 'vmess':
        return convert_vmess(outbound, remarks)
    elif protocol == 'trojan':
        return convert_trojan(outbound, remarks)
    else:
        return None

def convert_vless(outbound, remarks):
    server = outbound['settings']['vnext'][0]
    user = server['users'][0]
    stream = outbound['streamSettings']
    
    uuid = user['id']
    address = server['address']
    port = server['port']
    
    params = []
    params.append(f"encryption={user.get('encryption', 'none')}")
    
    if user.get('flow'):
        params.append(f"flow={user['flow']}")
    
    params.append(f"security={stream.get('security', 'none')}")
    params.append(f"type={stream.get('network', 'tcp')}")
    
    if stream.get('security') == 'reality':
        reality = stream['realitySettings']
        params.append(f"sni={reality['serverName']}")
        params.append(f"fp={reality['fingerprint']}")
        params.append(f"pbk={reality['publicKey']}")
        params.append(f"sid={reality['shortId']}")
    
    elif stream.get('security') == 'tls':
        tls = stream.get('tlsSettings', {})
        if tls.get('serverName'):
            params.append(f"sni={tls['serverName']}")
        if tls.get('fingerprint'):
            params.append(f"fp={tls['fingerprint']}")
    
    if stream.get('network') == 'tcp':
        tcp = stream.get('tcpSettings', {})
        header_type = tcp.get('header', {}).get('type', 'none')
        params.append(f"headerType={header_type}")
    
    elif stream.get('network') == 'ws':
        ws = stream.get('wsSettings', {})
        if ws.get('path'):
            params.append(f"path={quote(ws['path'])}")
        if ws.get('host'):
            params.append(f"host={ws['host']}")
    
    elif stream.get('network') == 'grpc':
        grpc = stream.get('grpcSettings', {})
        if grpc.get('serviceName'):
            params.append(f"serviceName={quote(grpc['serviceName'])}")
    
    param_str = "&".join(params)
    uri = f"vless://{uuid}@{address}:{port}?{param_str}#{quote(remarks)}"
    
    return uri

def convert_vmess(outbound, remarks):
    server = outbound['settings']['vnext'][0]
    user = server['users'][0]
    stream = outbound['streamSettings']
    
    vmess_obj = {
        "v": "2",
        "ps": remarks,
        "add": server['address'],
        "port": str(server['port']),
        "id": user['id'],
        "aid": str(user.get('alterId', 0)),
        "net": stream.get('network', 'tcp'),
        "type": "none",
        "host": "",
        "path": "",
        "tls": stream.get('security', 'none'),
        "sni": "",
        "alpn": ""
    }
    
    if stream.get('network') == 'ws':
        ws = stream.get('wsSettings', {})
        vmess_obj['path'] = ws.get('path', '')
        vmess_obj['host'] = ws.get('host', '')
    elif stream.get('network') == 'grpc':
        grpc = stream.get('grpcSettings', {})
        vmess_obj['path'] = grpc.get('serviceName', '')
    
    if stream.get('security') == 'tls':
        tls = stream.get('tlsSettings', {})
        vmess_obj['sni'] = tls.get('serverName', '')
    
    json_str = json.dumps(vmess_obj, separators=(',', ':'))
    encoded = base64.b64encode(json_str.encode()).decode()
    
    return f"vmess://{encoded}"

def convert_trojan(outbound, remarks):
    server = outbound['settings']['servers'][0]
    stream = outbound['streamSettings']
    
    password = server['password']
    address = server['address']
    port = server['port']
    
    params = []
    params.append(f"security={stream.get('security', 'tls')}")
    params.append(f"type={stream.get('network', 'tcp')}")
    
    if stream.get('security') == 'tls':
        tls = stream.get('tlsSettings', {})
        if tls.get('serverName'):
            params.append(f"sni={tls['serverName']}")
    
    param_str = "&".join(params)
    uri = f"trojan://{password}@{address}:{port}?{param_str}#{quote(remarks)}"
    
    return uri

# ==================== DEDUPLICATION ====================

def extract_config_fingerprint(uri):
    """Extract unique fingerprint from config URI"""
    try:
        if uri.startswith('vless://'):
            protocol = 'vless'
            uri = uri.replace('vless://', '')
            if '#' in uri:
                uri = uri.split('#')[0]
            
            user_part, rest = uri.split('@')
            uuid = user_part
            address_port = rest.split('?')[0]
            address, port = address_port.rsplit(':', 1)
            
            return (protocol, address, port, uuid)
        
        elif uri.startswith('vmess://'):
            protocol = 'vmess'
            encoded = uri.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode()
            data = json.loads(decoded)
            
            return (protocol, data['add'], data['port'], data['id'])
        
        elif uri.startswith('trojan://'):
            protocol = 'trojan'
            uri = uri.replace('trojan://', '')
            if '#' in uri:
                uri = uri.split('#')[0]
            
            password_part, rest = uri.split('@')
            password = password_part
            address_port = rest.split('?')[0]
            address, port = address_port.rsplit(':', 1)
            
            return (protocol, address, port, password)
        
        else:
            return None
    except Exception as e:
        print(f"⚠️  Error extracting fingerprint: {e}")
        return None

def load_existing_configs(output_file='subscription.txt'):
    """Load existing configs from output file"""
    if not os.path.exists(output_file):
        return set()
    
    fingerprints = set()
    with open(output_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                fp = extract_config_fingerprint(line)
                if fp:
                    fingerprints.add(fp)
    
    return fingerprints

def deduplicate_configs(new_configs, existing_fingerprints):
    """Remove duplicates from new configs"""
    unique_configs = []
    seen_in_batch = set()
    duplicates = 0
    
    for config in new_configs:
        fp = extract_config_fingerprint(config)
        if fp is None:
            continue
        
        if fp in existing_fingerprints or fp in seen_in_batch:
            duplicates += 1
            print(f"⏭️  Duplicate skipped: {config[:60]}...")
        else:
            unique_configs.append(config)
            seen_in_batch.add(fp)
            existing_fingerprints.add(fp)
    
    return unique_configs, duplicates

# ==================== MAIN FUNCTION ====================

def convert_from_file(input_file):
    """Read JSON from a text file and convert"""
    print(f"📖 Reading from: {input_file}")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    configs = []
    
    # Try as single JSON first
    try:
        uri = json_to_vless_uri(content)
        if uri:
            configs.append(uri)
            print(f"✅ Converted 1 config")
            return configs
    except:
        pass
    
    # Try as multiple JSONs (one per line)
    for line_num, line in enumerate(content.split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            uri = json_to_vless_uri(line)
            if uri:
                configs.append(uri)
                print(f"✅ Line {line_num} converted")
        except Exception as e:
            print(f"❌ Line {line_num} failed: {e}")
    
    return configs

def save_configs(configs, output_file='subscription.txt', append=True):
    """Save configs to file"""
    mode = 'a' if append else 'w'
    
    with open(output_file, mode, encoding='utf-8') as f:
        f.write('\n'.join(configs))
        if configs:
            f.write('\n')
    
    print(f"\n💾 Saved to: {output_file}")
    
    # Rebuild base64 file
    with open(output_file, 'r', encoding='utf-8') as f:
        all_configs = [line.strip() for line in f if line.strip()]
    
    encoded = base64.b64encode('\n'.join(all_configs).encode()).decode()
    with open('subscription_base64.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)
    print(f"💾 Base64 saved to: subscription_base64.txt")
    
    print(f"\n📊 Total configs in subscription: {len(all_configs)}")

if __name__ == "__main__":
    print("=" * 60)
    print("NPV JSON to V2Ray URI Converter (with Deduplication)")
    print("=" * 60)
    
    # Support environment variable for GitHub Actions
    input_file = os.environ.get('INPUT_FILE', 'npv_configs.txt')
    output_file = 'subscription.txt'
    
    if not os.path.exists(input_file):
        print(f"\n⚠️  File '{input_file}' not found!")
        print("\n📝 Instructions:")
        print("1. Create a file called 'npv_configs.txt'")
        print("2. Paste your NPV JSON(s) into it")
        print("3. One JSON per line, lines with # are ignored")
        print("4. Run this script again")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write("# Paste your NPV JSON exports here\n")
            f.write("# One JSON per line\n")
        print(f"\n✅ Created example file: {input_file}")
    else:
        print(f"\n🔍 Checking for existing configs in {output_file}...")
        existing_fingerprints = load_existing_configs(output_file)
        print(f"📊 Found {len(existing_fingerprints)} existing configs")
        
        print(f"\n🔄 Converting new configs...\n")
        new_configs = convert_from_file(input_file)
        
        if new_configs:
            print(f"\n🔍 Deduplicating configs...")
            unique_configs, duplicates = deduplicate_configs(new_configs, existing_fingerprints)
            
            print(f"\n📊 Results:")
            print(f"   • New configs converted: {len(new_configs)}")
            print(f"   • Duplicates found: {duplicates}")
            print(f"   • Unique configs to add: {len(unique_configs)}")
            
            if unique_configs:
                save_configs(unique_configs, output_file, append=True)
                
                print("\n" + "=" * 60)
                print("✅ DONE! New unique configs added:")
                print("=" * 60)
                for i, cfg in enumerate(unique_configs, 1):
                    print(f"{i}. {cfg[:70]}...")
            else:
                print("\n⚠️  No new unique configs to add (all were duplicates)")
        else:
            print("\n❌ No valid configs found!")
