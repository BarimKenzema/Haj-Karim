import json
import base64
import os
import re
from urllib.parse import quote

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
    stream = outbound.get('streamSettings', {})
    
    uuid = user['id']
    address = server['address']
    port = server['port']
    
    params = []
    params.append(f"encryption={user.get('encryption', 'none')}")
    
    # Flow (optional)
    if user.get('flow'):
        params.append(f"flow={user['flow']}")
    
    # Security
    security = stream.get('security', 'none')
    params.append(f"security={security}")
    
    # Network type
    network = stream.get('network', 'tcp')
    params.append(f"type={network}")
    
    # Reality settings (all optional)
    if security == 'reality':
        reality = stream.get('realitySettings', {})
        
        # serverName/SNI (optional but common)
        if reality.get('serverName'):
            params.append(f"sni={reality['serverName']}")
        
        # fingerprint (optional)
        if reality.get('fingerprint'):
            params.append(f"fp={reality['fingerprint']}")
        
        # publicKey (required for reality, but handle gracefully)
        if reality.get('publicKey'):
            params.append(f"pbk={reality['publicKey']}")
        
        # shortId (OPTIONAL - this was causing the error!)
        if reality.get('shortId'):
            params.append(f"sid={reality['shortId']}")
        # If no shortId, just don't add the parameter
        
        # spiderX (optional)
        if reality.get('spiderX'):
            params.append(f"spx={quote(reality['spiderX'])}")
    
    # TLS settings (all optional)
    elif security == 'tls':
        tls = stream.get('tlsSettings', {})
        
        if tls.get('serverName'):
            params.append(f"sni={tls['serverName']}")
        
        if tls.get('fingerprint'):
            params.append(f"fp={tls['fingerprint']}")
        
        if tls.get('alpn'):
            alpn = tls['alpn']
            if isinstance(alpn, list):
                alpn = ','.join(alpn)
            params.append(f"alpn={quote(alpn)}")
        
        if tls.get('allowInsecure'):
            params.append(f"allowInsecure=1")
    
    # TCP settings
    if network == 'tcp':
        tcp = stream.get('tcpSettings', {})
        header = tcp.get('header', {})
        header_type = header.get('type', 'none')
        params.append(f"headerType={header_type}")
        
        # HTTP header settings (for header type = http)
        if header_type == 'http':
            request = header.get('request', {})
            if request.get('path'):
                path = request['path']
                if isinstance(path, list):
                    path = path[0]
                params.append(f"path={quote(path)}")
            if request.get('headers', {}).get('Host'):
                host = request['headers']['Host']
                if isinstance(host, list):
                    host = host[0]
                params.append(f"host={host}")
    
    # WebSocket settings
    elif network == 'ws':
        ws = stream.get('wsSettings', {})
        if ws.get('path'):
            params.append(f"path={quote(ws['path'])}")
        if ws.get('host'):
            params.append(f"host={ws['host']}")
        # Also check headers for host
        headers = ws.get('headers', {})
        if headers.get('Host') and not ws.get('host'):
            params.append(f"host={headers['Host']}")
    
    # gRPC settings
    elif network == 'grpc':
        grpc = stream.get('grpcSettings', {})
        if grpc.get('serviceName'):
            params.append(f"serviceName={quote(grpc['serviceName'])}")
        if grpc.get('mode'):
            params.append(f"mode={grpc['mode']}")
    
    # HTTP/2 settings
    elif network in ['h2', 'http']:
        h2 = stream.get('httpSettings', {})
        if h2.get('path'):
            params.append(f"path={quote(h2['path'])}")
        if h2.get('host'):
            host = h2['host']
            if isinstance(host, list):
                host = ','.join(host)
            params.append(f"host={host}")
    
    # QUIC settings
    elif network == 'quic':
        quic = stream.get('quicSettings', {})
        if quic.get('security'):
            params.append(f"quicSecurity={quic['security']}")
        if quic.get('key'):
            params.append(f"key={quote(quic['key'])}")
        if quic.get('header', {}).get('type'):
            params.append(f"headerType={quic['header']['type']}")
    
    # KCP settings
    elif network == 'kcp':
        kcp = stream.get('kcpSettings', {})
        if kcp.get('seed'):
            params.append(f"seed={quote(kcp['seed'])}")
        if kcp.get('header', {}).get('type'):
            params.append(f"headerType={kcp['header']['type']}")
    
    param_str = "&".join(params)
    uri = f"vless://{uuid}@{address}:{port}?{param_str}#{quote(remarks)}"
    
    return uri

def convert_vmess(outbound, remarks):
    server = outbound['settings']['vnext'][0]
    user = server['users'][0]
    stream = outbound.get('streamSettings', {})
    
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
        "tls": stream.get('security', 'none') if stream.get('security') != 'reality' else 'tls',
        "sni": "",
        "alpn": ""
    }
    
    network = stream.get('network', 'tcp')
    
    # WebSocket
    if network == 'ws':
        ws = stream.get('wsSettings', {})
        vmess_obj['path'] = ws.get('path', '')
        vmess_obj['host'] = ws.get('host', '')
        if not vmess_obj['host']:
            vmess_obj['host'] = ws.get('headers', {}).get('Host', '')
    
    # gRPC
    elif network == 'grpc':
        grpc = stream.get('grpcSettings', {})
        vmess_obj['path'] = grpc.get('serviceName', '')
    
    # HTTP/2
    elif network in ['h2', 'http']:
        h2 = stream.get('httpSettings', {})
        vmess_obj['path'] = h2.get('path', '')
        host = h2.get('host', [])
        if isinstance(host, list) and host:
            vmess_obj['host'] = host[0]
        elif isinstance(host, str):
            vmess_obj['host'] = host
    
    # TCP with HTTP header
    elif network == 'tcp':
        tcp = stream.get('tcpSettings', {})
        header = tcp.get('header', {})
        if header.get('type') == 'http':
            vmess_obj['type'] = 'http'
            request = header.get('request', {})
            path = request.get('path', [])
            if isinstance(path, list) and path:
                vmess_obj['path'] = path[0]
            host = request.get('headers', {}).get('Host', [])
            if isinstance(host, list) and host:
                vmess_obj['host'] = host[0]
    
    # TLS settings
    security = stream.get('security', 'none')
    if security in ['tls', 'reality']:
        tls_key = 'tlsSettings' if security == 'tls' else 'realitySettings'
        tls = stream.get(tls_key, {})
        vmess_obj['sni'] = tls.get('serverName', '')
        alpn = tls.get('alpn', [])
        if isinstance(alpn, list):
            vmess_obj['alpn'] = ','.join(alpn)
        elif isinstance(alpn, str):
            vmess_obj['alpn'] = alpn
    
    json_str = json.dumps(vmess_obj, separators=(',', ':'))
    encoded = base64.b64encode(json_str.encode()).decode()
    
    return f"vmess://{encoded}"

def convert_trojan(outbound, remarks):
    server = outbound['settings']['servers'][0]
    stream = outbound.get('streamSettings', {})
    
    password = server['password']
    address = server['address']
    port = server['port']
    
    params = []
    
    # Security
    security = stream.get('security', 'tls')
    params.append(f"security={security}")
    
    # Network type
    network = stream.get('network', 'tcp')
    params.append(f"type={network}")
    
    # TLS settings
    if security == 'tls':
        tls = stream.get('tlsSettings', {})
        if tls.get('serverName'):
            params.append(f"sni={tls['serverName']}")
        if tls.get('fingerprint'):
            params.append(f"fp={tls['fingerprint']}")
        if tls.get('alpn'):
            alpn = tls['alpn']
            if isinstance(alpn, list):
                alpn = ','.join(alpn)
            params.append(f"alpn={quote(alpn)}")
    
    # Reality settings
    elif security == 'reality':
        reality = stream.get('realitySettings', {})
        if reality.get('serverName'):
            params.append(f"sni={reality['serverName']}")
        if reality.get('fingerprint'):
            params.append(f"fp={reality['fingerprint']}")
        if reality.get('publicKey'):
            params.append(f"pbk={reality['publicKey']}")
        if reality.get('shortId'):
            params.append(f"sid={reality['shortId']}")
    
    # WebSocket
    if network == 'ws':
        ws = stream.get('wsSettings', {})
        if ws.get('path'):
            params.append(f"path={quote(ws['path'])}")
        if ws.get('host'):
            params.append(f"host={ws['host']}")
    
    # gRPC
    elif network == 'grpc':
        grpc = stream.get('grpcSettings', {})
        if grpc.get('serviceName'):
            params.append(f"serviceName={quote(grpc['serviceName'])}")
    
    param_str = "&".join(params)
    uri = f"trojan://{password}@{address}:{port}?{param_str}#{quote(remarks)}"
    
    return uri

# ==================== JSON EXTRACTION ====================

def extract_json_objects(text):
    """
    Extract all JSON objects from text, regardless of formatting.
    """
    json_objects = []
    text = text.strip()
    
    if not text:
        return json_objects
    
    # Method 1: Try as single JSON first
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            json_objects.append(text)
            return json_objects
    except:
        pass
    
    # Method 2: Track braces to find individual JSON objects
    depth = 0
    start_index = None
    in_string = False
    escape_next = False
    
    for i, char in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\' and in_string:
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if in_string:
            continue
        
        if char == '{':
            if depth == 0:
                start_index = i
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0 and start_index is not None:
                json_str = text[start_index:i + 1]
                try:
                    json.loads(json_str)
                    json_objects.append(json_str)
                except:
                    pass
                start_index = None
    
    return json_objects

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
        content = f.read()
    
    # Remove comment lines
    lines = content.split('\n')
    filtered_lines = [line for line in lines if not line.strip().startswith('#')]
    content = '\n'.join(filtered_lines)
    
    # Extract all JSON objects
    print(f"🔍 Extracting JSON objects...")
    json_objects = extract_json_objects(content)
    print(f"📦 Found {len(json_objects)} JSON object(s)")
    
    # Convert each JSON to URI
    configs = []
    for i, json_str in enumerate(json_objects, 1):
        try:
            uri = json_to_vless_uri(json_str)
            if uri:
                configs.append(uri)
                print(f"✅ Config {i} converted")
        except Exception as e:
            print(f"❌ Config {i} failed: {e}")
    
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
    print("NPV JSON to V2Ray URI Converter")
    print("(with Deduplication + Smart JSON Detection)")
    print("=" * 60)
    
    # Support environment variable for GitHub Actions
    input_file = os.environ.get('INPUT_FILE', 'npv_configs.txt')
    output_file = 'subscription.txt'
    
    if not os.path.exists(input_file):
        print(f"\n⚠️  File '{input_file}' not found!")
        print("\n📝 Instructions:")
        print("1. Create a file called 'npv_configs.txt'")
        print("2. Paste your NPV JSON(s) into it")
        print("3. You can paste in ANY format:")
        print("   - One JSON per line")
        print("   - Multiple JSONs on same line")
        print("   - All JSONs concatenated together")
        print("   - Mixed formats")
        print("4. Lines starting with # are ignored")
        print("5. Run this script again")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write("# Paste your NPV JSON exports here\n")
            f.write("# Any format works - just paste everything!\n")
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
            print(f"   • JSON objects found: {len(new_configs)}")
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
        
        print("\n💡 TIP: Clear npv_configs.txt and paste more configs anytime")
