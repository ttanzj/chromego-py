# -*- coding: UTF-8 -*-
"""
最小改动优化版 - 增加对 TUIC、VLESS Reality、Trojan、VMess、SS 等协议的支持
尽量保持原有结构，只增强 process_json 中的参数提取
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logging.warning("GeoLite2-City.mmdb not found")

def get_location(ip):
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

def make_fingerprint(p):
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = [p.strip() for p in srv.split(',')]
        main_part = parts[0]
        if len(parts) > 1 and '-' in parts[-1]:
            ports_range = parts[-1]
        srv = main_part

    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')

                if url.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)

                logging.info(f"✓ {prefix}系列 处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ {prefix}系列 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 {file_path} 失败: {e}")

def process_clash(data, prefix):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','unk').upper()}-{i+1}"
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash 处理异常: {e}")

def process_json(data, prefix):
    try:
        content = json.loads(data)
        
        # ==================== Hysteria / Hysteria2 处理 ====================
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            typ = "hysteria2" if "hysteria2" in str(content).lower() else "hysteria"
            
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                
                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}",
                    "type": typ,
                    "server": server,
                    "port": main_port,
                    "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                    "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                    "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                    "skip-cert-verify": content.get('insecure', True),
                    "alpn": content.get('alpn', 'h3')
                }
                
                if typ == "hysteria":
                    p["up"] = content.get('upmbps') or content.get('up') or 100
                    p["down"] = content.get('downmbps') or content.get('down') or 100
                
                if ports_range:
                    p['ports'] = ports_range
                elif content.get('server_ports'):
                    p['ports'] = content.get('server_ports')
                elif content.get('hop_ports'):
                    p['ports'] = content.get('hop_ports')
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # ==================== 增强 outbounds 处理（TUIC, VLESS Reality, Trojan, VMess, SS 等） ====================
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            
            settings = ob.get('settings', ob)
            stream = ob.get('streamSettings', {}) or ob.get('transport', {})
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            
            p = {
                "name": f"{prefix}{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}",
                "type": proto,
                "server": server,
                "port": port
            }

            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
                p['flow'] = settings.get('users', [{}])[0].get('flow', '')
                p['tls'] = stream.get('security', 'none') != 'none'
                p['servername'] = stream.get('tlsSettings', {}).get('serverName') or stream.get('realitySettings', {}).get('serverName', '')
                p['client-fingerprint'] = stream.get('realitySettings', {}).get('fingerprint', 'chrome')
                if stream.get('realitySettings'):
                    p['reality-opts'] = {
                        "public-key": stream['realitySettings'].get('publicKey', ''),
                        "short-id": stream['realitySettings'].get('shortId', '')
                    }

            elif proto == 'vmess':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
                p['alterId'] = settings.get('users', [{}])[0].get('alterId', 0)
                p['cipher'] = 'auto'

            elif proto == 'trojan':
                p['password'] = settings.get('password') or settings.get('users', [{}])[0].get('password', '')

            elif proto in ('ss', 'shadowsocks'):
                p['password'] = settings.get('password')
                p['cipher'] = settings.get('method', 'aes-256-gcm')

            elif proto == 'tuic':
                p['uuid'] = settings.get('users', [{}])[0].get('id') or settings.get('uuid')
                p['password'] = settings.get('password') or settings.get('users', [{}])[0].get('password', '')
                p['congestion-controller'] = content.get('congestion_controller', 'bbr')
                p['udp-relay-mode'] = content.get('udp_relay_mode', 'native')
                p['reduce-rtt'] = True
                p['request-timeout'] = content.get('request_timeout', 8000)

            # 通用 stream 参数
            network = stream.get('network', 'tcp')
            p['network'] = network
            if network == 'ws':
                p['ws-opts'] = {
                    "path": stream.get('wsSettings', {}).get('path', '/'),
                    "headers": stream.get('wsSettings', {}).get('headers', {})
                }

            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"JSON 处理异常: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    logging.info("=== 开始提取节点 ===")
    process_file("urls/sources.txt", "Y-")
    process_file("urls/sources-j.txt", "Z-")

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logging.info("✅ clash_meta.yaml 已成功生成！")
