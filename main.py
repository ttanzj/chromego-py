# -*- coding: UTF-8 -*-
"""
Optimized chromego_py extractor - 2026 version
最大化提取节点：支持多种协议、自适应解析、严格安全去重、丰富输出
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import base64
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局
servers_list = []          # 严格去重用（核心指纹）
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logging.warning("GeoLite2-City.mmdb not found, location = UNK")

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(ip)
        country = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{country}-{city}" if city else country
    except:
        return "UNK"

def make_fingerprint(proxy: dict) -> str:
    """生成严格指纹，用于去重。包含核心连接参数，避免误删不同配置的节点"""
    key_parts = [
        str(proxy.get('server', '')),
        str(proxy.get('port', '')),
        str(proxy.get('type', '')),
        str(proxy.get('uuid', proxy.get('password', proxy.get('password', '')))),
        str(proxy.get('network', 'tcp')),
        str(proxy.get('tls', False)),
        str(proxy.get('servername', proxy.get('sni', ''))),
        str(proxy.get('flow', '')),
        str(proxy.get('ws-opts', {}).get('path', '')) if isinstance(proxy.get('ws-opts'), dict) else '',
    ]
    fp = "|".join(key_parts).lower()
    return hashlib.md5(fp.encode()).hexdigest()

def normalize_name(proxy: dict, index: int, sub_index: int) -> str:
    loc = get_location(proxy.get('server', ''))
    typ = proxy.get('type', 'unk').upper()
    return f"{loc}-{typ}-{index+1}-{sub_index+1}"

def process_urls(urls_file: str, processor):
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for idx, url in enumerate(urls):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                processor(data, idx)
                logging.info(f"✓ 处理成功 [{idx+1}/{len(urls)}]: {url}")
            except Exception as e:
                logging.error(f"✗ 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 urls 文件 {urls_file} 失败: {e}")

# ==================== 协议处理器（自适应多种格式） ====================

def process_clash_meta(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or 'server' not in p:
                continue
            p = dict(p)  # 复制避免修改原数据
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
            p['name'] = normalize_name(p, index, i)
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash Meta 处理失败 {index}: {e}")

def process_hysteria(data, index):
    try:
        content = json.loads(data)
        servers = content.get('server', content.get('servers', []))
        if isinstance(servers, str):
            servers = [servers]
        for srv in servers if isinstance(servers, list) else [servers]:
            if not srv:
                continue
            parts = srv.split(":")
            server = parts[0]
            port = int(parts[1].split(',')[0]) if len(parts) > 1 else 443
            auth = content.get('auth_str') or content.get('auth', content.get('password', ''))
            sni = content.get('server_name', content.get('sni', ''))
            p = {
                "name": normalize_name({"server": server, "type": "hysteria"}, index, 0),
                "type": "hysteria",
                "server": server,
                "port": port,
                "auth-str": auth,
                "up": content.get('up', 80),
                "down": content.get('down', 100),
                "sni": sni,
                "skip-cert-verify": content.get('insecure', True),
                "fast-open": True
            }
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria 处理失败 {index}: {e}")

def process_hysteria2(data, index):
    try:
        content = json.loads(data)
        server_str = content.get('server', '')
        if not server_str:
            return
        parts = server_str.split(":")
        server = parts[0]
        port = int(parts[1].split(',')[0]) if len(parts) > 1 else 443
        auth = content.get('auth') or content.get('password', '')
        tls = content.get('tls', {}) or {}
        sni = tls.get('sni', '')
        p = {
            "name": normalize_name({"server": server, "type": "hysteria2"}, index, 0),
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": auth,
            "sni": sni,
            "skip-cert-verify": tls.get('insecure', True)
        }
        fp = make_fingerprint(p)
        if fp not in servers_list:
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria2 处理失败 {index}: {e}")

def process_xray_singbox(data, index):
    """统一处理 Xray / Sing-box / v2ray 配置（支持 vless, vmess, trojan, ss 等）"""
    try:
        content = json.loads(data)
        outbounds = content.get('outbounds', []) or content.get('proxies', [])
        for i, ob in enumerate(outbounds):
            if not isinstance(ob, dict):
                continue
            proto = ob.get('protocol', ob.get('type', '')).lower()
            settings = ob.get('settings', {}) or ob
            stream = ob.get('streamSettings', {}) or ob.get('transport', {})

            server = settings.get('address') or settings.get('server')
            port = settings.get('port')
            if not server or not port:
                continue

            p = {"server": server, "port": int(port)}
            fp_base = make_fingerprint(p)

            if proto in ('vless', 'vmess'):
                uuid = settings.get('users', [{}])[0].get('id') or settings.get('uuid')
                if not uuid:
                    continue
                p.update({
                    "type": proto,
                    "uuid": uuid,
                    "network": stream.get('network', 'tcp'),
                    "tls": stream.get('security', 'none') != 'none',
                    "servername": stream.get('tlsSettings', {}).get('serverName') or stream.get('realitySettings', {}).get('serverName', ''),
                    "flow": settings.get('users', [{}])[0].get('flow', ''),
                    "skip-cert-verify": True
                })
                if p['network'] == 'ws':
                    p["ws-opts"] = {"path": stream.get('wsSettings', {}).get('path', '/')}

            elif proto == 'trojan':
                p.update({
                    "type": "trojan",
                    "password": settings.get('password') or settings.get('users', [{}])[0].get('password', ''),
                    "sni": stream.get('tlsSettings', {}).get('serverName', ''),
                    "skip-cert-verify": True
                })

            elif proto in ('shadowsocks', 'ss'):
                p.update({
                    "type": "ss",
                    "password": settings.get('password'),
                    "cipher": settings.get('method', 'aes-256-gcm')
                })

            else:
                continue  # 未知协议跳过

            p['name'] = normalize_name(p, index, i)
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Xray/Sing-box 处理失败 {index}: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    # 处理所有 urls 文件（按你仓库现有结构）
    process_urls("urls/clash_meta_urls.txt", process_clash_meta)
    process_urls("urls/hysteria_urls.txt", process_hysteria)
    process_urls("urls/hysteria2_urls.txt", process_hysteria2)
    process_urls("urls/xray_urls.txt", process_xray_singbox)
    process_urls("urls/singbox_urls.txt", process_xray_singbox)   # Sing-box 与 Xray 共用处理器
    process_urls("urls/ss_urls.txt", process_xray_singbox)        # SS 也走统一处理器

    logging.info(f"总共成功提取 {len(extracted_proxies)} 个有效节点（去重后）")

    # 输出 Clash Meta YAML（原项目核心格式）
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    # 输出 base64.txt（原项目要求的格式：所有支持的节点转 base64 订阅）
    all_links = []
    for p in extracted_proxies:
        typ = p.get('type', '').lower()
        if typ == 'vless':
            link = (f"vless://{p.get('uuid')}@{p['server']}:{p['port']}?"
                    f"type={p.get('network','tcp')}&security={'tls' if p.get('tls') else 'none'}"
                    f"&sni={p.get('servername','')}&flow={p.get('flow','')}&fp=chrome"
                    f"#{p['name']}")
            all_links.append(link)
        elif typ == 'vmess':
            # VMess base64 简化版（可进一步完善）
            vmess_dict = {"v": "2", "ps": p['name'], "add": p['server'], "port": p['port'],
                          "id": p.get('uuid'), "aid": "0", "net": p.get('network','tcp'),
                          "type": "none", "host": "", "path": "", "tls": "tls" if p.get('tls') else ""}
            all_links.append("vmess://" + base64.b64encode(json.dumps(vmess_dict).encode()).decode())
        elif typ == 'ss':
            ss_link = f"ss://{base64.b64encode(f'{p.get('cipher', 'aes-256-gcm')}:{p.get('password')}@{p['server']}:{p['port']}'.encode()).decode()}#{p['name']}"
            all_links.append(ss_link)
        # Hysteria / Hysteria2 暂不转 base64（Clash YAML 已支持），可按需扩展

    with open("outputs/base64.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))

    # 额外纯 VLESS 订阅（方便 v2rayN 等）
    with open("outputs/vless_subscription.txt", "w", encoding="utf-8") as f:
        vless_only = [ln for ln in all_links if ln.startswith("vless://")]
        f.write(base64.b64encode("\n".join(vless_only).encode()).decode())

    logging.info("输出完成！")
    logging.info("   → outputs/clash_meta.yaml （Clash Meta）")
    logging.info("   → outputs/base64.txt （原项目 base64 订阅）")
    logging.info("   → outputs/vless_subscription.txt （纯 VLESS）")
