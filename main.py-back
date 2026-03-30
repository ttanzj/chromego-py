#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5 - 纯 Y 系列版
- 其他提取逻辑完全不变
- 仅增强去重逻辑：增加 sni 识别（避免 sni 不同但其他字段相同的节点被去重）
- 节点名称去除 "Y-" 前缀
- 修复：hy1 节点 alpn 字段丢失问题（确保 alpn 为列表格式）
"""
import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re
import base64
import socket
import time
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# ==================== 全局防卡死设置 ====================
socket.setdefaulttimeout(15)
urllib.request.socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []          # 全局去重指纹
extracted_proxies: list[dict] = []    # 最终节点列表

geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到，位置信息将显示 UNK")

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

# ====================== 【核心修改】增强版指纹去重 - 增加 sni 识别 ======================
def make_fingerprint(p: dict) -> str:
    """原逻辑基础上增加 sni 识别，避免 sni 不同但其他字段一致的节点被去重"""
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('servername','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def test_node_availability(proxy: dict, timeout: int = 8) -> tuple[bool, int]:
    server = proxy.get('server')
    port = int(proxy.get('port', 443))
    if not server:
        return False, 9999
    try:
        start = time.time()
        with socket.create_connection((server, port), timeout=timeout):
            delay = int((time.time() - start) * 1000)
        return True, delay
    except Exception:
        return False, 9999

def preprocess_subscription(data: str) -> str:
    """原版预处理逻辑，完全不变"""
    content = data.strip()
    if not content:
        return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            return decoded
    except:
        pass
    if any(line.strip().startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')) for line in content.splitlines()[:10]):
        return content
    return content

# ====================== 原有核心处理函数（仅修复 hy1 alpn） ======================
def process_file(file_path: str):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
       
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')
                processed_data = preprocess_subscription(raw_data)
                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                    process_clash(processed_data)
                else:
                    process_json(processed_data)
                logger.info(f"✓ 订阅源处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
           
            # 只去除 "Y-" 前缀，其他命名逻辑完全保留
            original_name = p.get('name', '')
            if original_name.startswith('Y-'):
                new_name = original_name[2:]
            else:
                loc = get_location(p.get('server'))
                node_type = p.get('type', 'unk').upper()
                new_name = f"{loc}-{node_type}-{i+1}"
           
            p['name'] = new_name
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str):
    try:
        content = json.loads(data)
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str):
                servers = [servers]
           
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
           
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
               
                name_suffix = f" ({ports_range})" if ports_range else ""
                
                # ====================== 修复 hy1 alpn 问题 ======================
                if typ == "hysteria":   # hy1
                    alpn = content.get('alpn')
                    if isinstance(alpn, str):
                        alpn = [alpn]
                    elif alpn is None or alpn == "":
                        alpn = ["h3"]
                    
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": content.get('insecure', True),
                        "alpn": alpn,
                        "up": content.get('upmbps') or content.get('up') or 100,
                        "down": content.get('downmbps') or content.get('down') or 100,
                    }
                else:   # hysteria2
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{i+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": content.get('insecure', True),
                        "alpn": content.get('alpn', ["h3"]),
                    }
                
                if ports_range:
                    p['ports'] = ports_range
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria', 'hysteria2'): continue
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            p = {"server": server, "port": port, "type": proto}
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
            p['name'] = f"{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}"
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logger.error(f"JSON 处理异常: {e}")

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

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.5 纯 Y 系列版启动（增强 sni 去重 + 去除 Y- 前缀 + hy1 alpn 修复） ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成！")
    logger.info(" 输出文件 → outputs/clash_meta.yaml")
