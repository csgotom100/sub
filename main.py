import urllib.request
import json
import base64
import os
import urllib.parse
import re

def fix_address(address):
    """处理 IPv6 地址格式"""
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

def parse_nodes(content):
    links = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        
        for out in outbounds:
            # 兼容 sing-box (type) 和 xray (protocol)
            protocol = out.get("protocol") or out.get("type")
            if protocol != "vless": continue 

            # --- 提取基础信息 ---
            tag = out.get("tag", "Node")
            # 处理 xray 的 vnext 嵌套格式
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr = srv.get("address")
                port = srv.get("port")
                uuid = srv.get("users", [{}])[0].get("id")
            else:
                # 处理 sing-box 的平铺格式
                addr = out.get("server")
                port = out.get("server_port")
                uuid = out.get("uuid")

            if not all([addr, port, uuid]): continue

            # --- 提取传输层/安全配置 ---
            stream = out.get("streamSettings", {}) # xray
            tls = out.get("tls", {})               # sing-box
            
            net = stream.get("network") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            params = {
                "type": net,
                "security": security,
                "encryption": "none"
            }

            # Reality 参数提取
            if security == "reality":
                # 尝试从 xray 结构拿
                r_settings = stream.get("realitySettings")
                if r_settings:
                    params.update({
                        "sni": r_settings.get("serverName"),
                        "fp": r_settings.get("fingerprint"),
                        "pbk": r_settings.get("publicKey"),
                        "sid": r_settings.get("shortId")
                    })
                else:
                    # 尝试从 sing-box 结构拿
                    r_sb = tls.get("reality", {})
                    params.update({
                        "sni": tls.get("server_name"),
                        "fp": tls.get("utls", {}).get("fingerprint"),
                        "pbk": r_sb.get("public_key"),
                        "sid": r_sb.get("short_id")
                    })

            # 路径提取 (xhttp/ws)
            path = stream.get("xhttpSettings", {}).get("path") or stream.get("wsSettings", {}).get("path")
            if path: params["path"] = path

            # --- 构造最终链接 ---
            addr = fix_address(addr)
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            links.append(f"vless://{uuid}@{addr}:{port}?{query}#{urllib.parse.quote(tag)}")
            
    except Exception as e:
        print(f"解析错误: {e}")
    return links

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    for url in urls:
        print(f"Fetching: {url[:50]}...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                nodes = parse_nodes(res.read().decode('utf-8'))
                all_links.extend(nodes)
        except: continue

    # 利用 set 去重，保持顺序用 dict
    unique_links = list(dict.fromkeys(all_links))
    
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))
    print(f"Done. Extracted {len(unique_links)} unique nodes.")

if __name__ == "__main__":
    main()
