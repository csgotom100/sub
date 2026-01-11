import urllib.request
import json
import base64
import os
import urllib.parse

def parse_xray(data):
    """解析 Xray JSON 格式"""
    links = []
    outbounds = data.get("outbounds", [])
    for out in outbounds:
        protocol = out.get("protocol")
        if protocol not in ["vless", "vmess", "shadowsocks", "trojan"]:
            continue
        
        settings = out.get("settings", {})
        vnext = settings.get("vnext", [])
        if not vnext: continue
        
        # 提取基础信息
        srv = vnext[0]
        user = srv.get("users", [{}])[0]
        address = srv.get("address")
        port = srv.get("port")
        uuid = user.get("id")
        tag = out.get("tag", "Xray-Node")
        
        stream = out.get("streamSettings", {})
        net = stream.get("network", "tcp")
        security = stream.get("security", "none")
        
        # 构造参数
        params = {
            "type": net,
            "security": security,
            "sni": "",
            "fp": "",
            "pbk": "",
            "sid": "",
            "path": ""
        }
        
        # Reality 处理
        if security == "reality":
            r_settings = stream.get("realitySettings", {})
            params["sni"] = r_settings.get("serverName")
            params["fp"] = r_settings.get("fingerprint")
            params["pbk"] = r_settings.get("publicKey")
            params["sid"] = r_settings.get("shortId")
        
        # xhttp / ws 路径处理
        if net == "xhttp":
            params["path"] = stream.get("xhttpSettings", {}).get("path")
        elif net == "ws":
            params["path"] = stream.get("wsSettings", {}).get("path")

        # 构造 URL (以 VLESS 为例)
        if protocol == "vless":
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            links.append(f"vless://{uuid}@{address}:{port}?{query}#{urllib.parse.quote(tag)}")
            
    return links

def parse_sing_box(data):
    """解析 sing-box JSON 格式 (你之前已调通的部分)"""
    links = []
    outbounds = data.get("outbounds", [])
    for out in outbounds:
        t = out.get("type")
        if t not in ["vless", "vmess", "shadowsocks"]: continue
        
        address = out.get("server")
        port = out.get("server_port")
        uuid = out.get("uuid")
        tag = out.get("tag", "SB-Node")
        
        tls = out.get("tls", {})
        reality = tls.get("reality", {})
        
        params = {
            "encryption": "none",
            "security": "reality" if reality.get("enabled") else ("tls" if tls.get("enabled") else "none"),
            "sni": tls.get("server_name"),
            "fp": tls.get("utls", {}).get("fingerprint"),
            "pbk": reality.get("public_key"),
            "sid": reality.get("short_id"),
            "type": "tcp"
        }
        
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        links.append(f"vless://{uuid}@{address}:{port}?{query}#{urllib.parse.quote(tag)}")
    return links

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    for url in urls:
        print(f"Fetching: {url[:60]}...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                content = json.loads(res.read().decode('utf-8'))
                # 根据 JSON 特征判断解析方式
                if "outbounds" in content:
                    # 简单判断：xray 通常有 log 或 routing 字段
                    if "log" in content or "routing" in content:
                        nodes = parse_xray(content)
                    else:
                        nodes = parse_sing_box(content)
                    all_links.extend(nodes)
                    print(f"  Done: {len(nodes)} nodes")
        except Exception as e:
            print(f"  Skip: {e}")

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(all_links))

if __name__ == "__main__":
    main()
