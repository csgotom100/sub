import urllib.request
import json
import base64
import os
import urllib.parse

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

def parse_nodes(content, source_label, start_index):
    links = []
    node_count = start_index
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        for out in outbounds:
            protocol = out.get("protocol") or out.get("type")
            if protocol not in ["vless", "vmess", "shadowsocks", "ss", "trojan"]:
                continue
            
            # --- 自动生成唯一的节点名称 ---
            node_count += 1
            custom_tag = f"{source_label}-{node_count:03d} | {protocol.upper()}"
            
            # --- 提取 VLESS ---
            if protocol == "vless":
                if "settings" in out and "vnext" in out["settings"]:
                    srv = out["settings"]["vnext"][0]
                    addr, port = srv.get("address"), srv.get("port")
                    uuid = srv.get("users", [{}])[0].get("id")
                else:
                    addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")

                if not all([addr, port, uuid]): continue
                
                stream = out.get("streamSettings", {})
                tls = out.get("tls", {})
                net = stream.get("network") or "tcp"
                security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
                
                params = {"type": net, "security": security, "encryption": "none"}
                
                # Reality 逻辑
                r_settings = stream.get("realitySettings") or tls.get("reality", {})
                if security == "reality":
                    params["sni"] = (stream.get("realitySettings") or {}).get("serverName") or tls.get("server_name")
                    params["fp"] = (stream.get("realitySettings") or {}).get("fingerprint") or tls.get("utls", {}).get("fingerprint")
                    params["pbk"] = r_settings.get("publicKey") or r_settings.get("public_key")
                    params["sid"] = r_settings.get("shortId") or r_settings.get("short_id")

                path = stream.get("xhttpSettings", {}).get("path") or stream.get("wsSettings", {}).get("path")
                if path: params["path"] = path

                link = f"vless://{uuid}@{fix_address(addr)}:{port}?{urllib.parse.urlencode({k:v for k,v in params.items() if v})}#{urllib.parse.quote(custom_tag)}"
                links.append(link)

            # --- 提取 Shadowsocks ---
            elif protocol in ["shadowsocks", "ss"]:
                # ... (此处保留之前的 SS 提取逻辑，并使用 custom_tag)
                addr = out.get("server") or out.get("settings", {}).get("servers", [{}])[0].get("address")
                port = out.get("server_port") or out.get("settings", {}).get("servers", [{}])[0].get("port")
                method = out.get("method") or out.get("settings", {}).get("method")
                password = out.get("password") or out.get("settings", {}).get("servers", [{}])[0].get("password")
                if all([addr, port, method, password]):
                    auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                    links.append(f"ss://{auth}@{fix_address(addr)}:{port}#{urllib.parse.quote(custom_tag)}")

    except: pass
    return links, node_count

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    global_index = 0
    for url in urls:
        # 根据 URL 简单判断来源打标签
        label = "SB" if "singbox" in url.lower() else "XR"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                nodes, global_index = parse_nodes(res.read().decode('utf-8'), label, global_index)
                all_links.extend(nodes)
        except: continue

    unique_links = list(dict.fromkeys(all_links))
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))
    print(f"成功生成 {len(unique_links)} 个节点，已解决重名问题。")

if __name__ == "__main__":
    main()
