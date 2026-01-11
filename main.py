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
            if protocol != "vless": continue 
            
            node_count += 1
            # 重新定义节点名称，包含协议和端口，方便排查
            
            # --- Xray / VLESS 提取逻辑 ---
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr, port = srv.get("address"), srv.get("port")
                uuid = srv.get("users", [{}])[0].get("id")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")

            if not all([addr, port, uuid]): continue

            custom_tag = f"{source_label}-{node_count:03d} | {addr}:{port}"
            
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            # 基础参数
            params = {
                "encryption": "none",
                "security": security,
                "type": net
            }

            # --- 深度提取 Reality 参数 ---
            r_settings = stream.get("realitySettings") or tls.get("reality", {})
            if security == "reality":
                params["sni"] = (stream.get("realitySettings") or {}).get("serverName") or tls.get("server_name")
                params["fp"] = (stream.get("realitySettings") or {}).get("fingerprint") or tls.get("utls", {}).get("fingerprint")
                params["pbk"] = r_settings.get("publicKey") or r_settings.get("public_key")
                params["sid"] = r_settings.get("shortId") or r_settings.get("short_id")
                # 针对 xhttp 的 spiderX
                if r_settings.get("spiderX"):
                    params["spx"] = r_settings.get("spiderX")

            # --- 深度提取 xhttp 参数 ---
            if net == "xhttp":
                xh_settings = stream.get("xhttpSettings", {})
                if xh_settings.get("path"):
                    params["path"] = xh_settings.get("path")
                if xh_settings.get("host"):
                    params["host"] = xh_settings.get("host")

            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            link = f"vless://{uuid}@{fix_address(addr)}:{port}?{query}#{urllib.parse.quote(custom_tag)}"
            links.append(link)

    except Exception as e:
        print(f"Error: {e}")
    return links, node_count

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    global_index = 0
    for url in urls:
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

if __name__ == "__main__":
    main()
