import urllib.request
import json
import base64
import os
import urllib.parse

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

def parse_nodes(content):
    links = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        for out in outbounds:
            protocol = out.get("protocol") or out.get("type")
            tag = out.get("tag", "Node")
            
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

                # Path 编码处理
                path = stream.get("xhttpSettings", {}).get("path") or stream.get("wsSettings", {}).get("path")
                if path: params["path"] = path # urllib.parse.urlencode 会自动处理编码

                link = f"vless://{uuid}@{fix_address(addr)}:{port}?{urllib.parse.urlencode({k:v for k,v in params.items() if v})}#{urllib.parse.quote(tag)}"
                links.append(link)

            # --- 提取 Shadowsocks (SS) ---
            elif protocol in ["shadowsocks", "ss"]:
                addr = out.get("server") or out.get("settings", {}).get("servers", [{}])[0].get("address")
                port = out.get("server_port") or out.get("settings", {}).get("servers", [{}])[0].get("port")
                method = out.get("method") or out.get("settings", {}).get("method")
                password = out.get("password") or out.get("settings", {}).get("servers", [{}])[0].get("password")
                
                if all([addr, port, method, password]):
                    auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                    links.append(f"ss://{auth}@{fix_address(addr)}:{port}#{urllib.parse.quote(tag)}")

    except: pass
    return links

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                all_links.extend(parse_nodes(res.read().decode('utf-8')))
        except: continue

    unique_links = list(dict.fromkeys(all_links))
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))

if __name__ == "__main__":
    main()
