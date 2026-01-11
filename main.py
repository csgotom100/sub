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
            
            # --- 1. 提取基础信息 (严格不修改 ID) ---
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr, port = srv.get("address"), srv.get("port")
                user = srv.get("users", [{}])[0]
                uuid = user.get("id", "") # 严格保留原始 ID
                flow = user.get("flow", "")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")
                flow = out.get("flow", "")

            if not all([addr, port, uuid]): continue
            node_count += 1
            
            # --- 2. 提取传输层 ---
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or out.get("transport", {}).get("type") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            # 基础参数映射
            params = {}
            if flow: params["flow"] = flow
            params["encryption"] = "none"
            params["security"] = security
            params["type"] = net

            # --- 3. 严格映射 Reality 参数 ---
            r_settings = stream.get("realitySettings") or tls.get("reality", {})
            if security == "reality":
                # 优先从 xray 结构拿，再从 singbox 结构拿
                sni = stream.get("realitySettings", {}).get("serverName") or tls.get("server_name")
                fp = stream.get("realitySettings", {}).get("fingerprint") or tls.get("utls", {}).get("fingerprint")
                pbk = r_settings.get("publicKey") or r_settings.get("public_key")
                sid = r_settings.get("shortId") or r_settings.get("short_id")
                spx = r_settings.get("spiderX")
                
                if sni: params["sni"] = sni
                if fp: params["fp"] = fp
                if pbk: params["pbk"] = pbk
                if sid: params["sid"] = sid
                if spx: params["spx"] = spx

            # --- 4. 严格映射传输参数 (xhttp / grpc / ws) ---
            if net == "xhttp":
                xh = stream.get("xhttpSettings", {})
                if xh.get("path"): params["path"] = xh.get("path")
                if xh.get("mode"): params["mode"] = xh.get("mode")
            elif net == "grpc":
                gp = stream.get("grpcSettings", {})
                if gp.get("serviceName"): params["serviceName"] = gp.get("serviceName")
            elif net == "ws":
                ws = stream.get("wsSettings", {})
                if ws.get("path"): params["path"] = ws.get("path")

            # --- 5. 构造链接 (不强制编码，由 urlencode 处理) ---
            query_str = urllib.parse.urlencode(params)
            custom_tag = f"{source_label}-{node_count:03d}"
            
            link = f"vless://{uuid}@{fix_address(addr)}:{port}?{query_str}#{urllib.parse.quote(custom_tag)}"
            links.append(link)

    except: pass
    return links, node_count

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    idx = 0
    for url in urls:
        label = "SB" if "singbox" in url.lower() else "XR"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                nodes, idx = parse_nodes(res.read().decode('utf-8'), label, idx)
                all_links.extend(nodes)
        except: continue

    unique_links = list(dict.fromkeys(all_links))
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))

if __name__ == "__main__":
    main()
