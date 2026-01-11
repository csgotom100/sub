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
            
            # --- 提取核心信息 ---
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr, port = srv.get("address"), srv.get("port")
                user = srv.get("users", [{}])[0]
                # 关键：只取 UUID 部分，忽略后面可能的后量子加密干扰字符
                raw_id = user.get("id", "")
                uuid = raw_id.split()[0] if " " in raw_id else raw_id[:36]
                flow = user.get("flow", "")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")
                flow = out.get("flow", "")

            if not all([addr, port, uuid]): continue
            node_count += 1
            
            # --- 提取传输层 ---
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            params = {
                "encryption": "none",
                "security": security,
                "type": net
            }
            if flow: params["flow"] = flow # 修复 vision 流控

            # 1. Reality 参数 (兼容 xray/singbox)
            r_settings = stream.get("realitySettings") or tls.get("reality", {})
            if security == "reality":
                params["sni"] = (stream.get("realitySettings") or {}).get("server_name") or \
                                (stream.get("realitySettings") or {}).get("serverName") or \
                                tls.get("server_name")
                params["fp"] = (stream.get("realitySettings") or {}).get("fingerprint") or \
                               tls.get("utls", {}).get("fingerprint") or "chrome"
                params["pbk"] = r_settings.get("public_key") or r_settings.get("publicKey")
                params["sid"] = r_settings.get("short_id") or r_settings.get("shortId")
                if r_settings.get("spiderX"): params["spx"] = r_settings.get("spiderX")

            # 2. xhttp 特定参数
            if net == "xhttp":
                xh = stream.get("xhttpSettings", {})
                if xh.get("path"): params["path"] = xh.get("path")
                if xh.get("mode"): params["mode"] = xh.get("mode")

            # 3. gRPC 特定参数
            elif net == "grpc":
                gp = stream.get("grpcSettings", {})
                if gp.get("serviceName"): params["serviceName"] = gp.get("serviceName")

            # --- 构造节点名与链接 ---
            custom_tag = f"{source_label}-{node_count:03d} | {addr}"
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            link = f"vless://{uuid}@{fix_address(addr)}:{port}?{query}#{urllib.parse.quote(custom_tag)}"
            links.append(link)

    except Exception as e:
        print(f"解析异常: {e}")
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
            with urllib.request.urlopen(req, timeout=15) as res:
                nodes, idx = parse_nodes(res.read().decode('utf-8'), label, idx)
                all_links.extend(nodes)
        except: continue

    unique_links = list(dict.fromkeys(all_links))
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))
    print(f"成功导出 {len(unique_links)} 个节点。")

if __name__ == "__main__":
    main()
