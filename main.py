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
            
            # --- 基础字段提取 ---
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr, port = srv.get("address"), srv.get("port")
                user = srv.get("users", [{}])[0]
                uuid = user.get("id", "").split()[0][:36] # 严格截取 UUID
                flow = user.get("flow", "")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")
                flow = out.get("flow", "")

            if not all([addr, port, uuid]): continue
            node_count += 1
            
            # --- 传输层提取 ---
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            params = {
                "encryption": "none",
                "security": security,
                "type": net
            }

            # 1. 关键：流控处理 (xhttp 不兼容 vision)
            if net == "tcp" and flow:
                params["flow"] = flow

            # 2. Reality 深度适配
            r_settings = stream.get("realitySettings") or tls.get("reality", {})
            if security == "reality":
                params["sni"] = (stream.get("realitySettings") or {}).get("serverName") or tls.get("server_name")
                params["fp"] = (stream.get("realitySettings") or {}).get("fingerprint") or "chrome"
                params["pbk"] = r_settings.get("publicKey") or r_settings.get("public_key")
                params["sid"] = r_settings.get("shortId") or r_settings.get("short_id")
                if r_settings.get("spiderX"): params["spx"] = r_settings.get("spiderX")

            # 3. xhttp 协议参数名深度修正 (v2rayN 兼容性)
            if net == "xhttp":
                xh = stream.get("xhttpSettings", {})
                path_val = xh.get("path")
                if path_val:
                    params["path"] = path_val
                    params["extra"] = path_val # v2rayN 某些版本识别 extra 字段
                if xh.get("mode"): params["mode"] = xh.get("mode")

            # 4. gRPC 路径补全
            elif net == "grpc":
                gp = stream.get("grpcSettings", {})
                if gp.get("serviceName"): params["serviceName"] = gp.get("serviceName")

            # --- 构造链接 ---
            custom_tag = f"{source_label}-{node_count:03d} | {addr}"
            # 使用 safe='/' 避免路径斜杠被过度编码
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v}, safe='/')
            link = f"vless://{uuid}@{fix_address(addr)}:{port}?{query}#{urllib.parse.quote(custom_tag)}"
            links.append(link)

    except Exception: pass
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

if __name__ == "__main__":
    main()
