import urllib.request
import json
import os
import urllib.parse

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

def parse_nodes(content):
    extracted_nodes = []
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
                uuid, flow = user.get("id", ""), user.get("flow", "")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")
                flow = out.get("flow", "")

            if not all([addr, port, uuid]): continue

            # --- 传输层与安全字段提取 ---
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or out.get("transport", {}).get("type") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            # 基础参数
            params = {"encryption": "none", "security": security, "type": net}
            if flow: params["flow"] = flow

            # --- Reality 参数穷举抓取 (重点修复) ---
            # 整合所有可能的 Reality 配置源
            r_src = {}
            r_src.update(stream.get("realitySettings", {}))
            r_src.update(tls.get("reality", {}))
            
            if security == "reality":
                # SNI 查找
                params["sni"] = r_src.get("serverName") or r_src.get("server_name") or tls.get("server_name")
                # Fingerprint 查找
                params["fp"] = r_src.get("fingerprint") or tls.get("utls", {}).get("fingerprint")
                # PublicKey 查找
                params["pbk"] = r_src.get("publicKey") or r_src.get("public_key")
                # ShortId 查找
                params["sid"] = r_src.get("shortId") or r_src.get("short_id")
                # SpiderX 查找
                spx = r_src.get("spiderX")
                if spx: params["spx"] = spx

            # --- 传输协议路径提取 ---
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

            # 存储物理特征用于去重
            extracted_nodes.append({
                "unique_key": (addr, port, uuid), 
                "addr": addr, "port": port, "uuid": uuid, 
                "params": {k: v for k, v in params.items() if v}
            })
    except: pass
    return extracted_nodes

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    seen_nodes = set()
    final_links = []
    idx = 1

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                nodes = parse_nodes(res.read().decode('utf-8'))
                for n in nodes:
                    if n["unique_key"] not in seen_nodes:
                        seen_nodes.add(n["unique_key"])
                        query = urllib.parse.urlencode(n["params"])
                        tag = urllib.parse.quote(f"Node-{idx:03d}")
                        link = f"vless://{n['uuid']}@{fix_address(n['addr'])}:{n['port']}?{query}#{tag}"
                        final_links.append(link)
                        idx += 1
        except: continue

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links))

if __name__ == "__main__":
    main()
