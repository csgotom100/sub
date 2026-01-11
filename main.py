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
    nodes_data = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        for out in outbounds:
            protocol = out.get("protocol") or out.get("type")
            if protocol != "vless": continue 
            
            # 严格提取
            if "settings" in out and "vnext" in out["settings"]:
                srv = out["settings"]["vnext"][0]
                addr, port = srv.get("address"), srv.get("port")
                user = srv.get("users", [{}])[0]
                uuid, flow = user.get("id", ""), user.get("flow", "")
            else:
                addr, port, uuid = out.get("server"), out.get("server_port"), out.get("uuid")
                flow = out.get("flow", "")

            if not all([addr, port, uuid]): continue

            # 构造参数字典 (严格按照 JSON 原文)
            stream = out.get("streamSettings", {})
            tls = out.get("tls", {})
            net = stream.get("network") or out.get("transport", {}).get("type") or "tcp"
            security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
            
            params = {"encryption": "none", "security": security, "type": net}
            if flow: params["flow"] = flow

            r_settings = stream.get("realitySettings") or tls.get("reality", {})
            if security == "reality":
                for k, v in [("sni", "serverName"), ("fp", "fingerprint"), ("pbk", "publicKey"), ("sid", "shortId"), ("spx", "spiderX")]:
                    val = stream.get("realitySettings", {}).get(v) or tls.get(v if v != "serverName" else "server_name") or r_settings.get(v)
                    if val: params[k] = val

            if net == "xhttp":
                xh = stream.get("xhttpSettings", {})
                if xh.get("path"): params["path"] = xh.get("path")
                if xh.get("mode"): params["mode"] = xh.get("mode")
            elif net == "grpc":
                if stream.get("grpcSettings", {}).get("serviceName"): params["serviceName"] = stream["grpcSettings"]["serviceName"]
            elif net == "ws":
                if stream.get("wsSettings", {}).get("path"): params["path"] = stream["wsSettings"]["path"]

            # 将节点的核心特征和完整参数存入列表
            nodes_data.append({
                "key": f"{addr}:{port}:{uuid}", # 物理唯一特征
                "addr": addr, "port": port, "uuid": uuid, "params": params
            })
    except: pass
    return nodes_data

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    seen_keys = set()
    final_links = []
    global_idx = 1

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                nodes = parse_nodes(res.read().decode('utf-8'))
                for n in nodes:
                    if n["key"] not in seen_keys: # 物理去重判断
                        seen_keys.add(n["key"])
                        query = urllib.parse.urlencode(n["params"])
                        # 节点名称只保留数字索引，追求极致简洁
                        tag = f"NODE-{global_idx:03d}" 
                        link = f"vless://{n['uuid']}@{fix_address(n['addr'])}:{n['port']}?{query}#{tag}"
                        final_links.append(link)
                        global_idx += 1
        except: continue

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links))

if __name__ == "__main__":
    main()
