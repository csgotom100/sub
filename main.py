import urllib.request
import json
import os
import urllib.parse
import base64

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

class NodeExtractor:
    @staticmethod
    def vless(out, addr, port):
        if "settings" in out and "vnext" in out["settings"]:
            user = out["settings"]["vnext"][0]["users"][0]
            uuid, flow = user.get("id", ""), user.get("flow", "")
        else:
            uuid, flow = out.get("uuid", ""), out.get("flow", "")
        if not uuid: return None
        
        stream = out.get("streamSettings", {})
        tls = out.get("tls", {})
        net = stream.get("network") or out.get("transport", {}).get("type") or "tcp"
        security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
        
        params = {"encryption": "none", "security": security, "type": net}
        if flow: params["flow"] = flow

        r_src = {}
        r_src.update(stream.get("realitySettings", {})); r_src.update(tls.get("reality", {}))
        if security == "reality":
            params["sni"] = r_src.get("serverName") or r_src.get("server_name") or tls.get("server_name")
            params["fp"] = r_src.get("fingerprint") or tls.get("utls", {}).get("fingerprint")
            params["pbk"] = r_src.get("publicKey") or r_src.get("public_key")
            params["sid"] = r_src.get("shortId") or r_src.get("short_id")
            if r_src.get("spiderX"): params["spx"] = r_src.get("spiderX")

        if net == "xhttp":
            xh = stream.get("xhttpSettings", {})
            if xh.get("path"): params["path"] = xh.get("path")
            if xh.get("mode"): params["mode"] = xh.get("mode")
        
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{uuid}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def hy2(out, addr, port):
        auth = out.get("auth") or out.get("settings", {}).get("auth")
        if not auth: return None
        tls = out.get("tls", {})
        sni = tls.get("server_name") or tls.get("serverName")
        insecure = 1 if tls.get("insecure") or tls.get("allow_insecure") else 0
        query = urllib.parse.urlencode({"sni": sni, "insecure": insecure} if sni else {"insecure": insecure})
        return f"hysteria2://{auth}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def ss(out, addr, port):
        method = out.get("method") or out.get("settings", {}).get("method")
        password = out.get("password") or out.get("settings", {}).get("password")
        if not method or not password: return None
        auth_b64 = base64.b64encode(f"{method}:{password}".encode()).decode().strip("=")
        return f"ss://{auth_b64}@{fix_address(addr)}:{port}"

def process_content(content):
    # 分流容器
    pools = {"vless": [], "hysteria2": [], "shadowsocks": []}
    try:
        data = json.loads(content)
        for out in data.get("outbounds", []):
            raw_proto = (out.get("protocol") or out.get("type", "")).lower()
            proto = "hysteria2" if raw_proto in ["hysteria2", "hy2"] else ("shadowsocks" if raw_proto in ["shadowsocks", "ss"] else raw_proto)
            
            if proto not in pools: continue

            # 提取通用地址
            addr = out.get("server") or out.get("settings", {}).get("vnext", [{}])[0].get("address")
            port = out.get("server_port") or out.get("settings", {}).get("vnext", [{}])[0].get("port")
            if not addr or not port: continue

            # 调用对应提取器
            extractor = getattr(NodeExtractor, proto, None)
            if extractor:
                link = extractor(out, addr, port)
                if link: pools[proto].append(link)
    except: pass
    return pools

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    # 全局存储
    global_pools = {"vless": [], "hysteria2": [], "shadowsocks": []}

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                content = res.read().decode('utf-8')
                current_pools = process_content(content)
                for p in global_pools:
                    global_pools[p].extend(current_pools[p])
        except: continue

    # 1. 物理隔离写入各自分组文件（可选）
    for p, links in global_pools.items():
        with open(f'{p}_raw.txt', 'w', encoding='utf-8') as f:
            f.write("\n".join(links))

    # 2. 全局物理去重汇总
    seen_identity = set()
    final_links = []
    idx = 1
    
    # 按特定顺序汇总
    for p in ["vless", "hysteria2", "shadowsocks"]:
        for link in global_pools[p]:
            # 提取物理特征：协议 + 认证信息 + 地址端口
            identity = f"{p}:{link.split('#')[0]}" 
            if identity not in seen_identity:
                seen_identity.add(identity)
                tag = urllib.parse.quote(f"Node-{idx:03d}")
                final_links.append(f"{link}#{tag}")
                idx += 1

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links))

if __name__ == "__main__":
    main()
