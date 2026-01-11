import urllib.request
import json
import os
import urllib.parse

def fix_address(address):
    """处理 IPv6 地址"""
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

class NodeExtractor:
    @staticmethod
    def vless(out, addr, port):
        """严格按照之前的成功逻辑提取 VLESS"""
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

        # Reality 字段映射
        r_src = {}
        r_src.update(stream.get("realitySettings", {}))
        r_src.update(tls.get("reality", {}))
        
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
    def hy2(data):
        """专门提取 Alvin 的单节点 HY2 格式"""
        server_raw = data.get("server", "")
        if not server_raw or ":" not in server_raw: return None
        
        # 处理 Alvin 特有的端口范围格式 "IP:Port1,Port2-Port3"
        # 提取第一个主端口用于订阅链接
        addr_port = server_raw.split(',')[0]
        try:
            addr, port = addr_port.rsplit(':', 1)
        except ValueError: return None
        
        auth = data.get("auth", "")
        tls = data.get("tls", {})
        sni = tls.get("sni") or tls.get("serverName")
        insecure = 1 if tls.get("insecure") else 0
        
        params = {"insecure": insecure}
        if sni: params["sni"] = sni
        
        query = urllib.parse.urlencode(params)
        return f"hysteria2://{auth}@{fix_address(addr)}:{port}?{query}"

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        # 过滤掉 clash 链接，只处理 json 链接
        urls = [line.strip() for line in f if line.startswith('http') and '.yaml' not in line.lower() and 'clash' not in line.lower()]

    vless_pool = []
    hy2_pool = []
    seen = set()

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as res:
                content = res.read().decode('utf-8')
                data = json.loads(content)
                
                # 情况 1: 多节点 JSON (VLESS)
                if "outbounds" in data:
                    for out in data["outbounds"]:
                        if (out.get("protocol") or out.get("type", "")).lower() == "vless":
                            srv = out.get("server") or out.get("settings", {}).get("vnext", [{}])[0].get("address")
                            prt = out.get("server_port") or out.get("settings", {}).get("vnext", [{}])[0].get("port")
                            link = NodeExtractor.vless(out, srv, prt)
                            if link and link not in seen:
                                seen.add(link); vless_pool.append(link)
                
                # 情况 2: 单节点 JSON (HY2)
                elif "auth" in data and "server" in data:
                    link = NodeExtractor.hy2(data)
                    if link and link not in seen:
                        seen.add(link); hy2_pool.append(link)
        except: continue

    # 物理隔离写入
    with open('vless_raw.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(vless_pool))
    with open('hy2_raw.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(hy2_pool))

    # 统一汇总生成 subscribe.txt
    final_list = []
    idx = 1
    # 按照先 VLESS 后 HY2 的顺序排列
    for pool in [vless_pool, hy2_pool]:
        for link in pool:
            tag = urllib.parse.quote(f"Node-{idx:03d}")
            final_list.append(f"{link}#{tag}")
            idx += 1

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_list))

if __name__ == "__main__":
    main()
