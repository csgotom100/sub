import urllib.request
import json
import os
import urllib.parse
import yaml

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

class Extractor:
    @staticmethod
    def vless_json(out, addr, port):
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
        r_src = {**stream.get("realitySettings", {}), **tls.get("reality", {})}
        if security == "reality":
            params["sni"] = r_src.get("serverName") or r_src.get("server_name")
            params["pbk"] = r_src.get("publicKey") or r_src.get("public_key")
            params["sid"] = r_src.get("shortId") or r_src.get("short_id")
        
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{uuid}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def hy2_json(data):
        server_raw = data.get("server", "")
        if ":" not in server_raw: return None
        addr_port = server_raw.split(',')[0]
        addr, port = addr_port.rsplit(':', 1)
        params = {"insecure": 1 if data.get("tls", {}).get("insecure") else 0}
        if data.get("tls", {}).get("sni"): params["sni"] = data["tls"]["sni"]
        query = urllib.parse.urlencode(params)
        return f"hysteria2://{data.get('auth', '')}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def from_clash(p):
        ptype = str(p.get('type', '')).lower()
        addr, port = p.get('server'), p.get('port')
        if not addr or not port: return None

        # 彻底剔除 hysteria 1代 (hy1)
        if ptype == 'hysteria': return None 

        if ptype == 'vless':
            params = {
                "encryption": "none",
                "security": "reality" if p.get('reality-opts') or p.get('tls') else "none",
                "type": p.get('network', 'tcp'),
                "sni": p.get('servername') or p.get('sni'),
                "fp": p.get('client-fingerprint', 'chrome'),
                "pbk": p.get('reality-opts', {}).get('public-key') if p.get('reality-opts') else "",
                "sid": p.get('reality-opts', {}).get('short-id') if p.get('reality-opts') else ""
            }
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            return f"vless://{p.get('uuid')}@{fix_address(addr)}:{port}?{query}"
        
        if ptype == 'tuic':
            params = {"sni": p.get('sni'), "insecure": 1, "alpn": "h3"}
            query = urllib.parse.urlencode(params)
            return f"tuic://{p.get('uuid')}:{p.get('password')}@{fix_address(addr)}:{port}?{query}"
        
        return None

def main():
    pools = {"vless": [], "hy2": [], "clash": []}
    seen = set()
    
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                raw_data = res.read().decode('utf-8')
                if 'clash' in url.lower() or '.yaml' in url.lower():
                    data = yaml.safe_load(raw_data)
                    for p in data.get('proxies', []):
                        link = Extractor.from_clash(p)
                        if link and link not in seen:
                            seen.add(link); pools["clash"].append(link)
                else:
                    data = json.loads(raw_data)
                    if "outbounds" in data:
                        for out in data["outbounds"]:
                            if out.get("protocol") == "vless":
                                srv = out.get("server") or out.get("settings", {}).get("vnext", [{}])[0].get("address")
                                prt = out.get("server_port") or out.get("settings", {}).get("vnext", [{}])[0].get("port")
                                link = Extractor.vless_json(out, srv, prt)
                                if link and link not in seen: seen.add(link); pools["vless"].append(link)
                    elif "auth" in data and "server" in data:
                        link = Extractor.hy2_json(data)
                        if link and link not in seen: seen.add(link); pools["hy2"].append(link)
        except Exception as e:
            print(f"Error: {url} -> {e}")

    # 1. 物理隔离输出（明文）
    for k, v in pools.items():
        with open(f'{k}_raw.txt', 'w', encoding='utf-8') as f:
            f.write("\n".join(v))

    # 2. 汇总输出明文 (用于节点转换服务)
    all_links = pools["vless"] + pools["hy2"] + pools["clash"]
    # 增加标签区分
    final_links = [f"{link}#Node-{i+1:03d}" for i, link in enumerate(all_links)]
    
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links))

if __name__ == "__main__":
    main()
