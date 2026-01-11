import urllib.request
import os
import urllib.parse
import base64
import yaml  # 确保 GitHub Actions 环境已 pip install pyyaml

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

class ClashConverter:
    @staticmethod
    def to_vless(p):
        addr, port, uuid = p.get('server'), p.get('port'), p.get('uuid')
        if not all([addr, port, uuid]): return None
        params = {
            "encryption": "none",
            "security": "reality" if p.get('tls') else "none",
            "type": p.get('network', 'tcp'),
            "sni": p.get('servername'),
            "fp": p.get('client-fingerprint', 'chrome'),
            "pbk": p.get('reality-opts', {}).get('public-key'),
            "sid": p.get('reality-opts', {}).get('short-id'),
            "flow": p.get('flow')
        }
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{uuid}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def to_hy1(p):
        addr, port, auth = p.get('server'), p.get('port'), p.get('auth-str')
        if not all([addr, port, auth]): return None
        params = {
            "auth": auth,
            "sni": p.get('sni'),
            "insecure": 1 if p.get('skip-cert-verify') else 0,
            "alpn": ",".join(p.get('alpn', [])) if isinstance(p.get('alpn'), list) else p.get('alpn')
        }
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"hysteria://{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def to_ss(p):
        addr, port, method, password = p.get('server'), p.get('port'), p.get('cipher'), p.get('password')
        if not all([addr, port, method, password]): return None
        # Shadowsocks 标准格式: ss://base64(method:password)@addr:port
        auth_str = f"{method}:{password}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode().strip("=")
        return f"ss://{auth_b64}@{fix_address(addr)}:{port}"

    @staticmethod
    def to_trojan(p):
        addr, port, password = p.get('server'), p.get('port'), p.get('password')
        if not all([addr, port, password]): return None
        params = {
            "sni": p.get('sni') or p.get('servername'),
            "allowInsecure": 1 if p.get('skip-cert-verify') else 0
        }
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"trojan://{password}@{fix_address(addr)}:{port}?{query}"

def main():
    if not os.path.exists('sources.txt'): return
    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if 'clash' in line.lower() and line.startswith('http')]

    all_proxies = []
    v2ray_links = []
    seen = set()

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                data = yaml.safe_load(res.read().decode('utf-8'))
                proxies = data.get('proxies', [])
                for p in proxies:
                    ptype = str(p.get('type', '')).lower()
                    identity = f"{ptype}:{p.get('server')}:{p.get('port')}"
                    if identity in seen: continue
                    seen.add(identity)
                    
                    # 1. 物理搬运
                    all_proxies.append(p)
                    
                    # 2. 转换链接
                    link = None
                    if ptype == 'vless': link = ClashConverter.to_vless(p)
                    elif ptype == 'hysteria': link = ClashConverter.to_hy1(p)
                    elif ptype in ['ss', 'shadowsocks']: link = ClashConverter.to_ss(p)
                    elif ptype == 'trojan': link = ClashConverter.to_trojan(p)
                    
                    if link: v2ray_links.append(link)
        except Exception as e:
            print(f"Error: {url} -> {e}")

    # 结果一：照搬节点 YAML
    with open('clash_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": all_proxies}, f, allow_unicode=True, sort_keys=False)

    # 结果二：转换后的链接 TXT
    with open('clash_to_v2ray.txt', 'w', encoding='utf-8') as f:
        for i, link in enumerate(v2ray_links, 1):
            f.write(f"{link}#Clash-{i:03d}\n")

    print(f"成功从 Clash 源提取并转换了 {len(v2ray_links)} 个节点。")

if __name__ == "__main__":
    main()
