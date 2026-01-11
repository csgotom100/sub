import urllib.request
import json
import base64
import os
import urllib.parse

def parse_sing_box(json_text):
    links = []
    try:
        data = json.loads(json_text)
        outbounds = data.get("outbounds", [])
        
        for out in outbounds:
            t = out.get("type")
            if t != "vless": continue # 先专注调通 vless
            
            server = out.get("server")
            port = out.get("server_port")
            uuid = out.get("uuid")
            tag = out.get("tag", "Node")
            
            # 解析 TLS / Reality
            tls_conf = out.get("tls", {})
            reality_conf = tls_conf.get("reality", {})
            
            # 基础参数
            params = {
                "encryption": "none",
                "security": "reality" if reality_conf.get("enabled") else ("tls" if tls_conf.get("enabled") else "none"),
                "sni": tls_conf.get("server_name", ""),
                "fp": tls_conf.get("utls", {}).get("fingerprint", "chrome"),
                "pbk": reality_conf.get("public_key", ""),
                "sid": reality_conf.get("short_id", ""),
                "type": "tcp" # 默认 tcp，若有 transport 则需扩充
            }
            
            # 构造 vless 链接
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            vless_link = f"vless://{uuid}@{server}:{port}?{query}#{urllib.parse.quote(tag)}"
            links.append(vless_link)
            
    except Exception as e:
        print(f"解析出错: {e}")
    return links

def main():
    # 这里为了测试，我们直接读取 sources.txt
    if not os.path.exists('sources.txt'): return
    
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    all_links = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in urls:
        # 只处理包含 singbox 字样的链接进行调试
        if "singbox" not in url: continue
        
        print(f"Processing: {url}")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as res:
                content = res.read().decode('utf-8')
                nodes = parse_sing_box(content)
                print(f"  Extracted {len(nodes)} nodes")
                all_links.extend(nodes)
        except Exception as e:
            print(f"  Error: {e}")

    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(all_links))

if __name__ == "__main__":
    main()
