import urllib.request
import json
import base64
import os

def parse_json_to_v2ray(json_text):
    """
    从 sing-box/xray JSON 配置中提取节点并转换为 v2rayN 链接
    """
    links = []
    try:
        data = json.loads(json_text)
        outbounds = data.get("outbounds", [])
        
        for out in outbounds:
            proto = out.get("type") or out.get("protocol")
            # 1. 处理 Shadowsocks
            if proto == "shadowsocks":
                # ss://method:password@server:port#remark
                method = out.get("method")
                password = out.get("password")
                server = out.get("server")
                port = out.get("server_port") or out.get("port")
                tag = out.get("tag", "SS-Node")
                if all([method, password, server, port]):
                    userpass = base64.b64encode(f"{method}:{password}".encode()).decode()
                    links.append(f"ss://{userpass}@{server}:{port}#{tag}")

            # 2. 处理 VMess
            elif proto == "vmess":
                # vmess://base64(json_config)
                server = out.get("server")
                port = out.get("server_port") or out.get("port")
                uuid = out.get("uuid")
                tag = out.get("tag", "VMess-Node")
                if all([server, port, uuid]):
                    v2_json = {
                        "v": "2", "ps": tag, "add": server, "port": str(port),
                        "id": uuid, "aid": "0", "net": "tcp", "type": "none"
                    }
                    v2_enc = base64.b64encode(json.dumps(v2_json).encode()).decode()
                    links.append(f"vmess://{v2_enc}")
            
            # 3. 处理 VLESS (简单实现)
            elif proto == "vless":
                server = out.get("server")
                port = out.get("server_port") or out.get("port")
                uuid = out.get("uuid")
                tag = out.get("tag", "VLESS-Node")
                if all([server, port, uuid]):
                    links.append(f"vless://{uuid}@{server}:{port}?type=tcp#{tag}")

    except Exception as e:
        print(f"  Parse Error: {e}")
    return links

def main():
    if not os.path.exists('sources.txt'):
        return

    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    final_links = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    for url in urls:
        print(f"Downloading: {url[:60]}...")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8')
                nodes = parse_json_to_v2ray(content)
                print(f"  Found {len(nodes)} nodes")
                final_links.extend(nodes)
        except Exception as e:
            print(f"  Failed: {e}")

    # 保存为纯文本（一行一个链接）
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links))
    print(f"\nDone! Total nodes extracted: {len(final_links)}")

if __name__ == "__main__":
    main()
