import urllib.request
import json
import base64
import os
import urllib.parse

def parse_nodes(json_text):
    links = []
    try:
        data = json.loads(json_text)
        outbounds = data.get("outbounds", [])
        
        for out in outbounds:
            t = out.get("type") or out.get("protocol")
            # 过滤掉非代理协议（如 direct, block, dns 等）
            if t not in ["vmess", "vless", "shadowsocks", "trojan", "ss"]:
                continue
                
            tag = out.get("tag", "Node")
            server = out.get("server") or out.get("address")
            port = out.get("server_port") or out.get("port")
            
            if not server or not port:
                continue

            # --- 1. Shadowsocks ---
            if t in ["shadowsocks", "ss"]:
                method = out.get("method")
                password = out.get("password")
                if method and password:
                    # 格式: ss://base64(method:password)@server:port#tag
                    auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                    links.append(f"ss://{auth}@{server}:{port}#{urllib.parse.quote(tag)}")

            # --- 2. VMess ---
            elif t == "vmess":
                uuid = out.get("uuid") or (out.get("users", [{}])[0].get("id"))
                if uuid:
                    # 简化版 vmess 结构
                    v2_json = {
                        "v": "2", "ps": tag, "add": server, "port": str(port),
                        "id": uuid, "aid": "0", "net": "tcp", "type": "none", "tls": ""
                    }
                    # 自动识别 TLS/WS (针对 Alvin9999 的配置习惯)
                    if out.get("tls"): v2_json["tls"] = "tls"
                    
                    v2_enc = base64.b64encode(json.dumps(v2_json).encode()).decode()
                    links.append(f"vmess://{v2_enc}")

            # --- 3. VLESS ---
            elif t == "vless":
                uuid = out.get("uuid") or (out.get("users", [{}])[0].get("id"))
                if uuid:
                    links.append(f"vless://{uuid}@{server}:{port}?type=tcp&security=none#{urllib.parse.quote(tag)}")

            # --- 4. Trojan ---
            elif t == "trojan":
                password = out.get("password") or (out.get("users", [{}])[0].get("password"))
                if password:
                    links.append(f"trojan://{password}@{server}:{port}#{urllib.parse.quote(tag)}")

    except Exception as e:
        print(f"  解析跳转: {e}")
    return links

def main():
    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_links = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in urls:
        print(f"正在处理: {url[:50]}...")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as res:
                text = res.read().decode('utf-8')
                nodes = parse_nodes(text)
                print(f"  成功提取 {len(nodes)} 个节点")
                all_links.extend(nodes)
        except Exception as e:
            print(f"  请求失败: {e}")

    # 去重并保存
    unique_links = list(dict.fromkeys(all_links))
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_links))
    print(f"\n任务完成！共生成 {len(unique_links)} 个有效节点链接。")

if __name__ == "__main__":
    main()
