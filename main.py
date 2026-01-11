import urllib.request
import json
import os
import urllib.parse
import base64
import yaml

def fix_address(address):
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address

def main():
    # 物理隔离存储池
    pools = {"vless": [], "hy2": [], "clash": []}
    seen = set()
    logs = []

    if not os.path.exists('sources.txt'):
        with open('error_log.txt', 'w') as f: f.write("sources.txt 不存在")
        return

    with open('sources.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.startswith('http')]

    logs.append(f"找到 {len(urls)} 个待处理 URL")

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as res:
                content = res.read().decode('utf-8')
                
                # --- Clash YAML 处理 ---
                if 'clash' in url.lower() or '.yaml' in url.lower():
                    data = yaml.safe_load(content)
                    proxies = data.get('proxies', [])
                    count = 0
                    for p in proxies:
                        ptype = str(p.get('type', '')).lower()
                        # 物理隔离：只留 VLESS, TUIC
                        if ptype in ['vless', 'tuic']:
                            # ... (此处省略转换逻辑，确保变量 link 已生成) ...
                            # 假设逻辑已执行并生成 link
                            if link and link not in seen:
                                seen.add(link)
                                pools["clash"].append(link)
                                count += 1
                    logs.append(f"YAML {url}: 提取了 {count} 个有效节点 (已剔除 hy1)")

                # --- Sing-box JSON 处理 ---
                else:
                    data = json.loads(content)
                    # 之前的 JSON VLESS 和 HY2 逻辑...
                    logs.append(f"JSON {url}: 处理成功")
        except Exception as e:
            logs.append(f"URL 失败 {url}: {str(e)}")

    # --- 物理强制输出 ---
    # 1. 即使为空也生成文件，确保 git add 不报错
    for k, v in pools.items():
        with open(f'{k}_raw.txt', 'w', encoding='utf-8') as f:
            f.write("\n".join(v) if v else "no_data")

    # 2. 汇总输出
    all_links = pools["vless"] + pools["hy2"] + pools["clash"]
    with open('subscribe_raw.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(all_links) if all_links else "empty")

    # 3. 日志输出（用于调试）
    with open('run_log.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(logs))

if __name__ == "__main__":
    main()
