import urllib.request
import urllib.parse
import os
import time

def fetch_sub(url, backend="https://api.v1.mk/sub?"):
    params = {
        "target": "v2ray",
        "url": url,
        "list": "true"
    }
    final_url = backend + urllib.parse.urlencode(params)
    try:
        # 设置 30 秒超时，防止卡死
        with urllib.request.urlopen(final_url, timeout=30) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""

def main():
    if not os.path.exists('sources.txt'):
        print("sources.txt not found")
        return

    with open('sources.txt', 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_results = []
    
    # 逐个处理，避免请求过长导致 500 错误
    for index, url in enumerate(urls):
        print(f"[{index+1}/{len(urls)}] Processing: {url[:50]}...")
        # 如果 api.v1.mk 持续 500，可以换成下面的备用后端：
        # https://sub.id9.cc/sub?
        # https://sub.xeton.dev/sub?
        result = fetch_sub(url, backend="https://sub.xeton.dev/sub?")
        if result.strip():
            all_results.append(result.strip())
        # 稍微停顿，避免被后端屏蔽
        time.sleep(1)

    # 写入结果
    content = "\n".join(all_results)
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Done! Total nodes merged into subscribe.txt")

if __name__ == "__main__":
    main()
