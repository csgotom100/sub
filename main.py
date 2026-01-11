import urllib.request
import urllib.parse
import os

def main():
    # 1. 读取 sources.txt 中的所有链接
    if not os.path.exists('sources.txt'):
        print("Error: sources.txt not found")
        return
        
    with open('sources.txt', 'r') as f:
        # 过滤掉空行和注释
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not urls:
        print("No URLs found in sources.txt")
        return

    # 2. 拼接 Subconverter API
    # target=v2ray 表示生成 vmess/vless/ss 等原始链接
    # list=true 表示输出为纯文本列表，而非 Base64
    base_api = "https://api.v1.mk/sub?"
    joined_urls = "|".join(urls)
    params = {
        "target": "v2ray",
        "url": joined_urls,
        "list": "true" 
    }
    
    final_url = base_api + urllib.parse.urlencode(params)
    print(f"Fetching from: {final_url}")

    # 3. 下载并保存
    try:
        with urllib.request.urlopen(final_url) as response:
            content = response.read().decode('utf-8')
            with open('subscribe.txt', 'w', encoding='utf-8') as f:
                f.write(content)
        print("Success: subscribe.txt updated.")
    except Exception as e:
        print(f"Download failed: {e}")

if __name__ == "__main__":
    main()
