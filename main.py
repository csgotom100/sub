class Extractor:
    @staticmethod
    def vless_json(out, addr, port):
        """增强版 VLESS 提取：支持 xhttp 路径和完整 Reality 参数"""
        if "settings" in out and "vnext" in out["settings"]:
            user = out["settings"]["vnext"][0]["users"][0]
            uuid, flow = user.get("id", ""), user.get("flow", "")
        else:
            uuid, flow = out.get("uuid", ""), out.get("flow", "")
        if not uuid: return None
        
        stream = out.get("streamSettings", {})
        tls = out.get("tls", {})
        
        # 1. 基础网络设置
        net = stream.get("network") or out.get("transport", {}).get("type") or "tcp"
        security = stream.get("security") or ("reality" if tls.get("reality", {}).get("enabled") else "none")
        
        params = {
            "encryption": "none",
            "security": security,
            "type": net
        }
        if flow: params["flow"] = flow

        # 2. 提取 Reality 核心参数
        # 兼容两种嵌套格式：streamSettings.realitySettings 或 tls.reality
        r_src = {}
        r_src.update(stream.get("realitySettings", {}))
        r_src.update(tls.get("reality", {}))
        
        if security == "reality":
            params["sni"] = r_src.get("serverName") or r_src.get("server_name")
            params["pbk"] = r_src.get("publicKey") or r_src.get("public_key")
            params["sid"] = r_src.get("shortId") or r_src.get("short_id")
            # 提取指纹和 spx
            params["fp"] = r_src.get("fingerprint") or tls.get("utls", {}).get("fingerprint") or "chrome"
            if r_src.get("spiderX"): params["spx"] = r_src.get("spiderX")

        # 3. 提取传输层特有参数 (xhttp / ws / grpc)
        # 优先查找 streamSettings 下的设置，再查找外层 transport
        trans_settings = stream.get(f"{net}Settings") or out.get("transport", {})
        
        if net == "xhttp":
            if trans_settings.get("path"): params["path"] = trans_settings.get("path")
            if trans_settings.get("mode"): params["mode"] = trans_settings.get("mode")
            if not params.get("spx"): params["spx"] = "/" # 默认补全 spx
        elif net == "ws":
            if trans_settings.get("path"): params["path"] = trans_settings.get("path")
        elif net == "grpc":
            if trans_settings.get("serviceName"): params["serviceName"] = trans_settings.get("serviceName")

        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{uuid}@{fix_address(addr)}:{port}?{query}"

    # ... 其他 hy2_json 和 from_clash 逻辑保持不变 ...
