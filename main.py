class Extractor:
    @staticmethod
    def to_v2ray_vless(p):
        addr, port, uuid = p.get('server'), p.get('port'), p.get('uuid')
        if not all([addr, port, uuid]): return None
        # 针对 Reality 的精准匹配
        is_reality = True if p.get('reality-opts') or p.get('tls') else False
        params = {
            "encryption": "none",
            "security": "reality" if is_reality else "none",
            "type": p.get('network', 'tcp'),
            "sni": p.get('servername') or p.get('sni'),
            "fp": p.get('client-fingerprint', 'chrome'),
            "pbk": p.get('reality-opts', {}).get('public-key') if p.get('reality-opts') else "",
            "sid": p.get('reality-opts', {}).get('short-id') if p.get('reality-opts') else "",
            "flow": p.get('flow')
        }
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{uuid}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def to_v2ray_tuic(p):
        addr, port, uuid = p.get('server'), p.get('port'), p.get('uuid')
        password = p.get('password')
        if not all([addr, port, uuid]): return None
        params = {
            "sni": p.get('sni'),
            "alpn": ",".join(p.get('alpn')) if isinstance(p.get('alpn'), list) else "h3",
            "insecure": 1 if p.get('skip-cert-verify') else 0,
            "congestion_control": p.get('congestion-controller', 'bbr'),
            "udp_relay_mode": p.get('udp-relay-mode', 'native')
        }
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"tuic://{uuid}:{password}@{fix_address(addr)}:{port}?{query}"

    @staticmethod
    def from_clash(p):
        ptype = str(p.get('type', '')).lower()
        
        # --- 物理踢除逻辑 ---
        if ptype == 'hysteria': 
            return None # 踢掉 hy1
            
        if ptype == 'vless': 
            return Extractor.to_v2ray_vless(p)
        if ptype == 'tuic': 
            return Extractor.to_v2ray_tuic(p)
        if ptype == 'hysteria2' or ptype == 'hy2':
            # 如果 Clash 里出现了 hy2，也可以按需转换（目前 Alvin 的主要是 hy1）
            return None 
        return None
