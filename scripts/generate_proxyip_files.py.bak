#!/usr/bin/env python3
# scripts/generate_proxyip_files.py
# 读取 ips/allowed_ips.txt 和 ips_with_country/allowed_ips_with_country.txt
# 生成 proxyip.txt (仅 IP 列) 和 proxyip_with_country.txt
# 优先复用已有的 GeoIP 数据，避免重复 API 查询
import os
from pathlib import Path

INPUT_IPS = "ips/allowed_ips.txt"
INPUT_WITH_COUNTRY = "ips_with_country/allowed_ips_with_country.txt"
OUT_IPS = "proxyip.txt"
OUT_WITH = "proxyip_with_country.txt"

def parse_ip_with_country(line: str):
    """解析 ip#country_info 格式，返回 (ip, country_info)"""
    line = line.strip()
    if not line:
        return None, None
    parts = line.split('#')
    ip = parts[0].strip()
    info = '#'.join(parts[1:]).strip() if len(parts) > 1 else ''
    return ip, info

def main():
    # 确保输出目录存在
    out_dir = os.path.dirname(OUT_IPS)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # 读取 IP 列表
    if not os.path.exists(INPUT_IPS):
        print(f"Error: {INPUT_IPS} not found")
        return

    with open(INPUT_IPS, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]

    # 尝试读取已有的带国家信息的数据
    country_info_map = {}
    if os.path.exists(INPUT_WITH_COUNTRY):
        with open(INPUT_WITH_COUNTRY, "r", encoding="utf-8") as f:
            for line in f:
                ip, info = parse_ip_with_country(line)
                if ip:
                    country_info_map[ip] = info

    # 生成 proxyip.txt（所有 allowed IPs）
    with open(OUT_IPS, "w", encoding="utf-8") as f:
        for ip in sorted(set(ips)):
            f.write(ip + "\n")

    # 生成 proxyip_with_country.txt
    with open(OUT_WITH, "w", encoding="utf-8") as f:
        for ip in sorted(set(ips)):
            info = country_info_map.get(ip, "")
            if info:
                f.write(f"{ip}#{info}\n")
            else:
                f.write(f"{ip}#未知\n")

    print(f"Wrote {OUT_IPS} ({len(ips)} IPs) and {OUT_WITH}")

if __name__ == "__main__":
    main()
