#!/usr/bin/env python3
# scripts/generate_proxyip_files.py
# 读取 ips/allowed_ips.txt -> 生成 proxyip.txt (仅 IP 列)
# 并生成 proxyip_with_country.txt，每行 ip#<COUNTRY_CODE><COUNTRY_NAME> 或 ip#未知
# 依赖: requests, shelve
import os
import requests
import shelve
import time

CACHE_DB = "geo_cache.db"
INPUT = "ips/allowed_ips.txt"
OUT_IPS = "proxyip.txt"
OUT_WITH = "proxyip_with_country.txt"
COUNTRIES_FILE = "countries.txt"

# load mapping code -> name from countries.txt (格式: code,name)
def load_country_map(path=COUNTRIES_FILE):
    m = {}
    if not os.path.exists(path):
        return m
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            if len(parts) == 2:
                code = parts[0].strip().upper()
                name = parts[1].strip()
                m[code] = name
    return m

def lookup_country(ip, cache):
    if ip in cache:
        return cache[ip][0]
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            j = r.json()
            code = j.get("country")
            cache[ip] = (code, time.time())
            time.sleep(0.15)  # 减速以防爆速率
            return code
    except Exception:
        pass
    return None

def main():
    os.makedirs(os.path.dirname(OUT_IPS) or ".", exist_ok=True)
    if not os.path.exists(INPUT):
        print(f"{INPUT} not found, nothing to do.")
        return
    country_map = load_country_map()
    with open(INPUT, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]
    with shelve.open(CACHE_DB) as cache:
        with open(OUT_IPS, "w", encoding="utf-8") as f_ips, open(OUT_WITH, "w", encoding="utf-8") as f_with:
            for ip in sorted(set(ips)):
                f_ips.write(ip + "\n")
                code = lookup_country(ip, cache)
                name = country_map.get(code.upper(), "") if code else ""
                if code and name:
                    info = f"{code}{name}"
                elif code:
                    info = code
                else:
                    info = "未知"
                # 注意：没有测速字段 (MB/s)，原来的 speed 字段不可得
                f_with.write(f"{ip}#{info}\n")
    print(f"Wrote {OUT_IPS} and {OUT_WITH}")

if __name__ == "__main__":
    main()
