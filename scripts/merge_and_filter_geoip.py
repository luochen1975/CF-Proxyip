#!/usr/bin/env python3
# merge_and_filter_geoip.py
# 从多个 raw URL 拉取 IP/CIDR 列表，使用 GeoLite2 或 ipinfo 做国家判断，输出允许的 IP 列表。
# 依赖: requests, geoip2 (可选), ipaddress

import argparse
import requests
import os
import time
import shelve
import ipaddress
import sys

try:
    from geoip2.database import Reader as GeoReader
    HAVE_GEOIP2 = True
except Exception:
    HAVE_GEOIP2 = False

# 默认 session 不使用系统代理（避免走 OpenClash）
_session = requests.Session()
_session.trust_env = False

def fetch_url(url, timeout=15):
    try:
        r = _session.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] 拉取失败: {url} -> {e}")
        return None

def parse_lines(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 有些文件格式：ip#info 或 ip space info，先取首段
        for sep in ('#', ' ', '\t'):
            if sep in line:
                line = line.split(sep, 1)[0].strip()
        out.add(line)
    return out

def is_cidr(item):
    return '/' in item

def first_ip_of_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(net.network_address)
    except Exception:
        return None

def lookup_country_geoip(ip, reader):
    try:
        rec = reader.country(ip)
        code = rec.country.iso_code
        return code or None
    except Exception:
        return None

def lookup_country_ipinfo(ip, cache, max_sleep=1.0):
    # cache: shelve mapping ip -> (code, timestamp)
    if ip in cache:
        return cache[ip][0]
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = _session.get(url, timeout=10)
        if r.status_code == 200:
            j = r.json()
            code = j.get("country")
            cache[ip] = (code, time.time())
            # 小睡，减少速率问题
            time.sleep(0.2)
            return code
        else:
            # 非 200，稍等并返回 None
            time.sleep(0.5)
            return None
    except Exception:
        # 网络/超时等
        time.sleep(0.5)
        return None

def main():
    p = argparse.ArgumentParser(description="合并远程 IP 列表并按国家过滤（优先 GeoLite2）")
    p.add_argument("--urls-file", "-U", help="包含 raw URLs 的本地文件（每行一个 URL）", required=True)
    p.add_argument("--allowed", "-A", help="允许的国家两位 ISO 代码，用逗号分隔，例如 CN,HK,JP", required=True)
    p.add_argument("--geo-db", help="GeoLite2-Country.mmdb 路径（可选，优先使用）", default="")
    p.add_argument("--cache-db", help="缓存文件（shelve），默认: geo_cache.db", default="geo_cache.db")
    p.add_argument("--out", "-o", help="输出文件路径，默认: ips/allowed_ips.txt", default="ips/allowed_ips.txt")
    p.add_argument("--accept-cidr", action="store_true", help="若远端条目为 CIDR，按网段基地址做 geo 判断；若无法判断则保留 CIDR")
    p.add_argument("--provider-local-path", help="若指定，会把相同输出也写入该本地路径 (供路由器/本地使用)", default="")
    args = p.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if args.provider_local_path:
        os.makedirs(os.path.dirname(args.provider_local_path) or ".", exist_ok=True)

    # 读取 URLs 列表
    if not os.path.exists(args.urls_file):
        print(f"[ERR] urls-file 不存在: {args.urls_file}")
        sys.exit(2)
    with open(args.urls_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    all_items = set()
    for url in urls:
        txt = fetch_url(url)
        if not txt:
            continue
        items = parse_lines(txt)
        print(f"[INFO] 从 {url} 解析到 {len(items)} 条条目")
        all_items.update(items)

    print(f"[INFO] 合并后共有 {len(all_items)} 条原始条目（含 CIDR）")

    allowed_set = {c.strip().upper() for c in args.allowed.split(",") if c.strip()}
    use_geoip = False
    geo_reader = None
    if args.geo_db and os.path.exists(args.geo_db) and HAVE_GEOIP2:
        try:
            geo_reader = GeoReader(args.geo_db)
            use_geoip = True
            print("[INFO] 使用本地 GeoLite2 数据库进行离线查找")
        except Exception as e:
            print(f"[WARN] 打开 Geo DB 失败: {e}，将回退到 ipinfo 查询")
            use_geoip = False
    else:
        if args.geo_db:
            print("[WARN] 指定的 geo-db 未找到或未安装 geoip2 库，回退到 ipinfo")
        else:
            print("[WARN] 未指定 GeoLite2，使用 ipinfo 回退（可能受速率限制），推荐下载 GeoLite2 并传 --geo-db 参数")

    cache = shelve.open(args.cache_db)
    results = []
    total = len(all_items)
    i = 0
    for item in sorted(all_items):
        i += 1
        sys.stdout.write(f"\r处理 {i}/{total}: {item}    ")
        sys.stdout.flush()
        country = None
        iscidr = is_cidr(item)
        test_ip = item
        if iscidr:
            if args.accept_cidr:
                test_ip = first_ip_of_cidr(item) or item.split('/')[0]
            else:
                # 如果不按 CIDR 做检查，直接保留（信任外部列表）并让后续决定
                # 我们默认先尝试基地址判断，若失败按保留
                test_ip = first_ip_of_cidr(item) or item.split('/')[0]
        # 判断国家
        if use_geoip and geo_reader:
            try:
                code = lookup_country_geoip(test_ip, geo_reader)
                country = code
            except Exception:
                country = None
        if country is None:
            # 回退到 ipinfo（并缓存）
            try:
                country = lookup_country_ipinfo(test_ip, cache)
            except Exception:
                country = None

        if iscidr:
            # 处理 CIDR：若得到 country 且在 allow 中则保留；若 country 无法判断则按 accept_cidr 选项决定保留
            if country and country.upper() in allowed_set:
                results.append(item)
            else:
                if country and country.upper() not in allowed_set:
                    # 不允许
                    pass
                else:
                    # country 无法判断
                    if args.accept_cidr:
                        # 保留原始 CIDR（保守）
                        results.append(item)
                    else:
                        # 不保留
                        pass
        else:
            if country and country.upper() in allowed_set:
                results.append(item)
            else:
                # 不允许或未知 -> 不加入
                pass
    print()

    cache.close()
    # 写入输出文件
    with open(args.out, 'w', encoding='utf-8') as f:
        for ip in sorted(set(results)):
            f.write(ip + "\n")
    print(f"[OK] 写入允许 IP 列表到 {args.out}，共 {len(results)} 条")

    # 如果需要，写入 provider 本地路径（例如路由器可读取）
    if args.provider_local_path:
        with open(args.provider_local_path, 'w', encoding='utf-8') as f:
            for ip in sorted(set(results)):
                f.write(ip + "\n")
        print(f"[OK] 本地 provider 文件写入到 {args.provider_local_path}")

if __name__ == "__main__":
    main()
