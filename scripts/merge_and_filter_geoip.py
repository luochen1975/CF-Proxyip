#!/usr/bin/env python3
# scripts/merge_and_filter_geoip.py
# 合并远端 IP/CIDR 列表、写入 ips/all_ips.txt，并按国家过滤生成允许列表。
# 兼具 fetch_urls.py 功能：默认读取 urls.txt 并把合并结果写入 ips/all_ips.txt。
#
# 主要功能：
#  - fetch URLs (默认 urls.txt) -> 合并为原始条目（IP 或 CIDR）
#  - 写入 ips/all_ips.txt（去重、排序）
#  - 使用 GeoLite2 (--geo-db) 或 ipinfo.io（带 cache）判断国家
#  - 按 --allowed 指定的国家白名单输出允许的条目（默认从 allowed_countries.txt 读取）
#  - 可选写入 ips_with_country/all_ips_with_country.txt （--write-all-with-country）
#
# 依赖: requests, ipaddress, (可选) geoip2, shelve
#
# 用法示例:
#  python scripts/merge_and_filter_geoip.py               # 读取 urls.txt, allowed_countries.txt, 输出 ips/allowed_ips.txt
#  python scripts/merge_and_filter_geoip.py -U urls.txt -A CN,HK -o ips/allowed_ips.txt --write-all-with-country
#
import argparse
import requests
import os
import time
import shelve
import ipaddress
import sys
import re

try:
    from geoip2.database import Reader as GeoReader
    HAVE_GEOIP2 = True
except Exception:
    HAVE_GEOIP2 = False

# requests session 不使用系统代理（避免走 runner 主机代理）
_session = requests.Session()
_session.trust_env = False
_session.headers.update({"User-Agent": "cf-proxyip-merge/1.0"})

IP_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})")  # 简单 IPv4 抽取；保留 CIDR 原样

def fetch_url(url, timeout=15):
    try:
        r = _session.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] 拉取失败: {url} -> {e}", file=sys.stderr)
        return None

def parse_lines(text):
    """
    从原始文本中提取条目（IP / CIDR / plain line），返回 set。
    会跳过空行与注释行，若行里有分隔符(#/space/tab)，取首段。
    """
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 一般格式可能为 "ip#info" 或 "ip info" 等，先取首段
        for sep in ('#', ' ', '\t'):
            if sep in line:
                line = line.split(sep, 1)[0].strip()
                break
        if not line:
            continue
        out.add(line)
    return out

def load_urls_file(path):
    urls = []
    if not os.path.exists(path):
        return urls
    with open(path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            urls.append(ln)
    return urls

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

def lookup_country_ipinfo(ip, cache, max_sleep=0.2):
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
            time.sleep(max_sleep)
            return code
        else:
            time.sleep(0.1)
            return None
    except Exception:
        time.sleep(0.1)
        return None

def write_ips_all(out_path, items):
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        for it in sorted(items):
            f.write(it + "\n")
    print(f"[OK] wrote {len(items)} items to {out_path}")

def enrich_and_write_all_with_country(items, out_with_country, reader, cache, country_map):
    """
    items: iterable of original items (IP or CIDR)
    out_with_country: path to write lines like: ip#<CountryName> or cidr#<CountryName>
    This function tries to determine country (ISO code) for a representative IP of each item
    and map to friendly name via country_map (code->name) if provided.
    """
    os.makedirs(os.path.dirname(out_with_country) or '.', exist_ok=True)
    written = 0
    with open(out_with_country, 'w', encoding='utf-8') as out:
        for it in sorted(items):
            rep_ip = it
            if is_cidr(it):
                rep = first_ip_of_cidr(it)
                if rep:
                    rep_ip = rep
            code = None
            if reader:
                try:
                    code = lookup_country_geoip(rep_ip, reader)
                except Exception:
                    code = None
            if code is None:
                code = lookup_country_ipinfo(rep_ip, cache)
            if code:
                name = country_map.get(code.upper(), code)
                out.write(f"{it}#{name}\n")
            else:
                out.write(f"{it}#未知\n")
            written += 1
    print(f"[OK] wrote {written} records to {out_with_country}")

def main():
    p = argparse.ArgumentParser(description="Merge remote IP lists, write ips/all_ips.txt and filter by allowed countries.")
    p.add_argument("--urls-file", "-U", default="urls.txt", help="Local file that lists source URLs (one per line). Default: urls.txt")
    p.add_argument("--allowed", "-A", help="Allowed countries (comma separated two-letter codes) e.g. CN,HK,JP. If omitted, read allowed_countries.txt")
    p.add_argument("--geo-db", help="GeoLite2-Country.mmdb path (optional, prefer for offline lookup)", default="")
    p.add_argument("--cache-db", help="Cache DB (shelve) for ipinfo lookups", default="geo_cache.db")
    p.add_argument("--out", "-o", help="Output allowed IP file (default: ips/allowed_ips.txt)", default="ips/allowed_ips.txt")
    p.add_argument("--out-all-ips", help="Write merged raw ips to this path (default: ips/all_ips.txt)", default="ips/all_ips.txt")
    p.add_argument("--write-all-with-country", action="store_true", help="Also write ips_with_country/all_ips_with_country.txt (ip#CountryName)")
    p.add_argument("--accept-cidr", action="store_true", help="If set, accept CIDR when country unknown (preserve CIDR entries)")
    p.add_argument("--provider-local-path", help="Optional extra path to write allowed ips for local provider", default="")
    args = p.parse_args()

    urls = load_urls_file(args.urls_file)
    if not urls:
        print(f"[WARN] No URLs found in {args.urls_file} (or file missing). Continuing if local inputs exist.")

    # Fetch and parse remote lists
    all_items = set()
    for url in urls:
        print(f"[INFO] Fetching {url}")
        txt = fetch_url(url)
        if not txt:
            continue
        items = parse_lines(txt)
        print(f"[INFO]  -> parsed {len(items)} items")
        all_items.update(items)

    # Also include proxyip.txt and Manual_input_IP.txt if present
    if os.path.exists("proxyip.txt"):
        with open("proxyip.txt", "r", encoding="utf-8") as f:
            for ln in f:
                v = ln.strip().split("#",1)[0].strip()
                if v:
                    all_items.add(v)
    if os.path.exists("Manual_input_IP.txt"):
        with open("Manual_input_IP.txt", "r", encoding="utf-8") as f:
            for ln in f:
                v = ln.strip()
                if v:
                    all_items.add(v)

    print(f"[INFO] merged total {len(all_items)} raw items")

    # Write ips/all_ips.txt
    write_ips_all(args.out_all_ips, all_items)

    # Load allowed list
    allowed_set = set()
    if args.allowed:
        allowed_set = {c.strip().upper() for c in args.allowed.split(",") if c.strip()}
    else:
        if os.path.exists("allowed_countries.txt"):
            with open("allowed_countries.txt", "r", encoding="utf-8") as f:
                for ln in f:
                    v = ln.strip()
                    if v:
                        allowed_set.add(v.upper())
        else:
            print("[WARN] allowed_countries.txt not found and --allowed not provided; defaulting to empty allowed set")

    # Prepare geo resources
    geo_reader = None
    if args.geo_db and HAVE_GEOIP2 and os.path.exists(args.geo_db):
        try:
            geo_reader = GeoReader(args.geo_db)
            print("[INFO] Using GeoLite2 DB for lookups")
        except Exception as e:
            print("[WARN] Cannot open geo db:", e)
            geo_reader = None
    elif args.geo_db:
        print("[WARN] geo-db specified but geoip2 not available or file missing; falling back to ipinfo")

    cache = shelve.open(args.cache_db)

    # Optionally prepare country code->name map from countries.txt
    country_map = {}
    if os.path.exists("countries.txt"):
        with open("countries.txt", "r", encoding="utf-8") as f:
            for ln in f:
                parts = ln.strip().split(",", 1)
                if len(parts) == 2:
                    country_map[parts[0].strip().upper()] = parts[1].strip()

    # Optional: write ips_with_country/all_ips_with_country.txt (use rep IP per CIDR)
    if args.write_all_with_country:
        out_with_country = "ips_with_country/all_ips_with_country.txt"
        enrich_and_write_all_with_country(all_items, out_with_country, geo_reader, cache, country_map)

    # Main filtering: determine country for representative IPs and decide allowed/blocked/unreachable
    allowed_results = []
    total = len(all_items)
    i = 0
    for item in sorted(all_items):
        i += 1
        sys.stdout.write(f"\r[PROCESS] {i}/{total}: {item}    ")
        sys.stdout.flush()
        rep_ip = item
        if is_cidr(item):
            rep = first_ip_of_cidr(item)
            if rep:
                rep_ip = rep
        country = None
        if geo_reader:
            try:
                country = lookup_country_geoip(rep_ip, geo_reader)
            except Exception:
                country = None
        if country is None:
            country = lookup_country_ipinfo(rep_ip, cache)
        if country:
            if country.upper() in allowed_set:
                allowed_results.append(item)
        else:
            # unknown country
            if args.accept_cidr and is_cidr(item):
                # keep CIDR conservatively
                allowed_results.append(item)
            else:
                # skip unknown
                pass
    print()

    cache.close()

    # write allowed output
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for ip in sorted(set(allowed_results)):
            f.write(ip + "\n")
    print(f"[OK] Wrote {len(allowed_results)} allowed items to {args.out}")

    # optionally write provider local path
    if args.provider_local_path:
        with open(args.provider_local_path, "w", encoding="utf-8") as f:
            for ip in sorted(set(allowed_results)):
                f.write(ip + "\n")
        print(f"[OK] Also wrote provider file to {args.provider_local_path}")

if __name__ == "__main__":
    main()
