#!/usr/bin/env python3
# scripts/regenerate_all.py
"""
Regenerate IP lists and classification from multiple data sources:
  - Manual_input_IP.txt  (手动输入的 IP 列表)
  - urls.txt             (URL 列表，支持 IP、域名、可 fetch 的 URL)
  - domains.txt          (域名列表，需要 DNS 解析)

内置 GeoIP 查询（多 API 源 + 缓存），不依赖外部 DNS2Geo.py。

生成的文件：
  - ips/all_ips.txt
  - ips_with_country/all_ips_with_country.txt
  - ips/allowed_ips.txt
  - ips/blocked_ips.txt
  - ips/unreachable_ips.txt
  - ips_with_country/allowed_ips_with_country.txt
  - ips_with_country/blocked_ips_with_country.txt
  - ips_with_country/unreachable_ips_with_country.txt
  - proxyip.txt
  - proxyip_with_country.txt

Run in repository root. Intended to be executed by CI (GitHub Actions).
"""
import os
import re
import json
import time
import socket
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path

# Try to import helper functions from DNS2Geo.py as fallback
try:
    from DNS2Geo import load_country_mapping, collect_all_ips, save_all_ip_country
except Exception:
    try:
        from proxyip import load_country_mapping, collect_all_ips, save_all_ip_country
    except Exception:
        load_country_mapping = None
        collect_all_ips = None
        save_all_ip_country = None

ROOT = Path('.')
IPS_DIR = ROOT / 'ips'
IPS_WITH_COUNTRY_DIR = ROOT / 'ips_with_country'
CACHE_FILE = ROOT / 'geo_cache.json'

ALL_IPS = IPS_DIR / 'all_ips.txt'
ALL_WITH_COUNTRY = IPS_WITH_COUNTRY_DIR / 'all_ips_with_country.txt'
ALLOWED_COUNTRIES = ROOT / 'allowed_countries.txt'
COUNTRIES_FILE = ROOT / 'countries.txt'

# Output files
OUT_ALLOWED_IPS = IPS_DIR / 'allowed_ips.txt'
OUT_BLOCKED_IPS = IPS_DIR / 'blocked_ips.txt'
OUT_UNREACHABLE_IPS = IPS_DIR / 'unreachable_ips.txt'
OUT_ALLOWED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'allowed_ips_with_country.txt'
OUT_BLOCKED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'blocked_ips_with_country.txt'
OUT_UNREACHABLE_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'unreachable_ips_with_country.txt'
PROXYIP = ROOT / 'proxyip.txt'
PROXYIP_WITH_COUNTRY = ROOT / 'proxyip_with_country.txt'

# Input sources
MANUAL_INPUT = ROOT / 'Manual_input_IP.txt'
URLS_INPUT = ROOT / 'urls.txt'
DOMAINS = ROOT / 'domains.txt'

# GeoIP API endpoints (按优先级排序)
GEOIP_APIS = [
    'ipinfo',      # ipinfo.io (无需 key，有速率限制)
    'ipapi',       # ip-api.com (免费版 45/min，无需 key)
    'ipgeolocation', # ipgeolocation.io (有免费额度)
]


def clean_line_prefix(s: str) -> str:
    return re.sub(r'^\s*\d+\|\s*', '', s).strip()


def is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def load_country_map(path: Path) -> dict:
    """Load country code -> name mapping from countries.txt."""
    m = {}
    if not path.exists():
        return m
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',', 1)
            if len(parts) == 2:
                code = parts[0].strip().upper()
                name = parts[1].strip()
                m[code] = name
    return m


def load_geo_cache() -> dict:
    """Load GeoIP cache from JSON file."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_geo_cache(cache: dict):
    """Save GeoIP cache to JSON file."""
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def query_ipinfo(ip: str) -> tuple:
    """Query ipinfo.io for IP geolocation. Returns (country_code, country_name) or (None, None)."""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            code = data.get('country', '')
            # ipinfo returns region names, we need to map to full name
            return (code.upper() if code else None, code.upper() if code else None)
    except Exception:
        return None, None


def query_ipapi(ip: str) -> tuple:
    """Query ip-api.com for IP geolocation. Returns (country_code, country_name) or (None, None)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('status') == 'success':
                code = data.get('countryCode', '')
                name = data.get('country', '')
                return (code.upper() if code else None, name)
    except Exception:
        return None, None


def query_ipgeolocation(ip: str) -> tuple:
    """Query ipgeolocation.io for IP geolocation. Returns (country_code, country_name) or (None, None)."""
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            code = data.get('country_code2', '')
            name = data.get('country_name', '')
            return (code.upper() if code else None, name)
    except Exception:
        return None, None


def lookup_country(ip: str, cache: dict, country_map: dict) -> tuple:
    """
    Lookup country for an IP using multiple APIs with fallback.
    Returns (country_code, country_name, info_string).
    """
    # Check cache first
    if ip in cache:
        cached = cache[ip]
        if isinstance(cached, dict):
            code = cached.get('code')
            name = cached.get('name', country_map.get(code, code) if code else '')
        else:
            # Legacy cache format
            code = cached
            name = country_map.get(code, code) if code else ''
        return code, name, f"{code}{name}" if code else "不可达"

    # Try APIs in order
    code, name = None, None
    for api in GEOIP_APIS:
        if api == 'ipinfo':
            code, name = query_ipinfo(ip)
        elif api == 'ipapi':
            code, name = query_ipapi(ip)
        elif api == 'ipgeolocation':
            code, name = query_ipgeolocation(ip)

        if code:
            break

        # Rate limiting between APIs
        time.sleep(0.5)

    if code:
        # Use country_map for full name if available
        if not name or name == code:
            name = country_map.get(code, code)
        cache[ip] = {'code': code, 'name': name, 'ts': time.time()}
        return code, name, f"{code}{name}"
    else:
        cache[ip] = {'code': None, 'name': '', 'ts': time.time()}
        return None, '', '不可达'


def resolve_domain(domain: str) -> list:
    """Resolve domain to IP addresses via DNS."""
    ips = []
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        for item in result:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        print(f"  DNS resolve failed for {domain}: {e}")
    return ips


def fetch_url_ips(url: str) -> list:
    """Fetch IP list from a URL."""
    ips = []
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            content = response.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ip_part = line.split(':')[0].split('#')[0].strip()
                if is_ip_address(ip_part):
                    ips.append(ip_part)
                elif is_ip_address(line):
                    ips.append(line)
    except Exception as e:
        print(f"  Fetch failed for {url}: {e}")
    return ips


def collect_from_manual(manual_file: Path) -> list:
    """Collect IPs from Manual_input_IP.txt."""
    ips = []
    if not manual_file.exists():
        return ips
    with open(manual_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln:
                continue
            ip_part = ln.split(':')[0].split('#')[0].strip()
            if is_ip_address(ip_part):
                ips.append(ip_part)
            elif is_ip_address(ln):
                ips.append(ln)
    print(f"  Collected {len(ips)} IPs from {manual_file}")
    return ips


def collect_from_urls(urls_file: Path) -> list:
    """Collect IPs from urls.txt (IPs, domains, fetchable URLs)."""
    ips = []
    if not urls_file.exists():
        print(f"  {urls_file} not found, skipping URL collection")
        return ips
    with open(urls_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln or ln.startswith('#'):
                continue
            print(f"  Processing: {ln[:60]}...")
            if is_ip_address(ln):
                ips.append(ln)
                print(f"    -> Direct IP")
            elif ln.startswith(('http://', 'https://')):
                fetched = fetch_url_ips(ln)
                ips.extend(fetched)
                print(f"    -> Fetched {len(fetched)} IPs")
            else:
                domain = ln.split(':')[0].split('/')[0].strip()
                resolved = resolve_domain(domain)
                ips.extend(resolved)
                print(f"    -> Resolved {len(resolved)} IPs from {domain}")
    return ips


def collect_from_domains(domains_file: Path) -> list:
    """Collect IPs from domains.txt."""
    ips = []
    if not domains_file.exists():
        print(f"  {domains_file} not found, skipping domains")
        return ips
    with open(domains_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln or ln.startswith('#'):
                continue
            domain = ln.split(':')[0].split('/')[0].strip()
            resolved = resolve_domain(domain)
            ips.extend(resolved)
            print(f"  Resolved {len(resolved)} IPs from: {domain}")
    return ips


def run_collection():
    """Collect IPs from all sources and write to ips/all_ips.txt."""
    os.makedirs(IPS_DIR, exist_ok=True)
    os.makedirs(IPS_WITH_COUNTRY_DIR, exist_ok=True)

    all_ips = set()

    print("[Source 1] Reading Manual_input_IP.txt...")
    all_ips.update(collect_from_manual(MANUAL_INPUT))

    print("[Source 2] Reading urls.txt...")
    all_ips.update(collect_from_urls(URLS_INPUT))

    print("[Source 3] Reading domains.txt...")
    all_ips.update(collect_from_domains(DOMAINS))

    # Also try external collect_all_ips if available
    if collect_all_ips is not None:
        print("\n[External] Trying collect_all_ips from DNS2Geo/proxyip...")
        try:
            collect_all_ips(str(MANUAL_INPUT), str(DOMAINS), str(ALL_IPS))
            if ALL_IPS.exists():
                with open(ALL_IPS, 'r', encoding='utf-8') as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln:
                            ip_part = ln.split(':')[0].split('#')[0].strip()
                            if is_ip_address(ip_part):
                                all_ips.add(ip_part)
                print(f"  Merged external results")
        except Exception as e:
            print(f"  collect_all_ips failed: {e}")

    print(f"\nTotal unique IPs collected: {len(all_ips)}")
    with open(ALL_IPS, 'w', encoding='utf-8') as out:
        for ip in sorted(all_ips):
            out.write(ip + '\n')
    print(f"Wrote {len(all_ips)} IPs to {ALL_IPS}")


def run_geolookup_and_save():
    """Run geolocation lookup using built-in APIs and save results."""
    country_map = load_country_map(COUNTRIES_FILE)
    cache = load_geo_cache()

    if not ALL_IPS.exists():
        print(f"Error: {ALL_IPS} not found")
        return

    with open(ALL_IPS, 'r', encoding='utf-8') as f:
        ips = [ln.strip() for ln in f if ln.strip()]

    print(f"\n[GeoIP] Looking up {len(ips)} IPs...")
    results = []
    success_count = 0
    fail_count = 0

    for i, ip in enumerate(ips):
        code, name, info = lookup_country(ip, cache, country_map)
        results.append((ip, info))
        if code:
            success_count += 1
        else:
            fail_count += 1

        # Progress report every 10 IPs
        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(ips)} | Success: {success_count} | Failed: {fail_count}")

        # Rate limiting to avoid API bans
        time.sleep(0.3)

    # Save cache
    save_geo_cache(cache)

    # Write all_ips_with_country.txt
    with open(ALL_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for ip, info in results:
            f.write(f"{ip}#{info}\n")

    print(f"\nGeoIP lookup complete: {success_count} success, {fail_count} failed")
    print(f"Wrote {ALL_WITH_COUNTRY}")


def parse_all_with_country(path: Path):
    entries = []
    if not path.exists():
        return entries
    with open(path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln:
                continue
            parts = ln.split('#')
            ip = parts[0].strip()
            info = '#'.join(parts[1:]).strip() if len(parts) > 1 else ''
            entries.append((ip, info))
    return entries


def extract_country_code(info: str):
    if not info:
        return None
    m = re.search(r'\b([A-Z]{2})\b', info)
    if m:
        return m.group(1)
    if '不可' in info or '不可达' in info:
        return 'UNREACH'
    return None


def load_allowed_codes(path: Path):
    codes = set()
    if not path.exists():
        return codes
    with open(path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln).strip()
            if not ln:
                continue
            m = re.match(r'^([A-Z]{2})', ln)
            if m:
                codes.add(m.group(1))
            else:
                codes.add(ln)
    return codes


def run_filter_and_write():
    entries = parse_all_with_country(ALL_WITH_COUNTRY)
    allowed_codes = load_allowed_codes(ALLOWED_COUNTRIES)

    print(f"\n[Filter] Allowed country codes: {sorted(allowed_codes)}")
    print(f"[Filter] Total entries to process: {len(entries)}")

    allowed_ips = []
    blocked_ips = []
    unreachable_ips = []
    allowed_info = []
    blocked_info = []
    unreachable_info = []

    for ip, info in entries:
        if not ip:
            continue
        code = extract_country_code(info)
        if code == 'UNREACH':
            unreachable_ips.append(ip)
            unreachable_info.append(f"{ip}#{info}" if info else ip)
        else:
            if code and code.upper() in allowed_codes:
                allowed_ips.append(ip)
                allowed_info.append(f"{ip}#{info}" if info else ip)
            else:
                blocked_ips.append(ip)
                blocked_info.append(f"{ip}#{info}" if info else ip)

    print(f"  Allowed: {len(allowed_ips)} | Blocked: {len(blocked_ips)} | Unreachable: {len(unreachable_ips)}")

    IPS_DIR.mkdir(parents=True, exist_ok=True)
    IPS_WITH_COUNTRY_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUT_ALLOWED_IPS, 'w', encoding='utf-8') as f:
        for ip in sorted(set(allowed_ips)):
            f.write(ip + '\n')
    with open(OUT_BLOCKED_IPS, 'w', encoding='utf-8') as f:
        for ip in sorted(set(blocked_ips)):
            f.write(ip + '\n')
    with open(OUT_UNREACHABLE_IPS, 'w', encoding='utf-8') as f:
        for ip in sorted(set(unreachable_ips)):
            f.write(ip + '\n')

    with open(OUT_ALLOWED_WITH_INFO, 'w', encoding='utf-8') as f:
        for line in sorted(set(allowed_info)):
            f.write(line + '\n')
    with open(OUT_BLOCKED_WITH_INFO, 'w', encoding='utf-8') as f:
        for line in sorted(set(blocked_info)):
            f.write(line + '\n')
    with open(OUT_UNREACHABLE_WITH_INFO, 'w', encoding='utf-8') as f:
        for line in sorted(set(unreachable_info)):
            f.write(line + '\n')

    # 生成 proxyip.txt 和 proxyip_with_country.txt
    all_proxy_ips = sorted(set(allowed_ips + blocked_ips))
    with open(PROXYIP, 'w', encoding='utf-8') as f:
        for ip in all_proxy_ips:
            f.write(ip + '\n')

    all_proxy_with_country = sorted(set(allowed_info + blocked_info))
    with open(PROXYIP_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for line in all_proxy_with_country:
            f.write(line + '\n')

    print(f"Wrote proxyip files: {PROXYIP} ({len(all_proxy_ips)}), {PROXYIP_WITH_COUNTRY} ({len(all_proxy_with_country)})")


def main():
    run_collection()
    run_geolookup_and_save()
    run_filter_and_write()
    print("\n=== All done ===")


if __name__ == '__main__':
    main()
