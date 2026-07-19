#!/usr/bin/env python3
# scripts/regenerate_all.py
"""
Regenerate IP lists and classification from multiple data sources:
  - Manual_input_IP.txt  (手动输入的 IP/域名 列表)
  - urls.txt             (URL 列表，支持 IP、IPv6、域名、可 fetch 的 URL)
  - domains.txt          (域名列表，需要 DNS 解析)

内置 GeoIP 查询（多 API 源 + 缓存），不依赖外部 DNS2Geo.py。

同时生成 IPv4、IPv6 和域名的代理列表，各自独立分类：
  - proxyip.txt / proxyip_with_country.txt           (IPv4)
  - proxyip_v6.txt / proxyip_with_country_v6.txt       (IPv6)
  - proxyip_domain.txt / proxyip_domain_with_country.txt (域名)

运行后会自动调用 speedtest.py 对 allowed_ips_with_country.txt 前 500 个 IP 测速。

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
import subprocess
import sys
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

# --- IPv4 files ---
ALL_IPS = IPS_DIR / 'all_ips.txt'
ALL_WITH_COUNTRY = IPS_WITH_COUNTRY_DIR / 'all_ips_with_country.txt'
OUT_ALLOWED_IPS = IPS_DIR / 'allowed_ips.txt'
OUT_BLOCKED_IPS = IPS_DIR / 'blocked_ips.txt'
OUT_UNREACHABLE_IPS = IPS_DIR / 'unreachable_ips.txt'
OUT_ALLOWED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'allowed_ips_with_country.txt'
OUT_BLOCKED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'blocked_ips_with_country.txt'
OUT_UNREACHABLE_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'unreachable_ips_with_country.txt'

# --- IPv6 files ---
ALL_IPS_V6 = IPS_DIR / 'all_ips_v6.txt'
ALL_WITH_COUNTRY_V6 = IPS_WITH_COUNTRY_DIR / 'all_ips_with_country_v6.txt'
OUT_ALLOWED_IPS_V6 = IPS_DIR / 'allowed_ips_v6.txt'
OUT_BLOCKED_IPS_V6 = IPS_DIR / 'blocked_ips_v6.txt'
OUT_UNREACHABLE_IPS_V6 = IPS_DIR / 'unreachable_ips_v6.txt'
OUT_ALLOWED_WITH_INFO_V6 = IPS_WITH_COUNTRY_DIR / 'allowed_ips_with_country_v6.txt'
OUT_BLOCKED_WITH_INFO_V6 = IPS_WITH_COUNTRY_DIR / 'blocked_ips_with_country_v6.txt'
OUT_UNREACHABLE_WITH_INFO_V6 = IPS_WITH_COUNTRY_DIR / 'unreachable_ips_with_country_v6.txt'

# --- Domain files ---
ALL_DOMAINS = IPS_DIR / 'all_domains.txt'
ALL_WITH_COUNTRY_DOMAIN = IPS_WITH_COUNTRY_DIR / 'all_domains_with_country.txt'
OUT_ALLOWED_DOMAINS = IPS_DIR / 'allowed_domains.txt'
OUT_BLOCKED_DOMAINS = IPS_DIR / 'blocked_domains.txt'
OUT_UNREACHABLE_DOMAINS = IPS_DIR / 'unreachable_domains.txt'
OUT_ALLOWED_WITH_INFO_DOMAIN = IPS_WITH_COUNTRY_DIR / 'allowed_domains_with_country.txt'
OUT_BLOCKED_WITH_INFO_DOMAIN = IPS_WITH_COUNTRY_DIR / 'blocked_domains_with_country.txt'
OUT_UNREACHABLE_WITH_INFO_DOMAIN = IPS_WITH_COUNTRY_DIR / 'unreachable_domains_with_country.txt'

ALLOWED_COUNTRIES = ROOT / 'allowed_countries.txt'
COUNTRIES_FILE = ROOT / 'countries.txt'

# --- Proxy output files ---
PROXYIP = ROOT / 'proxyip.txt'
PROXYIP_V6 = ROOT / 'proxyip_v6.txt'
PROXYIP_DOMAIN = ROOT / 'proxyip_domain.txt'
PROXYIP_WITH_COUNTRY = ROOT / 'proxyip_with_country.txt'
PROXYIP_WITH_COUNTRY_V4 = ROOT / 'proxyip_with_country_v4.txt'
PROXYIP_WITH_COUNTRY_V6 = ROOT / 'proxyip_with_country_v6.txt'
PROXYIP_DOMAIN_WITH_COUNTRY = ROOT / 'proxyip_domain_with_country.txt'

# Input sources
MANUAL_INPUT = ROOT / 'Manual_input_IP.txt'
URLS_INPUT = ROOT / 'urls.txt'
DOMAINS = ROOT / 'domains.txt'

# GeoIP API endpoints (按优先级排序)
GEOIP_APIS = [
    'ipinfo',
    'ipapi',
    'ipgeolocation',
]


def clean_line_prefix(s: str) -> str:
    return re.sub(r'^\s*\d+\|\s*', '', s).strip()


def classify_address(s: str) -> str:
    """Classify an address string as 'ipv4', 'ipv6', or 'domain'."""
    if s.startswith('['):
        end = s.find(']')
        if end != -1:
            ip_part = s[1:end]
            try:
                addr = ipaddress.ip_address(ip_part)
                if isinstance(addr, ipaddress.IPv6Address):
                    return 'ipv6'
            except ValueError:
                pass

    try:
        addr = ipaddress.ip_address(s)
        if isinstance(addr, ipaddress.IPv4Address):
            return 'ipv4'
        elif isinstance(addr, ipaddress.IPv6Address):
            return 'ipv6'
    except ValueError:
        pass

    if ':' in s:
        host_part = s.rsplit(':', 1)[0]
        if host_part.startswith('['):
            host_part = host_part[1:]
        try:
            addr = ipaddress.ip_address(host_part)
            if isinstance(addr, ipaddress.IPv4Address):
                return 'ipv4'
            elif isinstance(addr, ipaddress.IPv6Address):
                return 'ipv6'
        except ValueError:
            pass

    return 'domain'


def extract_host(s: str) -> str:
    """Extract host (IP or domain) from a string, stripping comments."""
    s = s.split('#')[0].strip()
    if s.startswith('['):
        end = s.find(']')
        if end != -1:
            return s[:end + 1]
    if ':' in s:
        if s.count(':') > 2:
            return s
        parts = s.rsplit(':', 1)
        try:
            int(parts[1])
            return parts[0]
        except ValueError:
            return s
    return s


def is_ipv4_address(s: str) -> bool:
    try:
        addr = ipaddress.ip_address(s)
        return isinstance(addr, ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6_address(s: str) -> bool:
    try:
        addr = ipaddress.ip_address(s)
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False


def load_country_map(path: Path) -> dict:
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
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_geo_cache(cache: dict):
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def query_ipinfo(ip: str, country_map: dict) -> tuple:
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            code = data.get('country', '')
            code = code.upper() if code else None
            name = country_map.get(code, code) if code else ''
            return (code, name)
    except Exception:
        return None, None


def query_ipapi(ip: str, max_retries: int = 3) -> tuple:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                if data.get('status') == 'success':
                    code = data.get('countryCode', '')
                    name = data.get('country', '')
                    return (code.upper() if code else None, name)
                else:
                    error_msg = data.get('message', 'unknown error')
                    print(f"    ip-api returned failure for {ip}: {error_msg}")
                    return None, None
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait_time = 2 ** attempt
                print(f"    ip-api rate limited for {ip}, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_time)
                continue
            else:
                print(f"    ip-api HTTP error for {ip}: {e.code}")
                return None, None
        except Exception as e:
            print(f"    ip-api error for {ip}: {e}")
            return None, None
    print(f"    ip-api failed for {ip} after {max_retries} retries")
    return None, None


def query_ipgeolocation(ip: str) -> tuple:
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
    if ip in cache:
        cached = cache[ip]
        if isinstance(cached, dict):
            code = cached.get('code')
            name = cached.get('name', country_map.get(code, code) if code else '')
        else:
            code = cached
            name = country_map.get(code, code) if code else ''
        return code, name, f"{code}#{name}" if code else "不可达"

    code, name = None, None
    for api in GEOIP_APIS:
        result = None
        if api == 'ipinfo':
            result = query_ipinfo(ip, country_map)
        elif api == 'ipapi':
            result = query_ipapi(ip)
        elif api == 'ipgeolocation':
            result = query_ipgeolocation(ip)

        if isinstance(result, (tuple, list)) and len(result) >= 2:
            code, name = result[0], result[1]
        else:
            code, name = None, None

        if code:
            break
        time.sleep(0.5)

    if code:
        if not name or name == code:
            name = country_map.get(code, code)
        cache[ip] = {'code': code, 'name': name, 'ts': time.time()}
        return code, name, f"{code}#{name}"
    else:
        cache[ip] = {'code': None, 'name': '', 'ts': time.time()}
        return None, '', '不可达'


def resolve_domain(domain: str, include_v6: bool = True) -> dict:
    """Resolve domain to IP addresses via DNS. Returns dict with 'ipv4', 'ipv6', 'all'."""
    results = {'ipv4': [], 'ipv6': [], 'all': []}
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        for item in result:
            ip = item[4][0]
            if ip not in results['ipv4']:
                results['ipv4'].append(ip)
                if ip not in results['all']:
                    results['all'].append(ip)
    except Exception:
        pass

    if include_v6:
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for item in result:
                ip = item[4][0]
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr.is_loopback or addr.is_link_local:
                        continue
                except ValueError:
                    continue
                if ip not in results['ipv6']:
                    results['ipv6'].append(ip)
                    if ip not in results['all']:
                        results['all'].append(ip)
        except Exception:
            pass

    return results


def fetch_url_ips(url: str) -> dict:
    """Fetch IP/domain list from a URL. Returns dict with 'ipv4', 'ipv6', 'domain', 'all'."""
    results = {'ipv4': [], 'ipv6': [], 'domain': [], 'all': []}
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
                host = extract_host(line)
                if not host:
                    continue
                addr_type = classify_address(host)
                if addr_type == 'ipv4':
                    if host not in results['ipv4']:
                        results['ipv4'].append(host)
                        results['all'].append(host)
                elif addr_type == 'ipv6':
                    if host not in results['ipv6']:
                        results['ipv6'].append(host)
                        results['all'].append(host)
                else:
                    if line not in results['domain']:
                        results['domain'].append(line)
                        results['all'].append(line)
    except Exception as e:
        print(f"  Fetch failed for {url}: {e}")
    return results


def collect_from_manual(manual_file: Path) -> dict:
    results = {'ipv4': [], 'ipv6': [], 'domain': [], 'all': []}
    if not manual_file.exists():
        return results
    with open(manual_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln:
                continue
            host = extract_host(ln)
            if not host:
                continue
            addr_type = classify_address(host)
            if addr_type == 'ipv4':
                if host not in results['ipv4']:
                    results['ipv4'].append(host)
                    results['all'].append(host)
            elif addr_type == 'ipv6':
                if host not in results['ipv6']:
                    results['ipv6'].append(host)
                    results['all'].append(host)
            else:
                if ln not in results['domain']:
                    results['domain'].append(ln)
                    results['all'].append(ln)
    print(f"  Collected {len(results['ipv4'])} IPv4, {len(results['ipv6'])} IPv6, {len(results['domain'])} domains from {manual_file}")
    return results


def collect_from_urls(urls_file: Path) -> dict:
    results = {'ipv4': [], 'ipv6': [], 'domain': [], 'all': []}
    if not urls_file.exists():
        print(f"  {urls_file} not found, skipping URL collection")
        return results
    with open(urls_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln or ln.startswith('#'):
                continue
            print(f"  Processing: {ln[:60]}...")
            if ln.startswith(('http://', 'https://')):
                fetched = fetch_url_ips(ln)
                for k in ['ipv4', 'ipv6', 'domain']:
                    for item in fetched[k]:
                        if item not in results[k]:
                            results[k].append(item)
                            if item not in results['all']:
                                results['all'].append(item)
                print(f"    -> Fetched {len(fetched['ipv4'])} IPv4, {len(fetched['ipv6'])} IPv6, {len(fetched['domain'])} domains")
            else:
                host = extract_host(ln)
                addr_type = classify_address(host)
                if addr_type == 'ipv4':
                    if host not in results['ipv4']:
                        results['ipv4'].append(host)
                        results['all'].append(host)
                    print(f"    -> Direct IPv4")
                elif addr_type == 'ipv6':
                    if host not in results['ipv6']:
                        results['ipv6'].append(host)
                        results['all'].append(host)
                    print(f"    -> Direct IPv6")
                else:
                    if ln not in results['domain']:
                        results['domain'].append(ln)
                        results['all'].append(ln)
                    print(f"    -> Domain")
    return results


def collect_from_domains(domains_file: Path) -> dict:
    results = {'ipv4': [], 'ipv6': [], 'domain': [], 'all': []}
    if not domains_file.exists():
        print(f"  {domains_file} not found, skipping domains")
        return results
    with open(domains_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln or ln.startswith('#'):
                continue
            domain = ln.split(':')[0].split('/')[0].strip()
            resolved = resolve_domain(domain)
            for ip in resolved['ipv4']:
                if ip not in results['ipv4']:
                    results['ipv4'].append(ip)
                    results['all'].append(ip)
            for ip in resolved['ipv6']:
                if ip not in results['ipv6']:
                    results['ipv6'].append(ip)
                    results['all'].append(ip)
            if ln not in results['domain']:
                results['domain'].append(ln)
                results['all'].append(ln)
            print(f"  Resolved {len(resolved['ipv4'])} IPv4, {len(resolved['ipv6'])} IPv6 from: {domain}")
    return results


def run_collection():
    os.makedirs(IPS_DIR, exist_ok=True)
    os.makedirs(IPS_WITH_COUNTRY_DIR, exist_ok=True)

    all_ipv4 = set()
    all_ipv6 = set()
    all_domains = set()

    print("[Source 1] Reading Manual_input_IP.txt...")
    manual = collect_from_manual(MANUAL_INPUT)
    all_ipv4.update(manual['ipv4'])
    all_ipv6.update(manual['ipv6'])
    all_domains.update(manual['domain'])

    print("[Source 2] Reading urls.txt...")
    urls = collect_from_urls(URLS_INPUT)
    all_ipv4.update(urls['ipv4'])
    all_ipv6.update(urls['ipv6'])
    all_domains.update(urls['domain'])

    print("[Source 3] Reading domains.txt...")
    domains = collect_from_domains(DOMAINS)
    all_ipv4.update(domains['ipv4'])
    all_ipv6.update(domains['ipv6'])
    all_domains.update(domains['domain'])

    if collect_all_ips is not None:
        print("\n[External] Trying collect_all_ips from DNS2Geo/proxyip...")
        try:
            collect_all_ips(str(MANUAL_INPUT), str(DOMAINS), str(ALL_IPS))
            if ALL_IPS.exists():
                with open(ALL_IPS, 'r', encoding='utf-8') as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln:
                            continue
                        host = extract_host(ln)
                        addr_type = classify_address(host)
                        if addr_type == 'ipv4':
                            all_ipv4.add(host)
                        elif addr_type == 'ipv6':
                            all_ipv6.add(host)
                        else:
                            all_domains.add(ln)
                print(f"  Merged external results")
        except Exception as e:
            print(f"  collect_all_ips failed: {e}")

    with open(ALL_IPS, 'w', encoding='utf-8') as out:
        for ip in sorted(all_ipv4):
            out.write(ip + '\n')
    print(f"\nWrote {len(all_ipv4)} IPv4 to {ALL_IPS}")

    with open(ALL_IPS_V6, 'w', encoding='utf-8') as out:
        for ip in sorted(all_ipv6):
            out.write(ip + '\n')
    print(f"Wrote {len(all_ipv6)} IPv6 to {ALL_IPS_V6}")

    with open(ALL_DOMAINS, 'w', encoding='utf-8') as out:
        for domain in sorted(all_domains):
            out.write(domain + '\n')
    print(f"Wrote {len(all_domains)} domains to {ALL_DOMAINS}")

    print(f"\nTotal unique: {len(all_ipv4)} IPv4, {len(all_ipv6)} IPv6, {len(all_domains)} domains")


def lookup_batch(ips: list, cache: dict, country_map: dict, label: str) -> list:
    """Lookup country for a batch of IPs, return list of (ip, info) tuples."""
    if not ips:
        return []

    print(f"\n[GeoIP] Looking up {len(ips)} {label} addresses...")
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

        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(ips)} | Success: {success_count} | Failed: {fail_count}")
        time.sleep(0.3)

    print(f"{label} lookup complete: {success_count} success, {fail_count} failed")
    return results


def run_geolookup_and_save():
    country_map = load_country_map(COUNTRIES_FILE)
    cache = load_geo_cache()

    # --- IPv4 GeoIP ---
    ipv4s = []
    if ALL_IPS.exists():
        with open(ALL_IPS, 'r', encoding='utf-8') as f:
            ipv4s = [ln.strip() for ln in f if ln.strip()]

    ipv4_results = lookup_batch(ipv4s, cache, country_map, "IPv4")

    with open(ALL_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for ip, info in ipv4_results:
            f.write(f"{ip}#{info}\n")
    print(f"Wrote {len(ipv4_results)} IPv4 entries to {ALL_WITH_COUNTRY}")

    # --- IPv6 GeoIP ---
    ipv6s = []
    if ALL_IPS_V6.exists():
        with open(ALL_IPS_V6, 'r', encoding='utf-8') as f:
            ipv6s = [ln.strip() for ln in f if ln.strip()]

    ipv6_results = lookup_batch(ipv6s, cache, country_map, "IPv6")

    with open(ALL_WITH_COUNTRY_V6, 'w', encoding='utf-8') as f:
        for ip, info in ipv6_results:
            f.write(f"{ip}#{info}\n")
    print(f"Wrote {len(ipv6_results)} IPv6 entries to {ALL_WITH_COUNTRY_V6}")

    # --- Domain GeoIP ---
    domains = []
    if ALL_DOMAINS.exists():
        with open(ALL_DOMAINS, 'r', encoding='utf-8') as f:
            domains = [ln.strip() for ln in f if ln.strip()]

    domain_results = []
    if domains:
        print(f"\n[GeoIP] Looking up {len(domains)} domains (via DNS resolution)...")
        success_count = 0
        fail_count = 0

        for i, domain_line in enumerate(domains):
            domain = domain_line.split(':')[0].split('/')[0].strip()
            resolved = resolve_domain(domain)

            lookup_ip = None
            if resolved['ipv4']:
                lookup_ip = resolved['ipv4'][0]
            elif resolved['ipv6']:
                lookup_ip = resolved['ipv6'][0]

            if lookup_ip:
                code, name, info = lookup_country(lookup_ip, cache, country_map)
                if code:
                    success_count += 1
                    domain_results.append((domain_line, info))
                else:
                    fail_count += 1
                    domain_results.append((domain_line, "不可达"))
            else:
                fail_count += 1
                domain_results.append((domain_line, "不可达"))

            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{len(domains)} | Success: {success_count} | Failed: {fail_count}")
            time.sleep(0.3)

        print(f"Domain lookup complete: {success_count} success, {fail_count} failed")

    with open(ALL_WITH_COUNTRY_DOMAIN, 'w', encoding='utf-8') as f:
        for domain, info in domain_results:
            f.write(f"{domain}#{info}\n")
    print(f"Wrote {len(domain_results)} domain entries to {ALL_WITH_COUNTRY_DOMAIN}")

    save_geo_cache(cache)


def parse_with_country(path: Path):
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
    m = re.search(r'^([A-Z]{2})#', info)
    if m:
        return m.group(1)
    m = re.search(r'^([A-Z]{2})[A-Z]', info)
    if m:
        return m.group(1)
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


def filter_and_write(entries: list, allowed_codes: set, 
                     out_allowed_ips: Path, out_blocked_ips: Path, out_unreachable_ips: Path,
                     out_allowed_info: Path, out_blocked_info: Path, out_unreachable_info: Path,
                     label: str):

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

    print(f"  [{label}] Allowed: {len(allowed_ips)} | Blocked: {len(blocked_ips)} | Unreachable: {len(unreachable_ips)}")

    IPS_DIR.mkdir(parents=True, exist_ok=True)
    IPS_WITH_COUNTRY_DIR.mkdir(parents=True, exist_ok=True)

    with open(out_allowed_ips, 'w', encoding='utf-8') as f:
        for ip in sorted(set(allowed_ips)):
            f.write(ip + '\n')
    with open(out_blocked_ips, 'w', encoding='utf-8') as f:
        for ip in sorted(set(blocked_ips)):
            f.write(ip + '\n')
    with open(out_unreachable_ips, 'w', encoding='utf-8') as f:
        for ip in sorted(set(unreachable_ips)):
            f.write(ip + '\n')

    with open(out_allowed_info, 'w', encoding='utf-8') as f:
        for line in sorted(set(allowed_info)):
            f.write(line + '\n')
    with open(out_blocked_info, 'w', encoding='utf-8') as f:
        for line in sorted(set(blocked_info)):
            f.write(line + '\n')
    with open(out_unreachable_info, 'w', encoding='utf-8') as f:
        for line in sorted(set(unreachable_info)):
            f.write(line + '\n')

    return allowed_ips, blocked_ips, unreachable_ips, allowed_info, blocked_info, unreachable_info


def run_filter_and_write():
    allowed_codes = load_allowed_codes(ALLOWED_COUNTRIES)
    print(f"\n[Filter] Allowed country codes: {sorted(allowed_codes)}")

    # --- IPv4 Filter ---
    print("\n[Filter] Processing IPv4...")
    ipv4_entries = parse_with_country(ALL_WITH_COUNTRY)
    ipv4_allowed, ipv4_blocked, ipv4_unreachable, \
    ipv4_allowed_info, ipv4_blocked_info, ipv4_unreachable_info = filter_and_write(
        ipv4_entries, allowed_codes,
        OUT_ALLOWED_IPS, OUT_BLOCKED_IPS, OUT_UNREACHABLE_IPS,
        OUT_ALLOWED_WITH_INFO, OUT_BLOCKED_WITH_INFO, OUT_UNREACHABLE_WITH_INFO,
        "IPv4"
    )

    # --- IPv6 Filter ---
    print("\n[Filter] Processing IPv6...")
    ipv6_entries = parse_with_country(ALL_WITH_COUNTRY_V6)
    ipv6_allowed, ipv6_blocked, ipv6_unreachable, \
    ipv6_allowed_info, ipv6_blocked_info, ipv6_unreachable_info = filter_and_write(
        ipv6_entries, allowed_codes,
        OUT_ALLOWED_IPS_V6, OUT_BLOCKED_IPS_V6, OUT_UNREACHABLE_IPS_V6,
        OUT_ALLOWED_WITH_INFO_V6, OUT_BLOCKED_WITH_INFO_V6, OUT_UNREACHABLE_WITH_INFO_V6,
        "IPv6"
    )

    # --- Domain Filter ---
    print("\n[Filter] Processing Domains...")
    domain_entries = parse_with_country(ALL_WITH_COUNTRY_DOMAIN)
    domain_allowed, domain_blocked, domain_unreachable, \
    domain_allowed_info, domain_blocked_info, domain_unreachable_info = filter_and_write(
        domain_entries, allowed_codes,
        OUT_ALLOWED_DOMAINS, OUT_BLOCKED_DOMAINS, OUT_UNREACHABLE_DOMAINS,
        OUT_ALLOWED_WITH_INFO_DOMAIN, OUT_BLOCKED_WITH_INFO_DOMAIN, OUT_UNREACHABLE_WITH_INFO_DOMAIN,
        "Domain"
    )

    # --- Generate proxyip files ---

    # IPv4
    proxyip_v4 = sorted(set(ipv4_allowed + ipv4_blocked))
    with open(PROXYIP, 'w', encoding='utf-8') as f:
        for ip in proxyip_v4:
            f.write(ip + '\n')

    proxyip_v4_info = sorted(set(ipv4_allowed_info + ipv4_blocked_info))
    with open(PROXYIP_WITH_COUNTRY_V4, 'w', encoding='utf-8') as f:
        for line in proxyip_v4_info:
            f.write(line + '\n')

    # IPv6
    proxyip_v6 = sorted(set(ipv6_allowed + ipv6_blocked))
    with open(PROXYIP_V6, 'w', encoding='utf-8') as f:
        for ip in proxyip_v6:
            f.write(ip + '\n')

    proxyip_v6_info = sorted(set(ipv6_allowed_info + ipv6_blocked_info))
    with open(PROXYIP_WITH_COUNTRY_V6, 'w', encoding='utf-8') as f:
        for line in proxyip_v6_info:
            f.write(line + '\n')

    # Domain
    proxyip_domain = sorted(set(domain_allowed + domain_blocked))
    with open(PROXYIP_DOMAIN, 'w', encoding='utf-8') as f:
        for domain in proxyip_domain:
            f.write(domain + '\n')

    proxyip_domain_info = sorted(set(domain_allowed_info + domain_blocked_info))
    with open(PROXYIP_DOMAIN_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for line in proxyip_domain_info:
            f.write(line + '\n')

    # Combined (IPv4 + IPv6)
    all_proxy_ips = sorted(set(proxyip_v4 + proxyip_v6))
    with open(PROXYIP_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for line in sorted(set(proxyip_v4_info + proxyip_v6_info)):
            f.write(line + '\n')

    print(f"\n[Output Summary]")
    print(f"  === IPv4 ===")
    print(f"    ips/allowed_ips.txt              : {len(ipv4_allowed)}")
    print(f"    ips/blocked_ips.txt              : {len(ipv4_blocked)}")
    print(f"    ips/unreachable_ips.txt          : {len(ipv4_unreachable)}")
    print(f"    ips_with_country/allowed_ips_with_country.txt    : {len(ipv4_allowed_info)}")
    print(f"    ips_with_country/blocked_ips_with_country.txt      : {len(ipv4_blocked_info)}")
    print(f"    ips_with_country/unreachable_ips_with_country.txt  : {len(ipv4_unreachable_info)}")
    print(f"    proxyip.txt                      : {len(proxyip_v4)}")
    print(f"    proxyip_with_country_v4.txt      : {len(proxyip_v4_info)}")
    print(f"  === IPv6 ===")
    print(f"    ips/allowed_ips_v6.txt           : {len(ipv6_allowed)}")
    print(f"    ips/blocked_ips_v6.txt           : {len(ipv6_blocked)}")
    print(f"    ips/unreachable_ips_v6.txt       : {len(ipv6_unreachable)}")
    print(f"    ips_with_country/allowed_ips_with_country_v6.txt   : {len(ipv6_allowed_info)}")
    print(f"    ips_with_country/blocked_ips_with_country_v6.txt     : {len(ipv6_blocked_info)}")
    print(f"    ips_with_country/unreachable_ips_with_country_v6.txt : {len(ipv6_unreachable_info)}")
    print(f"    proxyip_v6.txt                   : {len(proxyip_v6)}")
    print(f"    proxyip_with_country_v6.txt      : {len(proxyip_v6_info)}")
    print(f"  === Domain ===")
    print(f"    ips/allowed_domains.txt          : {len(domain_allowed)}")
    print(f"    ips/blocked_domains.txt          : {len(domain_blocked)}")
    print(f"    ips/unreachable_domains.txt      : {len(domain_unreachable)}")
    print(f"    ips_with_country/allowed_domains_with_country.txt    : {len(domain_allowed_info)}")
    print(f"    ips_with_country/blocked_domains_with_country.txt      : {len(domain_blocked_info)}")
    print(f"    ips_with_country/unreachable_domains_with_country.txt  : {len(domain_unreachable_info)}")
    print(f"    proxyip_domain.txt               : {len(proxyip_domain)}")
    print(f"    proxyip_domain_with_country.txt  : {len(proxyip_domain_info)}")
    print(f"  === Combined ===")
    print(f"    proxyip_with_country.txt         : {len(all_proxy_ips)}")


def run_speedtest():
    """Run speedtest.py after generation."""
    speedtest_script = ROOT / 'speedtest.py'

    # 如果当前目录没有，尝试 scripts/ 目录
    if not speedtest_script.exists():
        speedtest_script = ROOT / 'scripts' / 'speedtest.py'

    if not speedtest_script.exists():
        print(f"\n[SpeedTest] Warning: speedtest.py not found at {speedtest_script}")
        print("  Skipping speed test. Place speedtest.py in repo root or scripts/ directory.")
        return

    print(f"\n[SpeedTest] Running {speedtest_script}...")
    try:
        result = subprocess.run(
            [sys.executable, str(speedtest_script)],
            capture_output=False,
            text=True,
            check=False
        )
        if result.returncode != 0:
            print(f"[SpeedTest] Warning: speedtest.py exited with code {result.returncode}")
    except Exception as e:
        print(f"[SpeedTest] Error running speedtest.py: {e}")


def main():
    run_collection()
    run_geolookup_and_save()
    run_filter_and_write()
    run_speedtest()  # 自动运行测速
    print("\n=== All done ===")


if __name__ == '__main__':
    main()
