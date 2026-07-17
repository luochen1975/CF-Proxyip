#!/usr/bin/env python3
# scripts/regenerate_all.py
"""
Regenerate IP lists and classification from multiple data sources:
  - Manual_input_IP.txt  (手动输入的 IP 列表)
  - urls.txt             (URL 列表，支持 IP、域名、可 fetch 的 URL)
  - domains.txt          (域名列表，需要 DNS 解析)

This script calls existing DNS2Geo.collect_all_ips and DNS2Geo.save_all_ip_country
then produces the following files (overwriting existing):
  - ips/all_ips.txt
  - ips_with_country/all_ips_with_country.txt
  - ips/allowed_ips.txt
  - ips/blocked_ips.txt
  - ips/unreachable_ips.txt
  - ips_with_country/allowed_ips_with_country.txt
  - ips_with_country/blocked_ips_with_country.txt
  - ips_with_country/unreachable_ips_with_country.txt
  - proxyip.txt                          (所有可达 IP)
  - proxyip_with_country.txt             (所有可达 IP 带国家信息)

Run in repository root. This script is intended to be executed by CI (GitHub Actions).
"""
import os
import re
import socket
import ipaddress
from pathlib import Path

# Try to import helper functions from DNS2Geo.py. If import fails, try proxyip.py equivalents.
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

ALL_IPS = IPS_DIR / 'all_ips.txt'
ALL_WITH_COUNTRY = IPS_WITH_COUNTRY_DIR / 'all_ips_with_country.txt'
ALLOWED_COUNTRIES = ROOT / 'allowed_countries.txt'

# Output files
OUT_ALLOWED_IPS = IPS_DIR / 'allowed_ips.txt'
OUT_BLOCKED_IPS = IPS_DIR / 'blocked_ips.txt'
OUT_UNREACHABLE_IPS = IPS_DIR / 'unreachable_ips.txt'
OUT_ALLOWED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'allowed_ips_with_country.txt'
OUT_BLOCKED_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'blocked_ips_with_country.txt'
OUT_UNREACHABLE_WITH_INFO = IPS_WITH_COUNTRY_DIR / 'unreachable_ips_with_country.txt'

# 新增: proxyip 输出文件
PROXYIP = ROOT / 'proxyip.txt'
PROXYIP_WITH_COUNTRY = ROOT / 'proxyip_with_country.txt'

# Input sources
MANUAL_INPUT = ROOT / 'Manual_input_IP.txt'
URLS_INPUT = ROOT / 'urls.txt'
DOMAINS = ROOT / 'domains.txt'


def clean_line_prefix(s: str) -> str:
    """Remove a leading numbered prefix like "1| " if present, and trim."""
    return re.sub(r'^\s*\d+\|\s*', '', s).strip()


def is_ip_address(s: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_domain(domain: str) -> list:
    """Resolve domain to IP addresses via DNS."""
    ips = []
    try:
        # Try IPv4
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        for item in result:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        print(f"  DNS resolve failed for {domain}: {e}")
    return ips


def fetch_url_ips(url: str) -> list:
    """Fetch IP list from a URL (plain text, one IP per line)."""
    ips = []
    try:
        import urllib.request
        import ssl
        # Create SSL context that doesn't verify certificates (for compatibility)
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
                # Extract IP from line (handle formats like "ip:port" or "ip#comment")
                ip_part = line.split(':')[0].split('#')[0].strip()
                if is_ip_address(ip_part):
                    ips.append(ip_part)
                elif is_ip_address(line):
                    ips.append(line)
    except Exception as e:
        print(f"  Fetch failed for {url}: {e}")
    return ips


def collect_from_urls(urls_file: Path) -> list:
    """Collect IPs from urls.txt (supports IPs, domains, and fetchable URLs)."""
    ips = []
    if not urls_file.exists():
        print(f"  {urls_file} not found, skipping URL collection")
        return ips

    with open(urls_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln or ln.startswith('#'):
                continue

            print(f"  Processing URL entry: {ln[:60]}...")

            # Case 1: Direct IP address
            if is_ip_address(ln):
                ips.append(ln)
                print(f"    -> Direct IP: {ln}")
                continue

            # Case 2: HTTP/HTTPS URL -> fetch content
            if ln.startswith(('http://', 'https://')):
                fetched = fetch_url_ips(ln)
                ips.extend(fetched)
                print(f"    -> Fetched {len(fetched)} IPs from URL")
                continue

            # Case 3: Domain name -> DNS resolve
            domain = ln.split(':')[0].split('/')[0].strip()
            resolved = resolve_domain(domain)
            ips.extend(resolved)
            print(f"    -> Resolved {len(resolved)} IPs from domain {domain}")

    return ips


def collect_from_manual(manual_file: Path) -> list:
    """Collect IPs from Manual_input_IP.txt."""
    ips = []
    if not manual_file.exists():
        print(f"  {manual_file} not found, skipping manual input")
        return ips

    with open(manual_file, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln:
                continue
            # Extract IP (handle "ip:port" or "ip#comment")
            ip_part = ln.split(':')[0].split('#')[0].strip()
            if is_ip_address(ip_part):
                ips.append(ip_part)
            elif is_ip_address(ln):
                ips.append(ln)

    print(f"  Collected {len(ips)} IPs from {manual_file}")
    return ips


def collect_from_domains(domains_file: Path) -> list:
    """Collect IPs from domains.txt (DNS resolve each domain)."""
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
            print(f"  Resolved {len(resolved)} IPs from domain: {domain}")

    print(f"  Total {len(ips)} IPs from domains")
    return ips


def run_collection():
    """Collect IPs from all sources and write to ips/all_ips.txt."""
    os.makedirs(IPS_DIR, exist_ok=True)
    os.makedirs(IPS_WITH_COUNTRY_DIR, exist_ok=True)

    all_ips = set()

    # Source 1: Manual_input_IP.txt
    print("[Source 1] Reading Manual_input_IP.txt...")
    manual_ips = collect_from_manual(MANUAL_INPUT)
    all_ips.update(manual_ips)

    # Source 2: urls.txt (IPs, domains, fetchable URLs)
    print("[Source 2] Reading urls.txt...")
    url_ips = collect_from_urls(URLS_INPUT)
    all_ips.update(url_ips)

    # Source 3: domains.txt
    print("[Source 3] Reading domains.txt...")
    domain_ips = collect_from_domains(DOMAINS)
    all_ips.update(domain_ips)

    print(f"\nTotal unique IPs collected: {len(all_ips)}")

    # Also try external collect_all_ips if available
    if collect_all_ips is not None:
        print("\n[External] Running collect_all_ips from DNS2Geo/proxyip...")
        try:
            # Try to call with our sources
            collect_all_ips(str(MANUAL_INPUT), str(DOMAINS), str(ALL_IPS))
            # Read what it produced and merge
            if ALL_IPS.exists():
                with open(ALL_IPS, 'r', encoding='utf-8') as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln and is_ip_address(ln.split(':')[0].split('#')[0]):
                            all_ips.add(ln.split(':')[0].split('#')[0])
                print(f"  Merged external results, total: {len(all_ips)}")
        except TypeError:
            try:
                collect_all_ips(str(MANUAL_INPUT), str(DOMAINS))
            except Exception as e:
                print(f"  collect_all_ips failed: {e}")
        except Exception as e:
            print(f"  collect_all_ips failed: {e}")

    # Write merged results
    with open(ALL_IPS, 'w', encoding='utf-8') as out:
        for ip in sorted(all_ips):
            out.write(ip + '\n')

    print(f"Wrote {len(all_ips)} IPs to {ALL_IPS}")


def run_geolookup_and_save():
    """Run geolocation lookup and save results."""
    # Clear target file first
    if ALL_WITH_COUNTRY.exists():
        ALL_WITH_COUNTRY.unlink()

    country_mapping = {}
    if load_country_mapping:
        try:
            country_mapping = load_country_mapping('countries.txt')
        except Exception as e:
            print('load_country_mapping failed:', e)

    if save_all_ip_country is None:
        print('Warning: save_all_ip_country not available; skipping geolocation step')
        return

    print('Running save_all_ip_country (this may take a while)...')
    try:
        save_all_ip_country(str(ALL_IPS), str(ALL_WITH_COUNTRY), country_mapping)
    except Exception as e:
        print('save_all_ip_country failed:', e)


def parse_all_with_country(path: Path):
    """Parse ip#country_info format, return list of (ip, info_part) tuples."""
    entries = []
    if not path.exists():
        return entries
    with open(path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = clean_line_prefix(ln)
            if not ln:
                continue
            # Support formats: IP#CODE#NAME, IP#CODENAME, IP#不可达, IP
            parts = ln.split('#')
            ip = parts[0].strip()
            info = '#'.join(parts[1:]).strip() if len(parts) > 1 else ''
            entries.append((ip, info))
    return entries


def extract_country_code(info: str):
    """Extract two-letter uppercase country code from info string."""
    if not info:
        return None
    m = re.search(r'\b([A-Z]{2})\b', info)
    if m:
        return m.group(1)
    if '不可' in info or '不可达' in info:
        return 'UNREACH'
    return None


def load_allowed_codes(path: Path):
    """Load allowed country codes from file."""
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
    """Filter IPs by country code and write classification files."""
    entries = parse_all_with_country(ALL_WITH_COUNTRY)
    allowed_codes = load_allowed_codes(ALLOWED_COUNTRIES)

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

    print('Filter step completed. Wrote allowed/blocked/unreachable files.')

    # ========================================================================
    # 生成 proxyip.txt 和 proxyip_with_country.txt
    # ========================================================================
    # proxyip.txt = 所有可达的 IP (allowed + blocked，排除 unreachable)
    all_proxy_ips = sorted(set(allowed_ips + blocked_ips))
    with open(PROXYIP, 'w', encoding='utf-8') as f:
        for ip in all_proxy_ips:
            f.write(ip + '\n')

    # proxyip_with_country.txt = 所有可达 IP 带国家信息
    all_proxy_with_country = sorted(set(allowed_info + blocked_info))
    with open(PROXYIP_WITH_COUNTRY, 'w', encoding='utf-8') as f:
        for line in all_proxy_with_country:
            f.write(line + '\n')

    print(f'Wrote {PROXYIP} ({len(all_proxy_ips)} IPs) and {PROXYIP_WITH_COUNTRY} ({len(all_proxy_with_country)} IPs)')


def main():
    run_collection()
    run_geolookup_and_save()
    run_filter_and_write()


if __name__ == '__main__':
    main()
