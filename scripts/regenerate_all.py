#!/usr/bin/env python3
# scripts/regenerate_all.py
"""
Regenerate IP lists and classification from Manual_input_IP.txt and domains.txt.
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

Run in repository root. This script is intended to be executed by CI (GitHub Actions).
"""
import os
import re
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

# Input sources
MANUAL_INPUT = ROOT / 'Manual_input_IP.txt'
DOMAINS = ROOT / 'domains.txt'

def clean_line_prefix(s: str) -> str:
    # Remove a leading numbered prefix like "1| " if present, and trim
    return re.sub(r'^\s*\d+\|\s*', '', s).strip()

def run_collection():
    os.makedirs(IPS_DIR, exist_ok=True)
    os.makedirs(IPS_WITH_COUNTRY_DIR, exist_ok=True)
    # collect_all_ips writes ips/all_ips.txt by default when called with our paths
    if collect_all_ips is None:
        print("Warning: collect_all_ips not available; falling back to simple Manual_input_IP copy")
        # fallback: copy Manual_input_IP.txt to ips/all_ips.txt (cleaned)
        ips = []
        if MANUAL_INPUT.exists():
            with open(MANUAL_INPUT, 'r', encoding='utf-8') as f:
                for ln in f:
                    ln = clean_line_prefix(ln)
                    if ln:
                        ips.append(ln)
        with open(ALL_IPS, 'w', encoding='utf-8') as out:
            for ip in sorted(set(ips)):
                out.write(ip + '\n')
        return

    # call the repo's collect_all_ips function
    print("Running collect_all_ips...")
    try:
        collect_all_ips(str(MANUAL_INPUT), str(DOMAINS), str(ALL_IPS))
    except TypeError:
        # some implementations may expect only two args (manual, domains) and write fixed file
        try:
            collect_all_ips(str(MANUAL_INPUT), str(DOMAINS))
        except Exception as e:
            print("collect_all_ips failed:", e)

def run_geolookup_and_save():
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
    entries = []  # list of tuples (ip, info_part)
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
    # try to extract two-letter uppercase country code
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

def main():
    run_collection()
    run_geolookup_and_save()
    run_filter_and_write()

if __name__ == '__main__':
    main()
