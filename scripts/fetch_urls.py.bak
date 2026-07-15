#!/usr/bin/env python3
# name=scripts/fetch_urls.py
"""
Fetch IP lists from urls.txt, extract IPv4 addresses and write ips/all_ips.txt (deduplicated, sorted).
"""
import re, os, sys, requests

TIMEOUT = 15
HEADERS = {"User-Agent": "cf-proxyip-fetcher/1.0"}

RE_IP = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})")  # simple IPv4 extractor

def load_urls(path="urls.txt"):
    urls = []
    if not os.path.exists(path):
        return urls
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            urls.append(ln)
    return urls

def fetch_text(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"Failed to fetch {url}: {e}", file=sys.stderr)
        return ""

def extract_ips(text):
    results = set()
    for m in RE_IP.finditer(text):
        ip = m.group(0).strip()
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    results.add(ip)
            except ValueError:
                continue
    return results

def main():
    os.makedirs("ips", exist_ok=True)
    urls = load_urls("urls.txt")
    if not urls:
        print("No urls found in urls.txt")
    all_ips = set()
    for url in urls:
        print("Fetching", url)
        txt = fetch_text(url)
        if not txt:
            continue
        ips = extract_ips(txt)
        print(f"  -> found {len(ips)} IPs")
        all_ips.update(ips)

    # include Manual_input_IP.txt if present
    if os.path.exists("Manual_input_IP.txt"):
        with open("Manual_input_IP.txt", "r", encoding="utf-8") as f:
            for ln in f:
                v = ln.strip()
                if v:
                    all_ips.add(v)

    # include proxyip.txt plain list if present
    if os.path.exists("proxyip.txt"):
        with open("proxyip.txt", "r", encoding="utf-8") as f:
            for ln in f:
                v = ln.strip().split("#",1)[0].strip()
                if v:
                    all_ips.add(v)

    out_path = os.path.join("ips", "all_ips.txt")
    with open(out_path, "w", encoding="utf-8") as out:
        for ip in sorted(all_ips):
            out.write(ip + "\n")
    print(f"Wrote {len(all_ips)} unique IPs to {out_path}")

if __name__ == "__main__":
    main()
