#!/usr/bin/env python3
# name=scripts/generate_ips.py
"""
Generate ips_with_country/all_ips_with_country.txt and the three filtered outputs:
 - ips_with_country/allowed_ips_with_country.txt
 - ips_with_country/blocked_ips_with_country.txt
 - ips_with_country/unreachable_ips_with_country.txt

Logic:
 1) Prefer existing ips_with_country/all_ips_with_country.txt
 2) Else prefer ips/all_ips.txt (enrich via ipinfo or proxyip.get_country_info)
 3) Else prefer proxyip_with_country.txt (copy)
 4) Else prefer proxyip.txt (enrich)
 5) Else attempt to run DNS2Geo.py to produce ips/all_ips.txt, then step 2
Then call proxyip.filter_ips_by_allowed_countries if available, else fallback.
"""
import os, sys, time, shutil

def load_country_mapping(path="countries.txt"):
    mapping = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                parts = ln.strip().split(",")
                if len(parts) == 2:
                    code, name = parts
                    mapping[code.strip()] = name.strip()
    return mapping

def lookup_ipinfo(ip, country_mapping):
    import requests
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            code = data.get("country", "未知")
            name = country_mapping.get(code, code)
            return f"{code}#{name}"
        else:
            return "未知"
    except Exception as e:
        print("ipinfo lookup failed for", ip, e, file=sys.stderr)
        return "不可达"

def enrich_ips_from_list(ips, country_mapping, use_proxyip_get=None):
    out_lines = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        info = None
        try:
            if use_proxyip_get:
                info = use_proxyip_get(ip, country_mapping)
            else:
                info = lookup_ipinfo(ip, country_mapping)
        except Exception as e:
            print("lookup error:", e, file=sys.stderr)
            info = "未知"
        if isinstance(info, str) and '#' in info:
            # keep the part after '#': country name (consistent with repo files)
            country_name = info.split('#',1)[1]
            out_lines.append(f"{ip}#{country_name}")
        else:
            out_lines.append(f"{ip}#{info}")
    return out_lines

def main():
    os.makedirs("ips_with_country", exist_ok=True)
    country_mapping = load_country_mapping("countries.txt")

    all_out = "ips_with_country/all_ips_with_country.txt"
    ips_list = "ips/all_ips.txt"
    proxy_with_country = "proxyip_with_country.txt"
    proxy_plain = "proxyip.txt"
    dns_script = "DNS2Geo.py"

    # Try import helper functions from proxyip.py if available
    use_proxy_helpers = False
    use_proxy_get = None
    filter_fn = None
    try:
        from proxyip import load_country_mapping as _lcm, get_country_info as _gci, filter_ips_by_allowed_countries as _filter
        # prefer proxyip's mapping & functions if present
        country_mapping = _lcm("countries.txt") or country_mapping
        use_proxy_helpers = True
        use_proxy_get = _gci
        filter_fn = _filter
    except Exception as e:
        # not fatal; fallback behavior will use ipinfo
        print("proxyip helpers not available:", e)

    # 1) If already exists, use it
    if os.path.exists(all_out):
        print("Using existing", all_out)
        input_file = all_out
    else:
        # 2) If ips/all_ips.txt exists -> enrich
        if os.path.exists(ips_list):
            print("Generating", all_out, "from", ips_list)
            with open(ips_list, "r", encoding="utf-8") as f:
                ips = [ln.strip() for ln in f if ln.strip()]
            lines = enrich_ips_from_list(ips, country_mapping, use_proxy_get)
            with open(all_out, "w", encoding="utf-8") as out:
                for l in lines:
                    out.write(l + "\n")
            input_file = all_out
        elif os.path.exists(proxy_with_country):
            print("Copying", proxy_with_country, "->", all_out)
            shutil.copy(proxy_with_country, all_out)
            input_file = all_out
        elif os.path.exists(proxy_plain):
            print("Generating", all_out, "from", proxy_plain)
            with open(proxy_plain, "r", encoding="utf-8") as f:
                ips = [ln.strip().split("#",1)[0].strip() for ln in f if ln.strip()]
            lines = enrich_ips_from_list(ips, country_mapping, use_proxy_get)
            with open(all_out, "w", encoding="utf-8") as out:
                for l in lines:
                    out.write(l + "\n")
            input_file = all_out
        else:
            # try running DNS2Geo.py to create ips/all_ips.txt then loop back
            if os.path.exists(dns_script):
                print("Attempting to run", dns_script)
                rc = os.system(f"{sys.executable} {dns_script}")
                time.sleep(1)
                if os.path.exists(all_out):
                    input_file = all_out
                elif os.path.exists(ips_list):
                    with open(ips_list, "r", encoding="utf-8") as f:
                        ips = [ln.strip() for ln in f if ln.strip()]
                    lines = enrich_ips_from_list(ips, country_mapping, use_proxy_get)
                    with open(all_out, "w", encoding="utf-8") as out:
                        for l in lines:
                            out.write(l + "\n")
                    input_file = all_out
                else:
                    print("DNS2Geo did not create expected files", file=sys.stderr)
                    sys.exit(1)
            else:
                print("No source found to produce all_ips_with_country.txt", file=sys.stderr)
                sys.exit(1)

    # Now filter into allowed/blocked/unreachable (with info)
    allowed_with_info = "ips_with_country/allowed_ips_with_country.txt"
    blocked_with_info = "ips_with_country/blocked_ips_with_country.txt"
    unreachable_with_info = "ips_with_country/unreachable_ips_with_country.txt"

    # If proxy helper available, call it; else fallback
    if filter_fn:
        try:
            filter_fn(
                input_file,
                'allowed_countries.txt',
                'ips_with_country/allowed_ips.txt',
                'ips_with_country/blocked_ips.txt',
                allowed_with_info,
                blocked_with_info,
                'ips_with_country/unreachable_ips.txt',
                unreachable_with_info
            )
        except Exception as e:
            print("proxyip.filter call failed:", e, file=sys.stderr)
            # fall through to fallback
    else:
        print("Using fallback filter implementation")
        allowed = set()
        if os.path.exists('allowed_countries.txt'):
            with open('allowed_countries.txt','r',encoding='utf-8') as f:
                for ln in f:
                    v = ln.strip()
                    if v:
                        allowed.add(v)

        allowed_info_lines = []
        blocked_info_lines = []
        unreachable_info_lines = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                parts = ln.split('#',1)
                ip = parts[0].strip()
                info = parts[1].strip() if len(parts) > 1 else ''
                if info in ("不可达", "未知", ""):
                    unreachable_info_lines.append(ln)
                else:
                    # check if any allowed token matches (code or name)
                    matched = False
                    for a in allowed:
                        if a and (a in info or a in ln):
                            matched = True
                            break
                    if matched:
                        allowed_info_lines.append(ln)
                    else:
                        blocked_info_lines.append(ln)

        with open(allowed_with_info, 'w', encoding='utf-8') as f:
            for l in allowed_info_lines:
                f.write(l + "\n")
        with open(blocked_with_info, 'w', encoding='utf-8') as f:
            for l in blocked_info_lines:
                f.write(l + "\n")
        with open(unreachable_with_info, 'w', encoding='utf-8') as f:
            for l in unreachable_info_lines:
                f.write(l + "\n")

    # verify outputs
    expected = [
        all_out,
        allowed_with_info,
        blocked_with_info,
        unreachable_with_info
    ]
    missing = [p for p in expected if not os.path.exists(p)]
    if missing:
        print("Missing outputs:", missing, file=sys.stderr)
        sys.exit(1)
    else:
        print("Generated all expected files:")
        for p in expected:
            print(" -", p)

if __name__ == "__main__":
    main()
