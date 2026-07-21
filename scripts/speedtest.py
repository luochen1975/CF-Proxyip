#!/usr/bin/env python3
"""
Speed test script for CF-Proxyip.
Reads allowed_ips_with_country.txt, splits into groups of 500 entries,
tests each group via TCP connection to port 443, sorts by latency,
and generates numbered output files.

Output format: IP#国家代码_国家名称_延迟ms
Example: 104.17.146.60#US_美国_1.44ms

Usage: python speedtest.py [input_file] [output_dir] [group_size] [concurrency] [timeout]
"""
import sys
import socket
import time
import concurrent.futures
from pathlib import Path

DEFAULT_INPUT = Path('ips_with_country/allowed_ips_with_country.txt')
DEFAULT_OUTPUT_DIR = Path('ips_with_country')
DEFAULT_GROUP_SIZE = 500
DEFAULT_CONCURRENCY = 30
DEFAULT_TIMEOUT = 3


def parse_entry(line: str):
    """Parse line like '1.2.3.4#US#United States' -> (ip, country_code, country_name)."""
    line = line.strip()
    if not line:
        return None, None, None
    parts = line.split('#')
    ip = parts[0].strip()
    country_code = parts[1].strip() if len(parts) > 1 else ''
    country_name = parts[2].strip() if len(parts) > 2 else country_code
    return ip, country_code, country_name


def test_latency(ip: str, port: int = 443, timeout: float = 3.0):
    """Test TCP connection latency to ip:port. Returns latency_ms or None if failed."""
    try:
        start = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=timeout)
        latency = (time.perf_counter() - start) * 1000
        sock.close()
        return round(latency, 2)
    except Exception:
        return None


def speed_test_group(entries: list, group_num: int, concurrency: int, timeout: float):
    """Run speed test on a group of entries. Returns sorted list of (ip, code, name, latency_ms)."""
    total = len(entries)
    print(f"\n[SpeedTest Group {group_num}] Testing {total} IPs (port 443, timeout {timeout}s, concurrency {concurrency})...")

    results = []
    success_count = 0
    fail_count = 0

    def test_one(args):
        idx, ip, code, name = args
        latency = test_latency(ip, port=443, timeout=timeout)
        return idx, ip, code, name, latency

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(test_one, (i, e[0], e[1], e[2])): i 
                   for i, e in enumerate(entries)}

        completed = 0
        for future in concurrent.futures.as_completed(futures):
            idx, ip, code, name, latency = future.result()
            if latency is not None:
                results.append((ip, code, name, latency))
                success_count += 1
                status = f"{latency}ms"
            else:
                fail_count += 1
                status = "TIMEOUT/FAIL"

            completed += 1
            if completed % 10 == 0 or completed == total:
                print(f"  Progress: {completed}/{total} | Success: {success_count} | Failed: {fail_count}")

    # Sort by latency (ascending)
    results.sort(key=lambda x: x[3])

    print(f"[SpeedTest Group {group_num}] Complete: {success_count} reachable, {fail_count} failed")
    if results:
        print(f"  Fastest: {results[0][3]}ms, Slowest: {results[-1][3]}ms")

    return results


def main():
    input_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT_DIR
    group_size = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_GROUP_SIZE
    concurrency = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_CONCURRENCY
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else DEFAULT_TIMEOUT

    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    # Parse input
    entries = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            ip, code, name = parse_entry(line)
            if ip:
                entries.append((ip, code, name))

    print(f"[SpeedTest] Loaded {len(entries)} entries from {input_file}")

    if not entries:
        print("No entries to test.")
        sys.exit(0)

    # Split into groups
    total_groups = (len(entries) + group_size - 1) // group_size
    print(f"[SpeedTest] Splitting into {total_groups} group(s) of max {group_size} each")

    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for group_num in range(1, total_groups + 1):
        start_idx = (group_num - 1) * group_size
        end_idx = min(start_idx + group_size, len(entries))
        group_entries = entries[start_idx:end_idx]

        # Run speed test for this group
        results = speed_test_group(group_entries, group_num, concurrency, timeout)
        all_results.extend(results)

        # Write group output file
        # Format: IP#国家代码_国家名称_延迟ms
        output_file = output_dir / f"allowed_ips_with_country_speed{group_num}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip, code, name, latency in results:
                f.write(f"{ip}#{code}_{name}_{latency}ms\n")

        print(f"Wrote {len(results)} sorted entries to {output_file}")

    # Summary
    print(f"\n[SpeedTest] All groups complete!")
    print(f"  Total entries: {len(entries)}")
    print(f"  Total groups: {total_groups}")
    print(f"  Total reachable: {len(all_results)}")
    if all_results:
        print(f"  Overall fastest: {min(r[3] for r in all_results)}ms")
        print(f"  Overall slowest: {max(r[3] for r in all_results)}ms")


if __name__ == '__main__':
    main()
