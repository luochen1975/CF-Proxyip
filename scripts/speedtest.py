#!/usr/bin/env python3
"""
Speed test script for CF-Proxyip.
Tests the first N IPs from allowed_ips_with_country.txt via TCP connection to port 443.
Generates sorted output by latency.

Usage: python speedtest.py [input_file] [output_file] [max_count] [concurrency] [timeout]
"""
import sys
import socket
import time
import concurrent.futures
from pathlib import Path

DEFAULT_INPUT = Path('ips_with_country/allowed_ips_with_country.txt')
DEFAULT_OUTPUT = Path('ips_with_country/allowed_ips_with_country_speed.txt')
DEFAULT_MAX_COUNT = 500
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
        latency = (time.perf_counter() - start) * 1000  # ms
        sock.close()
        return round(latency, 2)
    except Exception:
        return None


def speed_test(entries: list, max_count: int, concurrency: int, timeout: float):
    """Run speed test on entries. Returns list of (ip, country_code, country_name, latency_ms)."""
    # Take first max_count entries
    test_entries = entries[:max_count]
    total = len(test_entries)

    print(f"\n[SpeedTest] Testing {total} IPs (port 443, timeout {timeout}s, concurrency {concurrency})...")

    results = []
    success_count = 0
    fail_count = 0

    def test_one(args):
        idx, ip, code, name = args
        latency = test_latency(ip, port=443, timeout=timeout)
        return idx, ip, code, name, latency

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(test_one, (i, e[0], e[1], e[2])): i 
                   for i, e in enumerate(test_entries)}

        for future in concurrent.futures.as_completed(futures):
            idx, ip, code, name, latency = future.result()
            if latency is not None:
                results.append((ip, code, name, latency))
                success_count += 1
                status = f"{latency}ms"
            else:
                fail_count += 1
                status = "TIMEOUT/FAIL"

            progress = success_count + fail_count
            if progress % 10 == 0 or progress == total:
                print(f"  Progress: {progress}/{total} | Success: {success_count} | Failed: {fail_count}")

    # Sort by latency (ascending)
    results.sort(key=lambda x: x[3])

    print(f"\n[SpeedTest] Complete: {success_count} reachable, {fail_count} failed")
    print(f"  Fastest: {results[0][3]}ms" if results else "  No reachable IPs")
    print(f"  Slowest: {results[-1][3]}ms" if results else "")

    return results


def main():
    input_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT
    max_count = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_MAX_COUNT
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

    # Run speed test
    results = speed_test(entries, max_count, concurrency, timeout)

    # Write output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for ip, code, name, latency in results:
            f.write(f"{ip}#{code}#{name}#{latency}ms\n")

    print(f"\nWrote {len(results)} sorted entries to {output_file}")


if __name__ == '__main__':
    main()
