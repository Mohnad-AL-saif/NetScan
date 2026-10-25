#!/usr/bin/env python3

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

# ----------------------------
# Arguments
# ----------------------------
def get_arguments():
    parser = argparse.ArgumentParser(
        description="Fast Squid Proxy Port Scanner (Pivot Scanner)"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP behind the proxy"
    )
    parser.add_argument(
        "--proxy",
        required=True,
        help="Proxy address (ip:port)"
    )
    parser.add_argument(
        "--creds",
        help="Proxy credentials (username:password)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=300,
        help="Number of threads (default: 300)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Request timeout (default: 0.5)"
    )

    return parser.parse_args()

# ----------------------------
# Proxy Setup
# ----------------------------
def build_proxy(proxy, creds=None):
    if creds:
        proxy_url = f"http://{creds}@{proxy}"
    else:
        proxy_url = f"http://{proxy}"

    return {
        "http": proxy_url,
        "https": proxy_url
    }

# ----------------------------
# Scanner
# ----------------------------
def scan_port(port):
    url = f"http://{TARGET}:{port}"
    try:
        r = session.head(
            url,
            timeout=TIMEOUT,
            allow_redirects=False
        )

        squid_err = r.headers.get("X-Squid-Error", "")

        if not squid_err:
            print(f"[+] Possible open port: {port}")

    except:
        pass

# ----------------------------
# Main
# ----------------------------
args = get_arguments()

TARGET  = args.target
TIMEOUT = args.timeout
THREADS = args.threads

session = requests.Session()
session.proxies.update(build_proxy(args.proxy, args.creds))
session.verify = False

print(f"[*] Fast Squid scan on {TARGET}")
print(f"[*] Proxy   : {args.proxy}")
print(f"[*] Threads : {THREADS}")
print(f"[*] Timeout : {TIMEOUT}\n")

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    executor.map(scan_port, range(1, 65536))

print("\n[*] Scan finished.")
