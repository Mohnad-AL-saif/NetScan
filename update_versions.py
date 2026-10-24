#!/usr/bin/env python3
"""
Fetch latest versions from endoflife.date and save locally.
Run manually or via cron: 0 3 * * 0 python3 /path/to/update_versions.py
"""

import requests
import json
import os
from datetime import datetime

API_BASE = 'https://endoflife.date/api'
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'findings', 'latest_versions.json')


def get_all_products():
    try:
        resp = requests.get(f'{API_BASE}/all.json', timeout=15)
        if resp.status_code == 200:
            products = resp.json()
            if isinstance(products, list) and len(products) > 0:
                print(f'   Found {len(products)} products on endoflife.date')
                return products
    except Exception as e:
        print(f'   Could not fetch product list: {e}')

    print('   Using fallback product list')
    return [
        'mariadb', 'mysql', 'postgresql', 'mongodb', 'redis',
        'elasticsearch', 'nginx', 'apache', 'tomcat', 'openssh',
        'openssl', 'nodejs', 'php', 'python', 'rabbitmq',
        'docker-engine', 'kubernetes', 'grafana', 'jenkins', 'gitlab',
    ]


def _is_past(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d') < datetime.now()
    except ValueError:
        return False


def fetch_product(product):
    try:
        resp = requests.get(f'{API_BASE}/{product}.json', timeout=10)
        if resp.status_code != 200:
            return None

        cycles = resp.json()
        if not cycles or not isinstance(cycles, list):
            return None

        latest_cycle = cycles[0]

        supported = None
        for c in cycles:
            eol = c.get('eol')
            is_eol = False
            if isinstance(eol, bool):
                is_eol = eol
            elif isinstance(eol, str):
                try:
                    is_eol = datetime.strptime(eol, '%Y-%m-%d') < datetime.now()
                except ValueError:
                    pass
            if not is_eol:
                supported = c
                break

        if not supported:
            supported = latest_cycle

        return {
            'latest': latest_cycle.get('latest', latest_cycle.get('cycle', '')),
            'latest_cycle': latest_cycle.get('cycle', ''),
            'supported': supported.get('latest', supported.get('cycle', '')),
            'supported_cycle': supported.get('cycle', ''),
            'eol_cycles': [
                c.get('cycle', '') for c in cycles
                if (isinstance(c.get('eol'), bool) and c['eol'])
                or (isinstance(c.get('eol'), str) and _is_past(c['eol']))
            ][:10],
            'all_cycles': [c.get('cycle', '') for c in cycles[:15]],
        }
    except Exception as e:
        print(f'  x {product}: {e}')
        return None


def main():
    print('Fetching latest versions from endoflife.date ...')

    products = get_all_products()
    print(f'   Products to fetch: {len(products)}')
    print()

    data = {}
    success = 0
    failed = 0

    for product in products:
        info = fetch_product(product)
        if info:
            data[product] = info
            print(f'  + {product}: {info["latest"]} (supported: {info["supported"]})')
            success += 1
        else:
            print(f'  x {product}: failed or not found')
            failed += 1

    output = {
        'updated_at': datetime.now().isoformat(),
        'source': 'endoflife.date',
        'product_count': len(data),
        'products': data
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)

    print()
    print(f'Done! {success} products updated, {failed} failed')
    print(f'Saved to: {OUTPUT_FILE}')


if __name__ == '__main__':
    main()
