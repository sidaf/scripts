#!/usr/bin/env python3

###########
# IMPORTS #
###########

import sys
import csv
from typing import List
import argparse
from ipwhois import IPWhois
from tqdm import tqdm
from ipaddress import IPv4Address, IPv4Network
from tabulate import tabulate

#############
# FUNCTIONS #
#############

def iter_input_lines(handle):
    for line in handle:
        value = line.strip()
        if value and not value.startswith('#'):
            yield value


def clean_text(value):
    if value is None:
        return ''
    return str(value).replace('\n', ' ').strip()


def build_row(lookup, include_more, target):
    row = [
        lookup['asn'],
        lookup['registry'].upper(),
        lookup['country'],
        lookup['description'],
    ]
    if include_more:
        row.extend([
            lookup['net_description'],
            lookup['name'],
            lookup['handle'],
        ])
    row.extend([lookup['cidr'], target])
    return row


def build_headers(include_more, include_count):
    headers = ['asn', 'registry', 'country', 'description']
    if include_more:
        headers.extend(['net_description', 'net_name', 'net_handle'])
    headers.extend(['cidr', 'count' if include_count else 'address'])
    return headers


def whois(addresses: List[str]) -> List[dict]:
    results = {}
    for address in tqdm(addresses, leave=False):
        ip_network = None

        # Check results first
        ip_address = IPv4Address(address)
        for tmp_ip_network in results:
            if ip_address in tmp_ip_network:
                ip_network = tmp_ip_network
                break

        # No existing match, lookup whois
        if not ip_network:
            data = IPWhois(address).lookup_whois(inc_nir=True)

            # Cycle through the nets and find the most specific one that matches the IP address
            network = None
            for net in data['nets']:
                cidr = net.get('cidr')
                if cidr:
                    if ',' in cidr:
                        networks = cidr.split(',')
                        for n in networks:
                            tmp_ip_network = IPv4Network(n.strip())
                            if ip_address in tmp_ip_network:
                                ip_network = tmp_ip_network
                                network = net
                                break
                    else:
                        tmp_ip_network = IPv4Network(cidr)
                        if ip_address in tmp_ip_network:
                            ip_network = tmp_ip_network
                            network = net
                            break

            if not ip_network or not network:
                sys.stderr.write(f"{address} => No matching network found in WHOIS response.\n")
                sys.stderr.flush()
                continue

            results[ip_network] = {
                'registry': clean_text(data.get('asn_registry')),
                'asn': clean_text(data.get('asn')),
                'country': clean_text(data.get('asn_country_code')),
                'description': clean_text(data.get('asn_description')),
                'net_description': clean_text(network.get('description')),
                'name': clean_text(network.get('name')),
                'handle': clean_text(network.get('handle')),
                'cidr': str(ip_network),
                'addresses': [address]
            }
        else:
            results[ip_network]['addresses'].append(address)

    return list(results.values())

########
# MAIN #
########

if __name__ == '__main__':
    desc = (
        'Perform WHOIS lookups for IPv4 addresses and group the results by '
        'matched CIDR block.'
    )
    epilog = '''
Requirements:
  - Install the Python packages: ipwhois, tabulate, tqdm
  - Network access is required for WHOIS/RDAP lookups.

Input:
  - Read IPv4 addresses from FILE or STDIN, one entry per line.
  - Blank lines and lines starting with # are ignored.

Behavior:
  - When multiple input IPs fall inside the same discovered CIDR, the WHOIS
    result is queried once and the addresses are grouped together.
  - Default output is a table.
  - --csv prints CSV rows instead of a table.
  - --count replaces the final address column with the number of matching
    input addresses in that CIDR.
  - --more adds net_description, net_name, and net_handle columns from the
    matched network record.

Output columns:
  - Default: asn, registry, country, description, cidr, address
  - With --count: asn, registry, country, description, cidr, count
  - With --more: asn, registry, country, description, net_description,
    net_name, net_handle, cidr, address|count

Examples:
  whoislikeaboss.py ips.txt
  cat ips.txt | whoislikeaboss.py --csv
  whoislikeaboss.py --count ips.txt
  whoislikeaboss.py --csv --more ips.txt
'''

    parser = argparse.ArgumentParser(
        description=desc,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('file',
                        nargs='?',
                        type=argparse.FileType('r'),
                        action='store',
                        help='file containing IPv4 addresses split by newlines, otherwise read from STDIN',
                        metavar='FILE',
                        default=sys.stdin)
    parser.add_argument('--csv',
                        action='store_true',
                        help='output CSV rows instead of a table')
    parser.add_argument('--more',
                        action='store_true',
                        help='include net_description, net_name, and net_handle columns')
    parser.add_argument('--count',
                        action='store_true',
                        help='output the number of matching input addresses per CIDR instead of listing each address')
    args = parser.parse_args()

    try:
        addresses = [line for line in iter_input_lines(args.file)]
    except KeyboardInterrupt:
        exit()

    results = whois(addresses)
    headers = build_headers(args.more, args.count)

    if args.csv:
        writer = csv.writer(sys.stdout)
        for lookup in results:
            if not args.count:
                for address in lookup['addresses']:
                    writer.writerow(build_row(lookup, args.more, address))
            else:
                writer.writerow(build_row(lookup, args.more, len(lookup['addresses'])))
    else:
        table = []
        for lookup in results:
            if not args.count:
                for address in lookup['addresses']:
                    table.append(build_row(lookup, args.more, address))
            else:
                table.append(build_row(lookup, args.more, len(lookup['addresses'])))
        print(tabulate(table, headers, tablefmt="presto"))
