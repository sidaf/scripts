#!/usr/bin/env python3

###########
# IMPORTS #
###########

import sys
from typing import List
import argparse
from ipwhois import IPWhois
from tqdm import tqdm
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from tabulate import tabulate

#############
# FUNCTIONS #
#############

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
            print(data)

            cidr = data['nets'][-1]['cidr']
            if ',' in cidr:
                networks = cidr.split(',')
                for net in networks:
                    tmp_ip_network = IPv4Network(net.strip())
                    if ip_address in tmp_ip_network:
                        ip_network = tmp_ip_network
                        break
                if not ip_network:
                    sys.stderr.write(f"{address} => hmm, no network object found!\n")
                    sys.stderr.flush()
            else:
                ip_network = IPv4Network(data['nets'][-1]['cidr'])

            results[ip_network] = { 
                'registry': data['asn_registry'],
                'country': data['asn_country_code'],
                'owner': data['nets'][-1]['description'],
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
    desc = 'Perform a whois lookup on provided IP address(es) and return network range memebrship and owner information.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('file',
                        nargs='?',
                        type=argparse.FileType('r'),
                        action='store',
                        help='file containing a list of IP addresses split by a newline, otherwise read from STDIN',
                        metavar='FILE',
                        default=sys.stdin)
    parser.add_argument('--csv',
                        action='store_true',
                        help='output in CSV format')
    parser.add_argument('--count',
                        action='store_true',
                        help='output total count instead of a list of addresses')
    '''
    parser.add_argument('-g', '--geolite',
                        action='store',
                        help='path to MaxMind\'s GeoLite2 Country database file',
                        metavar='DB',
                        default=None)
    '''
    args = parser.parse_args()

    '''
    if args.geolite:
        import geoip2.database
        reader = geoip2.database.Reader(args.geolite)
    '''

    try:
        addresses = [line.strip() for line in args.file if len(line.strip())>0 and line[0] != '#']
    except KeyboardInterrupt:
        exit()

    results = whois(addresses)

    if args.csv:
        for lookup in results:
            registry = lookup['registry'].upper()
            country = lookup['country']
            owner = lookup['owner']
            cidr = lookup['cidr']
            if not args.count:
                for address in lookup['addresses']:
                    print(f"{registry},{country},{owner},{cidr},{address}")
            else:
                targets = len(lookup['addresses'])
                print(f"{registry},{country},{owner},{cidr},{targets}")
    else:
        table = []
        for lookup in results:
            registry = lookup['registry'].upper()
            country = lookup['country']
            owner = lookup['owner']
            cidr = lookup['cidr']
            if not args.count:
                for address in lookup['addresses']:
                    table.append([registry, country, owner, cidr, address])
            else:
                targets = len(lookup['addresses'])
                table.append([registry, country, owner, cidr, targets])

        headers = ["registry", "country", "owner", "cidr", "targets"]
        print(tabulate(table, headers, tablefmt="presto"))
