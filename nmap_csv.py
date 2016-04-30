#!/usr/bin/env python

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
from libnmap.parser import NmapParser


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def get_first(iterable, default=''):
    if iterable:
        for item in iterable:
            return item
    return default


def parse_to_csv(files):
    #try:
        lines = set()
        lookup = dict()
        for xml in files:
            parsed = NmapParser.parse_fromfile(xml)
            for host in parsed.hosts:
                hostname = get_first(host.hostnames)
                if hostname and not host.address in lookup:
                    lookup[host.address] = hostname
                elif not hostname and host.address in lookup:
                    hostname = lookup[host.address]
                for service in host.services:
                    display = service.service
                    if not display:
                        display = 'unknown'
                    if service.tunnel:
                        display = service.tunnel + "/" + display
                    if service.state == "open":
                        lines.add('%s,%s,%s,%s,%s,"%s",%s,"%s"' %
                                  (host.address,
                                   hostname,
                                   service.port,
                                   service.protocol,
                                   display,
                                   service.service_dict.get('product', ""),
                                   service.service_dict.get('version', ""),
                                   service.service_dict.get('extrainfo', "")))
        return sorted(lines)
    #except Exception as e:
    #    error("Error parsing xml file! %s" % e)
    #    exit()


def print_csv(files):
    lines = parse_to_csv(files)
    print("IP ADDRESS,HOSTNAME,PORT,PROTOCOL,SERVICE,PRODUCT,VERSION,INFO")
    for line in lines:
        print(line)


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and print out a CSV of all discovered ' \
           'hosts and their open ports.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('files',
                        action='store',
                        nargs='+',
                        help='nmap xml file(s) to parse',
                        metavar='INPUT')
    args = parser.parse_args()

    for xml in args.files:
        if not os.path.isfile(xml):
            error("File '%s' does not exist!" % xml)
            exit()
        if not os.access(xml, os.R_OK):
            error("File '%s' is not readable!" % xml)
            exit()

    print_csv(args.files)
