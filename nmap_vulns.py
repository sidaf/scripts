#!/usr/bin/env python

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
from libnmap.parser import NmapParser
from tabulate import tabulate


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def get_vulns(files):
    data = list()
    for xml in files:
        parsed = NmapParser.parse_fromfile(xml)
        for host in parsed.hosts:
            if not host.is_up():
                continue
            for service in host.services:
                if service.state == "open":
                    what = service.service
                    if not what:
                        what = 'unknown'
                    if service.tunnel:
                        what = service.tunnel + "/" + what
                    for cpe in service.cpelist:
                        #if cpe.is_application():
                            data.append(
                                {'address': host.address,
                                 'hostname': " ".join(host.hostnames),
                                 'port': service.port,
                                 'protocol': service.protocol,
                                 'service': what,
                                 'product': cpe.get_product(),
                                 'version': cpe.get_version(),
                                 #'product': service.service_dict.get(
                                 #    'product', ""),
                                 #'version': service.service_dict.get(
                                 #    'version', ""),
                                 'cpe': cpe})
    return data


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

    for xml_file in args.files:
        if not os.path.isfile(xml_file):
            error("File '%s' does not exist!" % xml_file)
            exit()
        if not os.access(xml_file, os.R_OK):
            error("File '%s' is not readable!" % xml_file)
            exit()

    data = get_vulns(args.files)
    print(tabulate(data, headers="keys"))
