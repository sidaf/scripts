#!/usr/bin/env python

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import re
from libnmap.parser import NmapParser


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def get_first(iterable, default=None):
    if iterable:
        for item in iterable:
            return item
    return default


def get_cpe_applications(iterable):
    applications = set()
    if iterable:
        for cpe in iterable:
            if cpe.is_application():
                applications.add(cpe.cpestring)
    return sorted(applications)


def get_vulns(files):
    #try:
        lines = set()
        for xml in files:
            parsed = NmapParser.parse_fromfile(xml)
            for host in parsed.hosts:
                for service in host.services:
                    display = service.service
                    if not display:
                        display = 'unknown'
                    if service.tunnel:
                        display = service.tunnel + "/" + display
                    if service.state == "open":
                        cpe = " ".join(get_cpe_applications(service.cpelist))
                        lines.add('%s,%s,%s,%s,%s,%s' %
                                  (host.address,
                                   get_first(host.hostnames, ''),
                                   service.port,
                                   service.protocol,
                                   display,
                                   cpe))
        return sorted(lines)
    #except Exception as e:
    #    error("Error parsing xml file! %s" % e)
    #    exit()


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

    vulns = get_vulns(args.files)
    for vuln in vulns:
        print(vuln)
