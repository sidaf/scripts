#!/usr/bin/env python2.7

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import modules.nmap as nmap


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)

def scan_hosts(files):
    info("Parsing nmap xml file(s) ...")
    hosts = nmap.parse_hosts(files, True)
    info("Starting scans ...")
    for host in tqdm(hosts, leave=True):
        ports = set()
        found = nmap.parse_ports_for_address(files, host)
        for port in found:
            ports.add(port.split('/', 1)[0])
        print("sudo nmap -v -Pn -sS -sV --version-intensity 9 -O --script=default --traceroute -T4 -p T:%s --initial-rtt-timeout=200ms --min-rtt-timeout=100ms --max-rtt-timeout=$maxrtt --defeat-rst-ratelimit --open --stats-every 15s -oA tcp_%s %s" % (ports, host, host))


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and rescan previosuly identified ' \
           'hosts and any open ports.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-o', '--output',
                        action='store',
                        help='directory to output results',
                        metavar='PATH')
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

    if args.output:
        if os.path.exists(args.output):
            error("Directory '%s' already exists!" % args.output)
            exit()

        os.mkdir(args.output)
        dump_data(args.files, args.output)
    else:
        print_report(args.files)
