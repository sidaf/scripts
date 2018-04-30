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


def print_report(files):
    print('##############')
    print('# LIVE HOSTS #')
    print('##############')
    print('')
    hosts = nmap.parse_hosts(files, True)
    for host in hosts:
        print(host)

    print('')
    print('###################')
    print('# UNIQUE SERVICES #')
    print('###################')
    print('')
    services = nmap.parse_unique_services(files)
    for service in services:
        print(service)

    print('')
    print('############')
    print('# SERVICES #')
    print('############')
    print('')
    for service in services:
        print("== %s ==" % service)
        found = nmap.parse_service(files, service)
        for host in found:
            print(host)
        print('')


def dump_data(files, path):
    hosts_path = path + "/hosts"
    os.mkdir(hosts_path)
    services_path = path + "/services"
    os.mkdir(services_path)

    hosts = nmap.parse_hosts(files, True)
    with open(path + "/hosts.txt", 'w') as f:
        for host in hosts:
            f.write(host + '\n')

    for host in hosts:
        with open(hosts_path + "/" + host + ".txt", 'w') as f:
            found = nmap.parse_ports_for_address(files, host)
            for port in found:
                f.write(port + '\n')

    services = nmap.parse_unique_services(files)
    with open(path + "/services.txt", 'w') as f:
        for service in services:
            f.write(service + '\n')

    for service in services:
        with open(services_path + "/" + service.replace('/', '_') + ".txt",
                  'w') as f:
            found = nmap.parse_service(files, service)
            for host in found:
                f.write(host + '\n')


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and extract host and service information ' \
           'and print to screen. Alternatively, output results into files.'

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
