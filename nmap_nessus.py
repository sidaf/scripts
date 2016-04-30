#!/usr/bin/env python

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import time
import modules.nmap as nmap
import modules.nessus as nessus
from tqdm import tqdm


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def check_scans(scanner, scans, path):
    data = scanner.list_scans()
    for scan in data:
        if (scan['status'] == 'completed' or scan['status'] == 'aborted' or
                    scan['status'] == 'canceled') and scan['id'] in scans:
            scanner.download_report(scan['id'],
                                    '{0}/{1}.nessus'.format(path,
                                                            scan['name']))
            scanner.delete_scan(scan['id'])
            scans.remove(scan['id'])


def scan_hosts(url, username, password, files,
               max_concurrent_scans, path, verify=True):
    scanner = nessus.Scanner(url, username, password, verify)
    info("Connecting to nessus server at {0} ...".format(url))
    scanner.login()
    info("Parsing nmap xml file(s) ...")
    hosts = nmap.parse_hosts(files, True)
    scans = list()
    info("Starting scans ...")
    for host in tqdm(hosts, leave=True):
        ports = set()
        found = nmap.parse_ports_for_address(files, host)
        for port in found:
            ports.add(port.split('/', 1)[0])

        while len(scans) >= max_concurrent_scans:
            check_scans(scanner, scans, path)
            if len(scans) < max_concurrent_scans:
                break
            time.sleep(20)

        scan_id = scanner.create_scan(host, host, ','.join(sorted(ports)))
        scanner.start_scan(scan_id)
        scans.append(scan_id)

    print("\n[+] Waiting for scans to finish ...")
    last = 0
    while len(scans) > 0:
        check_scans(scanner, scans, path)
        if len(scans) == 0:
            break
        if len(scans) != last:
            print("[+] {0} scan(s) left ...".format(len(scans)))
            last = len(scans)
        time.sleep(20)
    print("[+] Finished.")


def list_running_scans(scanner):
    data = scanner.list_scans()
    for scan in data:
        if scan['status'] == 'running':
            print('{0}'.format(scan['name']))


def cancel_all_scans(scanner):
    pass


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and launch nessus scans on discovered ' \
           'hosts. Only the open ports discovered by nmap are (re)scanned, ' \
           'which should make the nessus scans a bit more economical. One ' \
           'scan is performed per host.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-s', '--server',
                        action='store',
                        help='nessus server (default: https://127.0.0.1:8834)',
                        metavar='URL',
                        default='https://127.0.0.1:8834')
    parser.add_argument('-u', '--username',
                        action='store',
                        help='nessus username (default: nmap_nessus)',
                        metavar='USERNAME',
                        default='nmap_nessus')
    parser.add_argument('-p', '--password',
                        action='store',
                        help='nessus password (default: nmap_nessus)',
                        metavar='PASSWORD',
                        default='nmap_nessus')
    parser.add_argument('-c', '--concurrent',
                        action='store',
                        help='max concurrent nessus scans (default: 10)',
                        metavar='NUMBER',
                        default=10,
                        type=int)
    parser.add_argument('-i', '--insecure',
                        action='store_true',
                        help='do not verify remote nessus server certificate')
    parser.add_argument('files',
                        action='store',
                        nargs='+',
                        help='nmap xml file(s) to parse',
                        metavar='INPUT')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-o', '--output',
                          action='store',
                          help='directory to output results',
                          metavar='PATH',
                          required=True)
    args = parser.parse_args()

    for xml in args.files:
        if not os.path.isfile(xml):
            error("File '%s' does not exist!" % xml)
            exit()
        if not os.access(xml, os.R_OK):
            error("File '%s' is not readable!" % xml)
            exit()

    if not os.path.exists(args.output):
        error("Directory '%s' does not exist!" % args.output)
        exit()
    if not os.access(args.output, os.W_OK):
        error("Directory '%s' is not writable!" % args.output)
        exit()

    try:
        scan_hosts(args.server, args.username, args.password, args.files,
                   args.concurrent, args.output, (not args.insecure))
    except nessus.SSLException as ssl_ex:
        error("%s" % ssl_ex)
        error("You can use --insecure to disable SSL certificate verification, "
              "but use this with caution!")
        exit(1)
    except nessus.HttpException as http_ex:
        error("%s" % http_ex)
        exit(1)
