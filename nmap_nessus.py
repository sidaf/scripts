#!/usr/bin/env python2.7

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import time
import requests
import json
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


###########
# Objects #
###########

class SSLException(Exception):
    pass


class HttpException(Exception):
    pass


class Scanner(object):
    def __init__(self, url, username, password, verify=True):
        self.url = url
        self.username = username
        self.password = password
        self.verify = verify
        if not verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.token = ''


    def login(self):
        data = {'username': self.username, 'password': self.password}
        res = self.connect('POST', '/session', data, retry=False)
        self.token = res['token']


    def connect(self, method, resource, data=None, retry=True):
        headers = {'X-Cookie': 'token={0}'.format(self.token),
                   'content-type': 'application/json'}

        data = json.dumps(data)

        built_url = '{0}{1}'.format(self.url, resource)

        try:
            if method == 'POST':
                r = requests.post(built_url, data=data, headers=headers,
                                  verify=self.verify)
            elif method == 'PUT':
                r = requests.put(built_url, data=data, headers=headers,
                                 verify=self.verify)
            elif method == 'DELETE':
                r = requests.delete(built_url, data=data, headers=headers,
                                    verify=self.verify)
            else:
                r = requests.get(built_url, params=data, headers=headers,
                                 verify=self.verify)
        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('%s' % ssl_error)

        if r.status_code == 401 and retry:
            self.login()
            return self.connect(method, resource, data)
        elif r.status_code != 200:
            e = r.json()
            raise HttpException('%s for %s %s [%s]' %
                                (e['error'], method, built_url, r.status_code))

        # When downloading a scan we need the raw contents not the JSON data.
        if 'download' in resource:
            return r.content
        else:
            if r.text:
                return r.json()
            return {}


    def list_scans(self):
        res = self.connect('GET', '/scans')
        return res['scans']


    def get_scan(self, scan_id):
        res = self.connect('GET', '/scans/{0}'.format(scan_id))
        return res['info']


    def get_policy(self, policy_id):
        res = self.connect('GET', '/policies/{0}'.format(policy_id))
        return res


    def get_policy_template(self, name):
        res = self.connect('GET', '/editor/policy/templates')
        for template in res['templates']:
            if template['name'] == name:
                return template


    def get_scan_template(self, name):
        res = self.connect('GET', '/editor/scan/templates')
        for template in res['templates']:
            if template['name'] == name:
                return template


    def create_policy(self, name, custom_settings=None, template='advanced'):
        template = self.get_policy_template(template)
        settings = {"name": name,
                    "description": "Auto-generated",
                    "ping_the_remote_host": "no",
                    "unscanned_closed": "yes",
                    "portscan_range": "default",
                    "ssh_netstat_scanner": "no",
                    "wmi_netstat_scanner": "no",
                    "snmp_scanner": "no",
                    "only_portscan_if_enum_failed": "no",
                    "syn_scanner": "yes",
                    "syn_firewall_detection": "Automatic (normal)",
                    "svc_detection_on_all_ports": "yes",
                    "detect_ssl": "yes",
                    "ssl_prob_ports": "Known SSL ports",
                    "cert_expiry_warning_days": "60",
                    "enumerate_all_ciphers": "yes",
                    "check_crl": "no",
                    "scan_webapps": "yes",
                    "webcrawler_max_pages": "10",
                    "webcrawl_max_depth": "10",
                    "report_superseded_patches": "yes",
                    "silent_dependencies": "no",
                    "log_live_hosts": "yes",
                    "display_unreachable_hosts": "yes",
                    "safe_checks": "yes",
                    "reduce_connections_on_congestion": "yes",
                    "use_kernel_congestion_detection": "yes"}
        if custom_settings:
            settings.update(custom_settings)
        data = {"settings": settings, "uuid": template['uuid']}
        res = self.connect('POST', '/policies', data)
        return res['policy_id']


    def create_scan_from_policy(self, name, targets, policy_id,
                                custom_settings=None):
        policy = self.get_policy(policy_id)
        settings = {"name": name,
                    "enabled": "true",
                    "launch": "ON_DEMAND",
                    "description": "Auto-generated",
                    "policy_id": policy_id,
                    "text_targets": targets}
        if custom_settings:
            settings.update(custom_settings)
        data = {"uuid": policy['uuid'], "settings": settings}
        res = self.connect('POST', '/scans', data)
        return res['scan']['id']


    def create_scan(self, name, targets, ports='default', custom_settings=None,
                    template='advanced'):
        template = self.get_scan_template(template)
        settings = {"name": name,
                    "enabled": "true",
                    "launch": "ON_DEMAND",
                    "description": "Auto-generated",
                    "text_targets": targets,
                    "ping_the_remote_host": "no",
                    "unscanned_closed": "yes",
                    "portscan_range": ports,
                    "ssh_netstat_scanner": "no",
                    "wmi_netstat_scanner": "no",
                    "snmp_scanner": "no",
                    "only_portscan_if_enum_failed": "no",
                    "syn_scanner": "yes",
                    "syn_firewall_detection": "Automatic (normal)",
                    "svc_detection_on_all_ports": "yes",
                    "detect_ssl": "yes",
                    "ssl_prob_ports": "Known SSL ports",
                    "cert_expiry_warning_days": "60",
                    "enumerate_all_ciphers": "yes",
                    "check_crl": "no",
                    "scan_webapps": "yes",
                    "webcrawler_max_pages": "10",
                    "webcrawl_max_depth": "10",
                    "report_superseded_patches": "yes",
                    "silent_dependencies": "no",
                    "log_live_hosts": "yes",
                    "display_unreachable_hosts": "yes",
                    "safe_checks": "yes",
                    "reduce_connections_on_congestion": "yes",
                    "use_kernel_congestion_detection": "yes"}
        if custom_settings:
            settings.update(custom_settings)
        data = {"uuid": template['uuid'], "settings": settings}
        res = self.connect('POST', '/scans', data)
        return res['scan']['id']


    def start_scan(self, scan_id):
        res = self.connect('POST', '/scans/{0}/launch'.format(scan_id))
        return res['scan_uuid']


    def download_report(self, scan_id, filename):
        # export
        res = self.connect('POST', '/scans/{0}/export'.format(scan_id),
                           {"format": "nessus"})
        file_id = res['file']
        res = self.connect('GET',
                           '/scans/{0}/export/{1}/status'.format(scan_id,
                                                                 file_id))
        while not res['status'] == 'ready':
            time.sleep(5)
            res = self.connect('GET',
                               '/scans/{0}/export/{1}/status'.format(scan_id,
                                                                     file_id))
        # download
        report = self.connect('GET',
                              '/scans/{0}/export/{1}/download'.format(scan_id,
                                                                      file_id))
        # save
        with open(filename, 'w') as out_file:
            out_file.write(report)


    def delete_scan(self, scan_id):
        self.connect('DELETE', '/scans/{0}'.format(scan_id))


    def delete_policy(self, name):
        res = self.connect('GET', '/policies')
        for policy in res['policies']:
            if policy['name'] == name:
                self.connect('DELETE', '/policies/{0}'.format(policy['id']))
                break

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
