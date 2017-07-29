#!/usr/bin/env python2

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import json
import re

sys.path.append('/usr/share/vfeed-git/')
from config.constants import db
from lib.core.methods import CveExploit
from lib.core.methods import CveInfo
from lib.core.methods import CveRisk
from lib.core.methods import CveScanners
from lib.core.methods import CveRef
from lib.common.database import Database


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def search_product(name, version):
    name = name.lower()
    version = version.lower()
    if version:
        query = '%' + name + '%:' + version + '%'
    else:
        query = '%' + name + '%'
    search(query)


def search(query):
    (cur, q) = Database(query).db_init()

    cur.execute(
        "SELECT count(distinct cveid) from cve_cpe where cpeid like ?",
        (query,))
    count_cve = cur.fetchone()
    cur.execute(
        "SELECT count(distinct cpeid) from cve_cpe where cpeid like ?",
        (query,))
    count_cpe = cur.fetchone()

    if count_cve[0] == 0:
        error('No occurrences found with supplied information')
        exit()

    info('Total Unique CVEs        [%s] ' % count_cve)
    info('Total Found CPEs         [%s] ' % count_cpe)
    print()

    cur.execute(
        "SELECT distinct cpeid from cve_cpe where cpeid like ? ORDER BY cpeid DESC",
        (query,))
    cpe_datas = cur.fetchall()

    for i in range(0, count_cpe[0]):
        mycpe = cpe_datas[i][0]
        info('%s' % mycpe)
        cur.execute("SELECT cveid from cve_cpe where cpeid=?", (mycpe,))
        cve_datas = cur.fetchall()
        cves = dict()
        for cve_data in cve_datas:
            mycve = cve_data[0]
            cvss = json.loads(CveRisk(mycve).get_cvss())
            cves[mycve] = '[CVSS2:%s/AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s]' % \
                          (cvss[0]['base'],
                           cvss[0]['accessVector'].upper()[0],
                           cvss[0]['accessComplexity'].upper()[0],
                           cvss[0]['authentication'].upper()[0],
                           cvss[0]['confidentiality'].upper()[0],
                           cvss[0]['integrity'].upper()[0],
                           cvss[0]['availability'].upper()[0])
        for key, value in sorted(cves.iteritems(), key=lambda (k, v): (v, k),
                                 reverse=True):
            print('    -> %s %s' % (key, value))
            check_exploit(key)


def check_exploit(cve):
    msf = CveExploit(cve).get_msf()
    edb = CveExploit(cve).get_edb()
    if json.loads(msf) is not None:
        if len(json.loads(msf)) != 0:
            print('        -> Metasploit exploit found.')
            #print('            -> id: %s' % json.loads(msf)[0]['id'])
            pretty_print(json.loads(msf), 3)
    if json.loads(edb) is not None:
        if len(json.loads(edb)) != 0:
            print('        -> Exploit-DB PoC found.')
            #print('            -> url: %s' % json.loads(edb)[0]['url'])
            pretty_print(json.loads(edb), 3)


def search_cve(cve, references, cpe, scanners, exploits):
    #
    # Informational
    #
    basic = CveInfo(cve).get_cve()
    info("Basic information of", cve)
    pretty_print(json.loads(basic))
    # cvss = CveRisk(cve).get_cvss()
    # info("CVSS information related to", cve)
    # pretty_print(json.loads(cvss))
    severity = CveRisk(cve).get_severity()
    info("Risk information related to", cve)
    pretty_print(json.loads(severity))
    cwe = CveInfo(cve).get_cwe()
    info("CWE information related to", cve)
    pretty_print(json.loads(cwe))
    #capec = CveInfo(cve).get_capec()
    #info("CAPEC information related to", cve)
    #pretty_print(json.loads((capec)))
    #category = CveInfo(cve).get_category()
    #info("CATEGORY information related to", cve)
    #pretty_print(json.loads(category))

    if references:
        refs = CveRef(cve).get_refs()
        info("Reference information related to", cve)
        pretty_print(json.loads(refs))

    if cpe:
        cpe = CveInfo(cve).get_cpe()
        info("Total of CPEs found is:", len(json.loads(cpe)))
        info("CPE information related to", cve)
        pretty_print(json.loads(cpe))

    if scanners:
        #oval = CveScanners(cve).get_oval()
        #info("OVAL information related to", cve)
        #pretty_print(json.loads((oval))
        nmap = CveScanners(cve).get_nmap()
        info("Nmap information related to", cve)
        pretty_print(json.loads(nmap))
        nessus = CveScanners(cve).get_nessus()
        info("Nessus information related to", cve)
        info("Total Nessus:", len(json.loads(nessus)))
        pretty_print(json.loads(nessus))

    if exploits:
        metasploit = CveExploit(cve).get_msf()
        info("Metasploit information related to", cve)
        pretty_print(json.loads(metasploit))
        edb = CveExploit(cve).get_edb()
        info("Exploit-DB information related to", cve)
        pretty_print(json.loads(edb))


def pretty_print(obj, depth=0):
    if type(obj) == dict:
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                for i in range(depth):
                    print('    ', end="")
                print('-> %s' % k)
                pretty_print(v, depth + 1)
            else:
                for i in range(depth):
                    print('    ', end="")
                print('-> %s: %s' % (k, v))
        #print('')
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                pretty_print(v, depth + 1)
            else:
                for i in range(depth):
                    print('    ', end="")
                print(v)
    else:
        for i in range(depth):
            print('    ', end="")
        print(obj)


########
# MAIN #
########

cve_entry = re.compile("CVE-\d+-\d+", re.IGNORECASE)

if __name__ == '__main__':
    desc = 'Search CVE related information using the vFeed database.'

    parser = argparse.ArgumentParser(description=desc)
    subparsers = parser.add_subparsers(dest='command')

    cpe_p = subparsers.add_parser('cpe', help='search CPE identifers for a product')
    cpe_p.add_argument('-p', '--product',
                       action='store',
                       help='product name',
                       metavar='PRODUCT',
                       required=True)
    cpe_p.add_argument('-v', '--version',
                       action='store',
                       help='product version',
                       metavar='VERSION',
                       default='')

    cve_p = subparsers.add_parser('cve', help='show CVE information')
    cve_p.add_argument('-i', '--identifier',
                       action='store',
                       help='CVE identifier',
                       metavar='CVE',
                       required=True)
    cve_p.add_argument('-r', '--references',
                       action='store_true',
                       help='list references')
    cve_p.add_argument('-c', '--cpe',
                       action='store_true',
                       help='list CPEs')
    cve_p.add_argument('-s', '--scanners',
                       action='store_true',
                       help='list scanners that can detect this issue')
    cve_p.add_argument('-e', '--exploits',
                       action='store_true',
                       help='list available exploits')
    args = parser.parse_args()

    if args.command == 'cve':
        if re.findall(cve_entry, args.identifier):
            search_cve(args.identifier, args.references, args.cpe,
                       args.scanners, args.exploits)
        else:
            error('Invalid CVE identifier format!')
    elif args.command == 'cpe':
        search_product(args.product, args.version)
    else:
        parser.print_help()
