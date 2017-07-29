#!/usr/bin/env python2

'''
# based off: http://cmikavac.net/2011/07/09/merging-multiple-nessus-scans-python-script/
# plus additional work by mastahyeti
'''

###########
# IMPORTS #
###########

from __future__ import print_function
try:
    import xml.etree.cElementTree as etree
except ImportError:
    import xml.etree.ElementTree as etree
import os
import sys
import argparse
from tqdm import tqdm


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def merge(files, output, title):
    merged = None
    report = None
    first = True
    for fileName in tqdm(files, desc='[+] Processing', leave=True):
        try:
            root = etree.parse(fileName)
        except:
            raise Exception("Wrong XML structure: cannot parse data")

        #if not root.tag == 'NessusClientData_v2':
        #    raise Exception("Unexpected data structure for XML root node")

        if first:
            merged = root
            report = merged.find('Report')
            report.attrib['name'] = title
            first = False
            continue

        for host in root.findall('.//ReportHost'):
            existing_host = report.find(
                ".//ReportHost[@name='{0}']".format(host.attrib['name']))
            if not existing_host:
                report.append(host)
            else:
                for item in host.findall('ReportItem'):
                    if not existing_host.find(
                            "ReportItem[@port='{0}'][@pluginID='{1}']".format(
                                item.attrib['port'], item.attrib['pluginID'])):
                        existing_host.append(item)

    merged.write(output, encoding="utf-8", xml_declaration=True)
    print("")


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse Nessus reports and merge findings into a single report.'

    parser = argparse.ArgumentParser(description=desc)
    required = parser.add_argument_group('required arguments')
    required.add_argument('-o', '--output',
                          action='store',
                          help='filename of merged report',
                          metavar='FILE',
                          required=True)
    parser.add_argument('files',
                        action='store',
                        nargs='+',
                        help='nessus report file(s) to parse',
                        metavar='INPUT')
    parser.add_argument('-t', '--title',
                        action='store',
                        help='report title (default: Merged Report)',
                        metavar='TITLE',
                        default='Merged Report')
    args = parser.parse_args()

    for xml in args.files:
        if not os.path.isfile(xml):
            error("File '%s' does not exist!" % xml)
            exit()
        if not os.access(xml, os.R_OK):
            error("File '%s' is not readable!" % xml)
            exit()

    if os.path.isfile(args.output):
        error("Output file '{0}' already exists, please remove before "
              "continuing!".format(args.output))
        exit()

    merge(args.files, args.output, args.title)
