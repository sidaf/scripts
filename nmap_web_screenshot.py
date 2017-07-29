#!/usr/bin/env python2

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
from subprocess import check_output
import modules.nmap as nmap
from tqdm import tqdm


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def take_screenshot(urls, path):
    binary = 'CutyCapt'
    for url in tqdm(urls):
        filename = "{0}.png".format(
            url.replace('//', '_').replace('/', '_').replace(':', ''))
        check_output(["{0}".format(binary), "--insecure", "--max-wait=15000",
                      "--out-format=png", "--url={0}".format(url),
                      "--out={0}/{1}".format(path, filename)])


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and take a screenshot of all web servers.'

    parser = argparse.ArgumentParser(description=desc)
    required = parser.add_argument_group('required arguments')
    required.add_argument('-o', '--output',
                          action='store',
                          help='directory to output results',
                          metavar='PATH',
                          required=True)
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

    if not os.path.exists(args.output):
        error("Directory '%s' does not exist!" % args.output)
        exit()
    if not os.access(args.output, os.W_OK):
        error("Directory '%s' is not writable!" % args.output)
        exit()

    web_servers = nmap.parse_web_servers(args.files)
    take_screenshot(web_servers, args.output)
