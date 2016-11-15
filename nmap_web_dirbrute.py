#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import urllib2
import httplib
import random
import string
from subprocess import check_output, CalledProcessError
import modules.nmap as nmap
from tqdm import tqdm

import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


#############
# FUNCTIONS #
#############

def header(*objects):
    print("\033[01;01m[*]\033[00m", *objects, file=sys.stdout)


def error(*objects):
    print("\033[01;31m ✖ \033[00m", *objects, file=sys.stderr)


def success(*objects):
    print("\033[01;32m ✔ \033[00m", *objects, file=sys.stdout)


def info(*objects):
    print("\033[01;34m ➜ \033[00m", *objects, file=sys.stdout)


def random_alpha(size=7):
    return ''.join([random.choice(string.ascii_letters) for n in xrange(size)])


def random_alpha_numeric(size=7):
    return ''.join([random.choice(string.ascii_letters +
                                  string.digits) for n in xrange(size)])


def detect_404(url):
    try:
        response = urllib2.urlopen("{0}/{1}".format(url, random_alpha()))
        length1 = response.headers['content-length']
    except urllib2.HTTPError:
        return -1
    except KeyError:
        return None

    try:
        response = urllib2.urlopen("{0}/{1}".format(url, random_alpha()))
        length2 = response.headers['content-length']
    except urllib2.HTTPError:
        return -1

    if length1 == length2:
        return length1
    else:
        return None


def brute_dir(urls, wordlist):
    for url in urls:
        header("Attempting to discover resources on {0}".format(url))
        detected = detect_404(url)
        if not detected:
            error("Could not detect valid 404, skipping {0}".format(url))
            continue
        #for word in tqdm(wordlist):
        for word in wordlist:
            uri = "{0}/{1}".format(url, word)
            try:
                response = urllib2.urlopen(uri)
                if response:
                    if detected == -1 or response.headers['content-length'] != detected:
                        if 'content-length' in response.headers:
                            success("{0} [Code: {1} | Length: {2}]".format(uri, response.getcode(),
                                                                           response.headers['content-length']))
                        else:
                            success("{0} [Code: {1} | Length: unknown]".format(uri, response.getcode()))
            except urllib2.HTTPError, e:
                if e.code == 401:
                    info("{0} [Code {1}]".format(uri, e.code))
            except httplib.BadStatusLine:
                error("Bad status line received from {0}".format(uri))


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Parse nmap xml output and attempt to brute force directories on ' \
           'all web servers.'

    parser = argparse.ArgumentParser(description=desc)
    required = parser.add_argument_group('required arguments')
    required.add_argument('-w', '--wordlist',
                          action='store',
                          help='wordlist file',
                          metavar='WORDLIST',
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

    if not os.path.isfile(args.wordlist):
        error("File '%s' does not exist!" % args.wordlist)
        exit()
    if not os.access(args.wordlist, os.R_OK):
        error("File '%s' is not readable!" % args.wordlist)
        exit()

    web_servers = nmap.parse_web_servers(args.files)
    # TODO: Do vhost lookup on all IP addresses and then add to list

    with open(args.wordlist, 'r') as file_in:
        words = filter(None, (line.rstrip() for line in file_in))
    brute_dir(web_servers, words)
