#!/usr/bin/env python2.7

import argparse
import sys
import re
from cStringIO import StringIO

def group_consec(nums):
    # Assumes a non-empty, sorted list
    sio = StringIO()
    prev = nums[0]
    for i, n in enumerate(nums):
        if i > 0 and n - nums[i-1] > 1:
            sio.write("%d" % prev)
            if nums[i-1] != prev:
                sio.write("-%d" % nums[i-1])
            sio.write(",")
            prev = n
    if prev != n:
        sio.write("%d-" % prev)
    sio.write("%d" % n)
    return sio.getvalue()


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Group consecutive ports to a nmap suitabel format.'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('file',
                        nargs='?',
                        type=argparse.FileType('r'),
                        action='store',
                        help='file containing a list of ports split by a newline, otherwise read from STDIN',
                        metavar='FILE',
                        default=sys.stdin)
    args = parser.parse_args()

    try:
        ports = [int(line.strip()) for line in args.file if len(line.strip())>0 and line[0] is not '#']
    except KeyboardInterrupt:
        exit()

    ports.sort()
    print group_consec(ports)
