#!/usr/bin/env python2.7

import argparse
import sys


def missing_numbers(num_list, start, end):
    original_list = [x for x in range(start, end + 1)]
    num_list = set(num_list)
    return (list(num_list ^ set(original_list)))

########
# MAIN #
########

if __name__ == '__main__':
    desc = 'List missing ports from a list'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-s', '--start',
                        type=int,
                        action='store',
                        help='Starting number (default: 0)',
                        metavar='N',
                        default=0)
    parser.add_argument('-e', '--end',
                        type=int,
                        action='store',
                        help='Last number (default: 65535)',
                        metavar='N',
                        default=65535)
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
    print '\n'.join(str(p) for p in missing_numbers(ports, args.start, args.end))
