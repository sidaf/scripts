#!/usr/bin/env python3

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from netaddr import *

from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *

## FUNCTIONS

def is_ntlm(password):
    try:
        if len(password.split(':')) == 2:
            lm, ntlm = password.split(':')
            if len(lm) == 32 and len(ntlm) == 32:
                return True
            else:
                return False
    except Exception as e:
        return False

def list_shares(host, username, password, domain):
    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=4)
        if is_ntlm(password):
            lmhash, nthash = password.split(':')
            smb.login(username, '', domain=domain,lmhash=lmhash, nthash=nthash)
        else:
            smb.login(username, password, domain=domain)
    except Exception as e:
        sys.stderr.write('[!] Authentication error on %s, %s\n' % (host, e))
        return

    resp = smb.listShares()
    for i in range(len(resp)):
        sys.stdout.write("\\\\" + host + "\\" + resp[i]['shi1_netname'][:-1].strip() + "\n")
        sys.stdout.flush()

## MAIN

# parse the arguments
parser = argparse.ArgumentParser(description='List shares on target hosts')
parser.add_argument('-u','--user',help='SMB user to connect with', default='', required=False)
parser.add_argument('-p','--password',help='SMB password to connect with', default='', required=False)
parser.add_argument('-d','--domain',help='SMB domain to connect with', default='', required=False)
parser.add_argument('-t','--threads',help='Number of threads', default=5, required=False)
parser.add_argument('file',
                    nargs='?',
                    type=argparse.FileType('r'),
                    action='store',
                    help='File containing a list of IP addresses / ranges split by a newline, otherwise read from STDIN',
                    metavar='FILE',
                    default=sys.stdin)
args = parser.parse_args()

try:
    targets = [line.strip() for line in args.file if len(line.strip())>0 and line[0] is not '#']
except KeyboardInterrupt:
    exit()

#for target in targets:
#    list_shares(target, args.user, args.password, args.domain)

with PoolExecutor(args.threads) as pool:
    for target in targets:
        pool.submit(lambda p: list_shares(*p), [target, args.user, args.password, args.domain])
