#!/usr/bin/env python3

import sys
import requests
import base64
import argparse

parser = argparse.ArgumentParser(description='Mark Bloodhound owned from list.')
parser.add_argument('-c', '--creds',
                    action='store',
                    help='Credentials for Neo4j (Default: neo4j:toor)',
                    metavar='CREDS',
                    default='neo4j:toor')
parser.add_argument('-s', '--server',
                    action='store',
                    help='Server for Neo4j (Default: localhost:7474)',
                    metavar='SERVER',
                    default='localhost:7474')
parser.add_argument('--computers',
                    action='store_true',
                    help='Treat input as computer accounts rather than user accounts')
parser.add_argument('file',
                    nargs='?',
                    type=argparse.FileType('r'),
                    action='store',
                    help='File containing a list of users/computers split by a newline, otherwise read from STDIN',
                    metavar='FILE',
                    default=sys.stdin)

args = parser.parse_args()

auth = base64.b64encode(args.creds.encode())

#Run Cypher query in Neo4j
def runcypher(server,statement,auth):
    headers = { "Accept": "application/json; charset=UTF-8",
                "Content-Type": "application/json",
                "Authorization": auth }
    data = {"statements": [{'statement': statement}]}
    url = 'http://{}/db/data/transaction/commit'.format(server)
    r = requests.post(url=url,headers=headers,json=data)
    r.raise_for_status()

try:
    owned = [line.strip() for line in args.file if len(line.strip())>0 and line[0] is not '#']
except KeyboardInterrupt:
    exit()

if (args.computers):
    for o in owned:
        statement = "MATCH (n) WHERE n.name =~ '(?i)^{}\\\\..*$' SET n.owned=true RETURN n".format(o)
        runcypher(args.server,statement,auth)
        print('marked computer: {} owned'.format(o))
else:
    for o in owned:
        statement = "MATCH (n) WHERE n.name =~ '(?i)^{}$' SET n.owned=true RETURN n".format(o)
        runcypher(args.server,statement,auth)
        print('marked user: {} owned'.format(o))

