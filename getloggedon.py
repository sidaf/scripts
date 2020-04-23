#!/usr/bin/env python
#
# Orginal script downloaded from https://gist.github.com/dirkjanm/acbd85799b23fc7662f9826ace7bd917
#
# Copyright (c) 2012-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Gets logged on users via NetrWkstaUserEnum (requires admin on targets).
# Mostly adapted from netview.py and lookupsid.py
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#

import sys
import logging
import argparse
import codecs

from impacket.examples.logger import ImpacketFormatter
from impacket import version
from impacket.dcerpc.v5 import transport, wkst


class GetLoggedOn(object):
    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None, show_computer=False):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__show_computer = show_computer
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remote_host, csv=False):

        logging.info('Enumerating users logged in at %s', remote_host)

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remote_host
        # logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remote_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        try:
            self.lookup(rpctransport, remote_host, csv)
        except Exception, e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            raise

    def lookup(self, rpctransport, host, csv):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)

        try:
            resp = wkst.hNetrWkstaUserEnum(dce,1)
        except Exception, e:
            if str(e).find('Broken pipe') >= 0:
                # The connection timed-out. Let's try to bring it back next round
                logging.error('Connection failed - skipping host!')
                return
            elif str(e).upper().find('ACCESS_DENIED'):
                # We're not admin, bye
                logging.error('Access denied - you must be admin to enumerate sessions this way')
                dce.disconnect()
                return
            else:
                raise
        try:
            users = set()
            # Easy way to uniq them
            for i in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                if i['wkui1_username'][-2] == '$' and not self.__show_computer:
                    continue
                users.add((host, i['wkui1_logon_domain'][:-1], i['wkui1_username'][:-1]))
            for user in list(users):
                if csv:
                    print u'%s,%s,%s' % user
                else:
                    print u'%s\\%s' % (user[1], user[2])
        except IndexError:
            logging.info('No sessions found!')
        # resp.dump()

        dce.disconnect()

        return None


# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    logging.info(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-file',
                       action='store',
                       metavar="file",
                       help='Use the targets in the specified file instead of the one on'\
                            ' the command line (you must still specify something as target name)')
    group.add_argument('-csv', action='store_true', help='Output in host,domain,user format')
    group.add_argument('-show-computer', action='store_true', help='Also show computer accounts')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through smbrelayx)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    remote_names = []
    if options.target_file is not None:
        with open(options.target_file, 'r') as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = GetLoggedOn(username, password, domain, int(options.port), options.hashes, options.show_computer)
    for remote_name in remote_names:

        try:
            lookup.dump(remote_name, options.csv)
        except KeyboardInterrupt:
            break
        except:
            pass

if __name__ == '__main__':
    main()
