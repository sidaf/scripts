#!/usr/bin/env python
#
# Orginal script downloaded from https://gist.github.com/UrfinJusse/031a708e68f661f1ba000eda6cfab2bd
#
# Title: lookupadmins.py
# Author: @ropnop
# Description: Python script using Impacket to query members of the builtin Administrators group through SAMR
# Similar in function to Get-NetLocalGroup from Powerview
# Won't work against Windows 10 Anniversary Edition unless you already have local admin
# See: http://www.securityweek.com/microsoft-experts-launch-anti-recon-tool-windows-10-server-2016
#
# Heavily based on original Impacket example scripts written by @agsolino and available here: https://github.com/CoreSecurity/impacket

import sys
import logging
import argparse
import codecs

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, lsat, lsad, samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb import SMB_DIALECT

class SAMRQuery:
    def __init__(self, username='', password='', domain='', port=445, remoteName='', remoteHost=''):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__port = port
        self.__remoteName = remoteName
        self.__remoteHost = remoteHost
        self.dce = self.getDce()
        self.serverHandle = self.getServerHandle()

    def getTransport(self):
        stringbinding = 'ncacn_np:%s[\pipe\samr\]' % self.__remoteName
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(rpctransport,'preferred_dialect'):
            rpctransport.preferred_dialect(SMB_DIALECT)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(False, None)

        return rpctransport

    def getDce(self):
        rpctransport = self.getTransport()
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    def getServerHandle(self):
        resp = samr.hSamrConnect(self.dce)
        return resp['ServerHandle']

    def getDomains(self):
        resp = samr.hSamrEnumerateDomainsInSamServer(self.dce, self.serverHandle)
        domains = resp['Buffer']['Buffer']
        domainNames = []
        for domain in domains:
            domainNames.append(domain['Name'])
        return domainNames

    def getDomainHandle(self, domainName):
        resp = samr.hSamrLookupDomainInSamServer(self.dce, self.serverHandle, domainName)
        resp = samr.hSamrOpenDomain(self.dce, serverHandle = self.serverHandle, domainId = resp['DomainId'])
        return resp['DomainHandle']

    def getDomainAliases(self, domainHandle):
        resp = samr.hSamrEnumerateAliasesInDomain(self.dce, domainHandle)
        aliases = {}
        for alias in resp['Buffer']['Buffer']:
            aliases[alias['Name']] =  alias['RelativeId']
        return aliases

    def getAliasHandle(self, domainHandle, aliasId):
        resp = samr.hSamrOpenAlias(self.dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=aliasId)
        return resp['AliasHandle']

    def getAliasMembers(self, domainHandle, aliasId):
        aliasHandle = self.getAliasHandle(domainHandle, aliasId)
        resp = samr.hSamrGetMembersInAlias(self.dce, aliasHandle)
        memberSids = []
        for member in resp['Members']['Sids']:
            memberSids.append(member['SidPointer'].formatCanonical())
        return memberSids


class LSAQuery:

    def __init__(self, username='', password='', domain='', port=445, remoteName='', remoteHost=''):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__port = port
        self.__remoteName = remoteName
        self.__remoteHost = remoteHost
        self.dce = self.getDCE()
        self.policyHandle = self.getPolicyHandle()

    def getTransport(self):
        stringbinding = 'ncacn_np:%s[\pipe\lsarpc]' % self.__remoteName
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(self.__remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(False, None)
        return rpctransport

    def getDCE(self):
        rpctransport = self.getTransport()
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        return dce

    def getPolicyHandle(self):
        resp = lsad.hLsarOpenPolicy2(self.dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        return resp['PolicyHandle']

    def lookupSids(self, sids):
        try:
            resp = lsat.hLsarLookupSids(self.dce, self.policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
                if str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise
        names = []
        for translatedNames in resp['TranslatedNames']['Names']:
            names.append(translatedNames['Name'])
        return names


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('authentication')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]
        
    
    if domain is None:
        domain = ''

    if password == '' and username != '' and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    print "[+] Connecting to {}".format(remoteName)
    SAMRObject = SAMRQuery(username=username, password=password, remoteName=remoteName, remoteHost=remoteName)
    domains = SAMRObject.getDomains()
    print "[+] Found domains: "
    for domain in domains:
        print "\t{}".format(domain)
    if "Builtin" in domains:
        print "[+] Using 'Builtin'"
    else:
        print "[!] Didn't find 'Builtin' domain. Will not work. Aborting"
        sys.exit(1)
    domainHandle = SAMRObject.getDomainHandle('Builtin')
    domainAliases = SAMRObject.getDomainAliases(domainHandle)
    if 'Administrators' in domainAliases:
        print "[+] Found Local Administrators Group: RID {}".format(domainAliases['Administrators'])
    print "[+] Querying group members"

    memberSids = SAMRObject.getAliasMembers(domainHandle, domainAliases['Administrators'])
    print "[+] Found {} members: ".format(len(memberSids))

    LSAObject = LSAQuery(username=username, password=password, remoteName=remoteName, remoteHost=remoteName)
    memberNames = LSAObject.lookupSids(memberSids)
    for name in memberNames:
        print "\t{}".format(name)

    print "\n[+] Good luck!"
    sys.exit(1)