#!/usr/bin/env python2.7

###########
# IMPORTS #
###########

from __future__ import print_function
import sys
import argparse
import os
import ConfigParser
from netaddr import *
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from time import sleep
import shlex
import subprocess


#############
# FUNCTIONS #
#############

def error(*objects):
    print("[!]", *objects, file=sys.stderr)


def info(*objects):
    print("[+]", *objects, file=sys.stdout)


def config_section_map(config, section):
    dict1 = {}
    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
            #if dict1[option] == -1:
                #DebugPrint("skip: %s" % option)
        except:
            #error("exception on %s!" % option)
            dict1[option] = None
    return dict1


def list_scans(config_file):
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    for section in config.sections():
        info('%s' % section)
        print('    -> %s' % config_section_map(config, section)['desc'])
        #print('    -> arguments: %s' % config_section_map(config, section)['args'])
        #print()


def perform_scan(config_file, section, targets, output_dir):
    # merge targets to create the smallest possible list of CIDR subnets
    subnets = list()
    for target in targets:
        subnets.append(IPNetwork(target))
    subnets = cidr_merge(subnets)
    targets = list()
    for subnet in subnets:
        targets.append(str(subnet))

    # check if required args declaration is supplied
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    args = config_section_map(config, section)['args']
    if not args:
        error('No \'args\' declaration found in %s' % section)
        exit()

    # check for options that will interfere with this script
    illegal_options = ['-oG', '-oN', '-iL', '-oA', '-oS', '-oX', '--iflist',
                       '--resume', '--stylesheet', '--datadir', '--stats-every']
    for option in illegal_options:
        if option in args:
            error('\'args\' declaration contains incompatible option \'%s\'' %
                  (section, option))
            exit()

    # store raw nmap output as well
    raw_file = '%s/%s.nmap' % (output_dir, section)
    args += ' -oN %s' % raw_file

    # perform scan
    info('Starting scan \'%s\'' % section)
    print('    -> %s' % config_section_map(config, section)['desc'])
    nmap_proc = NmapProcess(targets=targets, options=args, safe_mode=False)
    nmap_proc.sudo_run_background()
    while nmap_proc.is_running():
        nmap_task = nmap_proc.current_task
        if nmap_task:
            m, s = divmod(int(nmap_task.remaining), 60)
            h, m = divmod(m, 60)
            remaining = "%d:%02d:%02d" % (h, m, s)
            sys.stdout.write(
                '[+] Task: {0} - ETC: {1} DONE: {2}%'
                '              \r'.format(
                    nmap_task.name,
                    remaining,
                    nmap_task.progress))
            sys.stdout.flush()
        sleep(1)

    # save results
    if nmap_proc.rc == 0:
        info('%s' % nmap_proc.summary.replace('Nmap done at',
                                              'Scan completed on'))
        run('chown %s:%s %s' % (os.getuid(), os.getgid(), raw_file), sudo=True)
        print("    -> Nmap report saved to '%s'" % raw_file)
        if nmap_proc.stdout:
            xml_file = '%s/%s.xml' % (output_dir, section)
            out = open(xml_file, 'w')
            out.write(nmap_proc.stdout)
            out.close()
            print("    -> XML report saved to '%s'" % xml_file)
        #if nmap_proc.stderr:
        #    err_file = '%s/%s.err' % (output_dir, section)
        #    out = open(err_file, 'w')
        #    out.write(nmap_proc.stderr)
        #    out.close()
        #    print("    -> Standard error output saved to '%s'" %
        #          err_file)
    else:
        error('Error occurred:')
        print('    -> %s' % nmap_proc.stderr.rstrip())


def run(command, sudo=False, run_as='root'):
    if sudo:
        sudo_user = run_as.split().pop()
        command = 'sudo -u %s %s' % (sudo_user, command)
    try:
        cmdline = shlex.split(command)
        proc = subprocess.Popen(args=cmdline,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                bufsize=0)
    except OSError:
        raise EnvironmentError(1, '%s is not installed or could '
                                  'not be found in system path' % command)

    stdout = ''
    while proc.poll() is None:
        for streamline in iter(proc.stdout.readline, ''):
            stdout += streamline
    stderr = proc.stderr.read()
    rc = proc.poll()
    return rc, stdout, stderr


########
# MAIN #
########

if __name__ == '__main__':
    desc = 'Run predefined nmap scans.'
    config = os.path.dirname(os.path.realpath(__file__)) + '/nmap_auto.ini'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-c', '--config',
                        action='store',
                        help='location of config file (default: %s)' % config,
                        metavar='FILE',
                        default=config)
    parser.add_argument('-l', '--list',
                        action='store_true',
                        help='list predefined scans and exit')
    target_p = parser.add_argument_group('target source arguments')
    target_p.add_argument('-f', '--files',
                          action='store',
                          nargs='+',
                          help='nmap xml file(s) to parse for targets',
                          metavar='XML')
    target_p.add_argument('-t', '--targets',
                          action='store',
                          help='file containing newline separated list of '
                               'targets',
                          metavar='FILE')
    required_p = parser.add_argument_group('required arguments')
    required_p.add_argument('-s', '--scans',
                            action='store',
                            nargs='+',
                            help='scan(s) to execute',
                            metavar='NAME')
    required_p.add_argument('-o', '--output',
                            action='store',
                            help='directory to output results',
                            metavar='PATH')
    nmapxml_p = parser.add_argument_group('nmap xml file parse arguments')
    nmapxml_p.add_argument('-u', '--up',
                           action='store_true',
                           help='only scan hosts that have status of \'up\'')
    nmapxml_p.add_argument('-p', '--ports',
                           action='store_true',
                           help='only scan hosts that have open ports, '
                                'regardless of status')
    args = parser.parse_args()

    # check if config exists
    if not os.path.isfile(args.config):
        error("Config file '%s' does not exist!" % args.config)
        exit()
    if not os.access(args.config, os.R_OK):
        error("Config file '%s' is not readable!" % args.config)
        exit()

    # if --list is called, list scans
    if args.list:
        list_scans(args.config)
        exit()

    # check if scan name has been supplied
    if not args.scans:
        error("At leaste one scan name is needed!")
        parser.print_help()
        exit()

    # check if scan exists
    config = ConfigParser.ConfigParser()
    config.read(args.config)
    for scan in args.scans:
        if scan not in config.sections():
            error("Scan '%s' does not exist in config!" % scan)
            exit()

    # check if output directory exists
    if not os.path.exists(args.output):
        error("Output directory '%s' does not exist!" % args.output)
        exit()
    if not os.access(args.output, os.W_OK):
        error("Output directory '%s' is not writable!" % args.output)
        exit()

    # now we need targets, either from file or xml
    targets = set()
    if args.targets:
        if not os.path.isfile(args.targets):
            error("Targets file '%s' does not exist!" % args.targets)
            exit()
        if not os.access(args.targets, os.R_OK):
            error("Targets file '%s' is not readable!" % args.targets)
            exit()
        with open(args.targets) as f:
            targets = [line.rstrip('\n') for line in f]
    elif args.files:
        for xml in args.files:
            parsed = NmapParser.parse_fromfile(xml)
            for host in parsed.hosts:
                if args.up and args.ports:
                    if host.is_up() and len(host.get_open_ports()) > 0:
                        targets.add(host.address)
                elif args.up:
                    if host.is_up():
                        targets.add(host.address)
                elif args.ports:
                    if len(host.get_open_ports()) > 0:
                        targets.add(host.address)
                else:
                    targets.add(host.address)
    else:
        error("Targets needed!")
        parser.print_help()
        exit()

    if len(targets) > 0:
        for scan in args.scans:
            perform_scan(args.config, scan, sorted(targets), args.output)
    else:
        error("No targets found!")
