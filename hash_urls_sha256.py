#!/usr/bin/env python2

import os, sys, urllib2
from hashlib import sha256

urls = [line.rstrip('\n') for line in open(str(sys.argv[1]))]

for url in urls:
    print 'url "{}"'.format(url)
    f = urllib2.urlopen(url)
    checksum = sha256(f.read()).hexdigest()
    print 'sha256 "{}"'.format(checksum)
    print
