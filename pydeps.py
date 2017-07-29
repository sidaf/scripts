#!/usr/bin/env python2

import os, sys, json, urllib2
from hashlib import sha256

deps = [line.rstrip('\n') for line in open(str(sys.argv[1]))]

for dep in deps:
    version = None
    if "==" in dep:
        columns = dep.split("==")
        dep = columns[0]
        version = columns[1]
    elif "<=" in dep:
        columns = dep.split("<=")
        dep = columns[0]
        version = columns[1]
    elif ">=" in dep:
        columns = dep.split(">=")
        dep = columns[0]
    f = urllib2.urlopen("http://pypi.python.org/pypi/{}/json".format(dep))
    j = json.load(f)
    f.close()
    print '  resource "{}" do'.format(dep)
    if version:
        for i in j['releases']:
            if i == version:
                for k in j['releases'][i]:
                    if k['packagetype'] == 'sdist':
                        url = k['url']
                        print '    url "{}"'.format(url)
                        f = urllib2.urlopen(url)
                        checksum = sha256(f.read()).hexdigest()
                        print '    sha256 "{}"'.format(checksum)
                        break
                break
    else:
        for i in j['urls']:
            if i['packagetype'] == 'sdist':
                url = i['url']
                print '    url "{}"'.format(url)
                f = urllib2.urlopen(url)
                checksum = sha256(f.read()).hexdigest()
                print '    sha256 "{}"'.format(checksum)
                break
    print '  end'
    print

print "===\n"
print '    ENV.prepend_create_path "PYTHONPATH", libexec/"vendor/lib/python2.7/site-packages"'
print '    %w[' + ' '.join(deps) + '].each do |r|'
print '      resource(r).stage do'
print '        system "python", *Language::Python.setup_install_args(libexec/"vendor")'
print '      end'
print '    end'
