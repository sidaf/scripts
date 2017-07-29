#!/usr/bin/env python2

#
# whoislikeaboss.py
#
# Modified version of script downloaded from:
#   - https://labs.portcullis.co.uk/tools/whois-like-a-boss/
#
# Takes files with one IP per line and does a whois, so you can see if 
# something looks fishy.
#

import sys, os, subprocess, re

## Puts IPs into an array
try:
	inputfile = sys.argv[1]
except:
	print "You need to give me a file of IPs"
	sys.exit(1)
openfile = open(inputfile, "r")
ips = []	
for line in openfile.read().split('\n'):
	ips.append(line.rstrip())
del ips[-1]


## whois the IPs, and parse results into an array
responses=[]
for ip in ips:
	p = subprocess.Popen(['whois', ''.join(ip)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	response = p.communicate()[0]
	if "ARIN WHOIS" in response:
		rtype = "ARIN"
		nrange = "NetRange:"
		owner = "OrgName:"
	elif "RIPE Database" in response:
		rtype = "RIPE"
		nrange = "inetnum:"
		owner = "address:"
	elif "APNIC" in response:
		rtype = "APNIC"
		nrange = "inetnum:"
		owner = "descr:"
	else:
		print "It looks like the whois response for "+ip+" can't currently be parsed. Why not do something about this so it'll work in future?"
		continue
	
	frange=""
	fowner=""
	
	for line in response.split("\n"):
			if nrange in line and not frange:
				spline = line.split(":")
				frange = str(spline[1].strip())
				
				
			if owner in line and not fowner:
				spline = line.split(":")
				fowner = fowner+str(spline[1].strip())
	
	e=""
	for r in responses:
		if r[0] == frange:
			r.append(ip)
			e="true"
			break
	if not e:
		responses.append( [frange, fowner, ip] )
		
			
		

##Print the responses
for r in responses:
	print r[0]+"		"+r[1]

