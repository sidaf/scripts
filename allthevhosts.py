#!/usr/bin/env python2

#
# A quick little webscraper to identify all the webapps associated with an IP address.
#
# Modified version of script downloaded from https://labs.portcullis.co.uk/tools/finding-all-the-vhosts/
#
# Usage allthevhosts.py <ip or URL> <outputfile (optional)>
#

import urllib2
import sys
import re
import json
import socket
import ssl
from HTMLParser import HTMLParser
from bs4 import BeautifulSoup

ca_certs="/etc/ssl/certs/ca-certificates.crt"

try:
	ip=sys.argv[1]
except:
	print "[E] I need an address!"
	sys.exit(1)

## URLs that searches claim to be on the same IP
matches=[]

## URLs which resolve to the same IP as the original
vhosts=[]

def bing():
	print "[-] searching bing..."
	try:
		search = urllib2.urlopen("http://www.bing.com/search?q=IP%3A" + ip + "&go=&qs=n&form=QBRE").read()
	except:
		print "\r[E] bing search error!"
	
	soup = BeautifulSoup(search)
	for url in soup.find_all('cite'):
		try:
			tld=re.sub('\/.*','',url.string)
			if tld not in matches:
				matches.append(tld)
		except:
			pass
	print "\r[+] bing search complete"

def myipneighbours():
	print "[-] searching myipneighbours..."
	try:
		search = urllib2.urlopen("http://www.my-ip-neighbors.com/?domain=" + ip).read()
		soup = BeautifulSoup(search)
		for url in soup.find_all('td'):
			try:
				if url.attrs and str(url.attrs['class']) == "['domain']" and url.string not in matches:
					matches.append(url.string)
			except:
				pass
		print "\r[+] myipneighbours search complete"
	except:
		print "\r[E] myipneighbours search error!"

		
def ipneighbour():
	try:
		print "[-] Searching ipneighbour..."
		search = urllib2.urlopen("http://www.ipneighbour.com/", "domainName=" + ip + "&submit=").read()
		
		soup = BeautifulSoup(search)
		for url in soup.find_all('a'):
			try:
				if url.attrs and str(url.attrs['target']) == '_blank' and url.attrs['href'].replace('http://','') not in matches:
					matches.append(url.attrs['href'].replace('http://',''))
			except:
				pass
		print "\r[+] ipneighbour search complete"	
	except:
		print "\r[E] ipneighbour search error!"

def yougetsignal():
	print "[-] searching yougetsignal..."
	req = urllib2.Request(url='http://www.yougetsignal.com/tools/web-sites-on-web-server/php/get-web-sites-on-web-server-json-data.php', data='remoteAddress=' + ip + '&key=')
	req.add_header('Referer', 'http://www.yougetsignal.com/tools/web-sites-on-web-server/')
	req.add_header('User-Agent', 'firefox')
	search = urllib2.urlopen(req)
	results = json.load(search)
	try:
		for url in results['domainArray']:
			if url[0] not in matches:
				matches.append(url[0])
		print "\r[+] yougetsignal search complete"
	except:
		print "\r[E] yougetsignal search error - probably just hit the limit for this IP"
		

def san():
	print "[-] checking for Subject Alternate Names (SAN) within SSL/TLS certificate..."
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
		ssl_sock = ssl.wrap_socket(s, ca_certs=ca_certs, cert_reqs=ssl.CERT_REQUIRED)
		ssl_sock.connect((ip, 443))
		CERT = ssl_sock.getpeercert()
		ssl_sock.close()
		
		for type,url in CERT['subjectAltName']:
			if url not in matches: 
				matches.append(url)
		print "\r[+] SAN enumeration complete."
	except:
		print "\r[E] looks like there's no SSL/TLS on port 443, or port is closed"

		
def verifyresults():
	print "[-] resolving original address..."
	try:
		socket.inet_aton(ip)
		realip = ip
	except socket.error:
		realip = socket.gethostbyname(ip)
	print "\r[+] resolved original address"
	num = str(len(matches))
	print "[+] verifying that " + num + " found URLs resolve to the same address"
	i = 1
	if hasattr(socket, 'setdefaulttimeout'):
		socket.setdefaulttimeout(5)
	for url in matches:
		try:
			testip = socket.gethostbyname(url)
			i = i + 1
			if realip == testip:
				vhosts.append(url)
		except:
			i = i + 1
	print "\r[+] " + str(len(vhosts)) + " out of " + str(len(matches)) + " URLs resolved correctly\n"
	
def fileoutput():
	try:
		outfile = sys.argv[2]
		f = open(outfile,'w')
		for url in vhosts:
			#f.write(url + "\n")
			f.write(ip + "," + url + "\n")
		f.close()
	except:
		for url in vhosts:
			print ip + "," + url
	

bing()
myipneighbours()
#ipneighbour()
#yougetsignal()
san()
verifyresults()
fileoutput()
