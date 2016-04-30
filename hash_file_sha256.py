#!/usr/bin/env python

import sys
import hashlib
import ftplib

path = sys.argv[1]
encrypted_report = open(path,"rb")
hash = hashlib.sha256(encrypted_report.read()).hexdigest()
encrypted_report.close()

print hash

#ftp = ftplib.FTP('XX.XX.XX.XX.XX',timeout=10)
#ftp.login("encriptionreports","6SMrmS6SF5hD")
#ftp.mkd(hash)
#ftp.cwd(hash)
#ftp.storbinary("STOR report.exe",encrypted_report,callback=updateFTP)
##ftp.close()
