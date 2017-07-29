#!/usr/bin/env python2

import sys
import SimpleHTTPServer
import SocketServer

if len(sys.argv) == 2:
    port = int(sys.argv[1])
else:
    port = 8000

httpd = SocketServer.TCPServer(("", port), SimpleHTTPServer.SimpleHTTPRequestHandler)
print "[+] serving over port " + str(port)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print ""
    sys.exit()
