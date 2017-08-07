#!/bin/bash

DIR='/usr/share/nmap/scripts/'
SCRIPTS=$(grep portrule $DIR*.nse|grep '"udp"'|cut -d':' -f1|tr '/' '\n'|grep '\.nse'| sed ':a;N;$!ba;s/\n/,/g; s/,$//g; s/\.nse//g;');
PORTS=$(grep portrule $DIR*.nse|grep '"udp"'|sed 's/[^0-9a-zA-Z]/\n/g'|egrep -o '^[0-9]{1,5}'|sort -uR|sed ':a;N;$!ba;s/\n/,/g; s/,$//g;');

echo "SCRIPTS: $SCRIPTS"
echo "PORTS: $PORTS"
