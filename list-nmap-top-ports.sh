#!/bin/bash
# https://github.com/jnqpblc/Randomness/blob/master/3.mapping/list-nmap-top-ports.sh

if [ -z $1 ]; then printf "\nSytnax: $0 <top-ports|e.g. 1000>\n\n"
	else
   NUM=$1;
   nmap -F -oG - 0.0.0.1 -v --top-ports $NUM 2>/dev/null | tr ';' '\n' | tr ')' '\n' | egrep '^[0-9]'
fi
