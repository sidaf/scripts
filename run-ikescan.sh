#!/bin/bash
# https://github.com/jnqpblc/Randomness/blob/master/3.mapping/run-ikescan.sh

if [ -z $1 ];then
  printf "\nSyntax: ./$0 <ip|1.1.1.1> <Option|-i or -a or -t>\n\n"
else
  IP=$1
  OPTION=$2

  if [ $OPTION == '-i' ];then
	  echo "# ike-scan -M $IP"
	  sudo ike-scan -M $IP | tee ikescan-$IP-main-mode.txt
  elif [ $OPTION == '-a' ];then
	  echo "# ike-scan -M -A --id=GroupVPN $IP"
	  sudo ike-scan -M -A --id=GroupVPN $IP | tee ikescan-$IP-aggressive-mode.txt
  elif [ $OPTION == '-t' ];then
	  echo "# generate-transforms.sh | xargs --max-lines=8 sudo ike-scan $IP | grep Handshake"
	  bash generate-transforms.sh | xargs --max-lines=8 sudo ike-scan $IP | grep Handshake | tee ikescan-$IP-generate-transforms.txt
  else
	  echo 'Dammit Bobby.'
  fi
fi
