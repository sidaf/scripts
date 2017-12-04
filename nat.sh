#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!"
   exit 1
fi

echo "[+] Enabling IP Forwarding"
sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "[+] Creating iptables NAT and FORWARD entries"
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable
