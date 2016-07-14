#!/usr/bin/env bash

# Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] This script must be run as root, quitting..."
  exit 1
fi

# Check to see if a virtual machine
if [[ $(dmidecode | grep -i virtual) -ne 0 ]]; then
  echo "[!] This system is not a virtual machine, quitting..."
  exit 1
fi

# install appropiate tools
if [[ $(dmidecode | grep -iq vmware) ]]; then
  echo "[+] Installing VMware virtual machine tools"
  apt -y -qq install open-vm-tools-desktop fuse
elif (dmidecode | grep -iq virtualbox); then
  echo "[+] Installing VirtualBox guest additions"
  apt -y -qq install virtualbox-guest-x11
fi

# check if there is a second network card
ip addr show eth1 &>/dev/null
if [[ "$?" == 0 ]]; then
  echo "[+] Second interface found, configuring for IP Forwarding and NAT
  echo "[+] Setting static configuration for eth1"
  cat > /etc/network/interfaces.d/eth1 << "EOF"
auto eth1
iface eth1 inet manual
    address 192.168.56.254
    netmask 255.255.255.0
EOF

  echo "[+] Enabling IP Forwarding"
  cat > /etc/sysctl.d/ip_forward.conf << EOF
net.ipv4.ip_forward=1
EOF
  sysctl -w net.ipv4.ip_forward=1
  
  echo "[+] Creating iptables NAT and FORWARD entries"
  iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A FORWARD -s 192.168.56.0/24 ! -d 192.168.56.0/24 -j ACCEPT
  iptables -t nat -A POSTROUTING -s 192.168.56.0/24 ! -d 192.168.56.0/24 -j MASQUERADE
  iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable
  iptables-save > /etc/iptables.up.rules
  cat > /etc/network/if-pre-up.d/iptables << EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.up.rules
EOF
  chmod +x /etc/network/if-pre-up.d/iptables
fi