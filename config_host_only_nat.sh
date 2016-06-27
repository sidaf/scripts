
if (cat /etc/network/interfaces | grep -iq enp0s3); then
  cat <<EOF
[!] An existing entry has been found for interface 'enp0s3' within the /etc/network/interfaces file.
EOF
  echo ""
  read -N 1 -p "Update file regardless? [y/N] " update; echo
  if [[ "$update" =~ [Yy] ]]; then
    echo "[!] WARNING, there may now be duplicate entries within the /etc/network/interfaces file for interface 'enp0s3', please review and edit accordingly!"
  else
    echo "[!] Exiting..."
    exit 1
  fi
fi

# configure interface
echo "[+] Inserting entry for interface 'enp0s3' into /etc/network/interfaces"
cat <<EOT >> /etc/network/interfaces

auto enp0s3
iface enp0s3 inet static
    address 192.168.56.254
    netmask 255.255.255.0
EOT

echo "[+] Enabling IP Forwarding"
# configure system to allow ip forwarding
sudo cat > /etc/sysctl.d/ip_forward.conf << EOF
  net.ipv4.ip_forward=1
EOF
sysctl -w net.ipv4.ip_forward=1

echo "[+] Creating iptables NAT and FORWARD entries"
# create iptables rules to NAT traffic originating from clients
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 ! -d 192.168.56.0/24 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.168.56.0/24 ! -d 192.168.56.0/24 -j MASQUERADE
sudo iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable
sudo iptables-save > /etc/iptables.up.rules
sudo cat > /etc/network/if-pre-up.d/iptables << EOF
#!/bin/sh
     /sbin/iptables-restore < /etc/iptables.up.rules
EOF
sudo chmod +x /etc/network/if-pre-up.d/iptables

