#!/usr/bin/env bash

# Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] This script must be run as root, quitting..."
  exit 1
fi

# Remove xfce and tools installed by Kali Light ISO
echo "[+] Enabling removal of Suggested packages during apt autoremove"
echo 'APT::AutoRemove::SuggestsImportant "false";' >> /etc/apt/apt.conf.d/99_autoremove_suggests

echo "[+] Removing and purging packages"
packages=(iceweasel nmap ncrack sqlmap aircrack-ng kali-desktop-xfce lightdm)
for i in $packages
do
  if (dpkg -l | grep -iq $i); then
    apt -y -qq remove --purge $i 1>&2
    echo -e "  - Removing ${i}"
  fi
done
  
echo "[+] Autoremove orphaned packages"
apt -y -qq autoremove --purge

echo "[+] Removing any previously removed packages that were not purged"
dpkg -l | grep "^rc" | awk '{print $2}' | xargs apt -y -qq remove --purge

echo "[!] Reboot, then run this script again to complete purge"