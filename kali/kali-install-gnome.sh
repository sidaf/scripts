#!/usr/bin/env bash

# Check if we are running as root  - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] This script must be run as root, quitting..."
  exit 1
fi

if ! (dpkg -l | grep -iq kali-desktop-gnome); then
  echo "Installing GNOME desktop environment"
  apt -y -qq install kali-desktop-gnome
else
  echo "[!] GNOME appears to be installed, skipping installation"
fi

# Configure GNOME desktop
if [[ $(which gnome-shell) ]]; then
  echo "[+] Configuring GNOME desktop environment"

  echo "  - Disable screensaver"
  xset s 0 0
  xset s off
  gsettings set org.gnome.desktop.session idle-delay 0
  gsettings set org.gnome.desktop.screensaver lock-enabled false
  gsettings set org.gnome.desktop.screensaver idle-activation-enabled false

  echo "  - Show date in top bar"
  gsettings set org.gnome.desktop.interface clock-show-date true

  echo "  - Set font face and size"
  gsettings set org.gnome.desktop.interface document-font-name 'Sans 10'
  gsettings set org.gnome.desktop.interface font-name 'Cantarell 10'
  gsettings set org.gnome.desktop.interface monospace-font-name 'Monospace 10.5'
  gsettings set org.gnome.desktop.wm.preferences titlebar-font 'Cantarell Bold 10'

  echo "  - Set font antialiasing and hinting"
  gsettings set org.gnome.settings-daemon.plugins.xsettings antialiasing 'grayscale'
  gsettings set org.gnome.settings-daemon.plugins.xsettings rgba-order 'rgb'
  gsettings set org.gnome.settings-daemon.plugins.xsettings hinting 'slight'

  echo "  - Hide notifications in lock screen"
  gsettings set org.gnome.desktop.notifications show-in-lock-screen false

  echo "  - Disable 'Usage & History'"
  gsettings set org.gnome.desktop.privacy remember-recent-files false

  echo "  - Disable NetworkManager Notifications"
  gsettings set org.gnome.nm-applet disable-connected-notifications true
  #gsettings set org.gnome.nm-applet disable-disconnected-notifications true

  #echo "  - Set dock to use the full height"
  #gsettings set org.gnome.shell.extensions.dash-to-dock extend-height true
  #echo "  - Set dock to be always visible"
  #gsettings set org.gnome.shell.extensions.dash-to-dock dock-fixed true
  echo "  - Place dock to the bottom of the screen"
  gsettings set org.gnome.shell.extensions.dash-to-dock dock-position 'BOTTOM'
  
  echo "  - Change keyboard layout to GB"
  gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'gb')]"
  
  # Gnome extensions
  echo "  - Enable 'Alternate-tab' extension"
  gnome-shell-extension-tool -e alternate-tab@gnome-shell-extensions.gcampax.github.com
  echo "  - Disable 'Applications menu' extension"
  gnome-shell-extension-tool -d apps-menu@gnome-shell-extensions.gcampax.github.com
  echo "  - Disable 'Places status indicator' extension"
  gnome-shell-extension-tool -d places-menu@gnome-shell-extensions.gcampax.github.com
  echo "  - Disable 'Workspace Indicator' extension"
  gnome-shell-extension-tool -d workspace-indicator@gnome-shell-extensions.gcampax.github.com
  echo "  - Disable 'Easy Screen Cast' extension"
  gnome-shell-extension-tool -d EasyScreenCast@iacopodeenosee.gmail.com
  
  echo "  - Configure GNOME terminal"
  gsettings set org.gnome.Terminal.Legacy.Settings default-show-menubar false
  #gconftool-2 -t bool -s /apps/gnome-terminal/profiles/Default/login_shell true
  
  echo "  - Configure Files"
  gsettings set org.gnome.nautilus.icon-view default-zoom-level 'standard'
  gsettings set org.gnome.nautilus.desktop volumes-visible false
  gsettings set org.gnome.nautilus.icon-view captions "['size', 'None', 'None']"
  
  if [[ $(dmidecode | grep -i virtual) ]]; then
    echo "[+] System is a virtual machine, enabling GDM auto login 
    file=/etc/gdm3/daemon.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
    sed -i 's/^.*AutomaticLoginEnable = .*/AutomaticLoginEnable = true/' "${file}"
    sed -i 's/^.*AutomaticLogin = .*/AutomaticLogin = root/' "${file}"
  fi
else
  echo "[!] GNOME does not appear to be installed, skipping configuration"
fi