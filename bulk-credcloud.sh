#!/usr/bin/env bash

if [[ $# -gt 1 || "$*" == "--help" || "$*" == "-h" ]]; then
  echo "Usage: bulk-credcloud.sh [domains.txt]"
  exit 1
fi

if [[ "$OSTYPE" =~ ^darwin ]]; then
  CREDCLOUD="$HOME/Downloads/Tools/Credcloud/credcloud-darwin"
else
  CREDCLOUD="$HOME/Downloads/Tools/Credcloud/credcloud"
fi

DOMAINS=$1

if [[ $# -lt 1 ]]; then
  DOMAINS='../domains/domains.txt'
fi


BLUE="\e[34m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33"
BOLD="\e[1m"
NORMAL="\e[0m"

for DOMAIN in $(cat ${DOMAINS}); do
  echo -ne "${BLUE}[>]${NORMAL} ${BOLD}${DOMAIN}${NORMAL} ... "
  mkdir -p ${DOMAIN}
  ${CREDCLOUD} -o ${DOMAIN}/output.csv ${DOMAIN} > /dev/null
  cat ${DOMAIN}/output.csv | cut -d, -f3 | sed 's/"//g' | grep -v "^email$" | sort -fu > ${DOMAIN}/emails.list
  cat ${DOMAIN}/output.csv | cut -d, -f3 | sed 's/"//g' | grep -v "^email$" | cut -d'@' -f1 | sort -fu > ${DOMAIN}/users.list
  cat ${DOMAIN}/output.csv | cut -d, -f3,6 | grep -v '""' | sed 's/"//g' | grep -v "^email,plaintext$" | tr ',' ' ' | sort -u > ${DOMAIN}/combo.list
  cat ${DOMAIN}/combo.list | cut -d" " -f1 > ${DOMAIN}/combo_e.list
  cat ${DOMAIN}/combo.list | cut -d" " -f2 > ${DOMAIN}/combo_p.list
  cat ${DOMAIN}/combo.list | sed "s/@${DOMAIN}//" > ${DOMAIN}/combo2.list
  cat ${DOMAIN}/combo2.list | cut -d" " -f1 > ${DOMAIN}/combo_u.list
  echo "$(($(wc -l ${DOMAIN}/output.csv | awk '{print $1}')-1)) record(s)"
done

echo -e "${BLUE}[>]${NORMAL} Total"
cat */emails.list | sort -fu > emails.list
echo "Unique emails: $(wc -l emails.list | awk '{print $1}')"
cat */users.list | sort -fu > users.list
echo "Unique users: $(wc -l users.list | awk '{print $1}')"
cat */combo_p.list | sort -fu > passwords.list
echo "Unique passwords: $(wc -l passwords.list | awk '{print $1}')"
