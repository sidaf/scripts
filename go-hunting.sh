#!/usr/bin/env bash

if [[ $# -eq 0 || $# -gt 2 || "$*" == "--help" || "$*" == "-h" ]]; then
  echo "Usage: go-hunting.sh <domain> [output.txt]"
  exit 1
fi

BLUE="\e[34m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33"
BOLD="\e[1m"
NORMAL="\e[0m"

if [[ -z "${HUNTER_API_KEY}" ]]; then
  echo -e "${RED}[X]${NORMAL} The HUNTER_API_KEY environment variable has not been set!"
  exit 1
fi

DOMAIN=$1
OUTPUT=$2

if [[ $# -lt 2 ]]; then
  OUTPUT="${DOMAIN}_hunter.io.txt"
fi

TOTAL=$(curl -s "https://api.hunter.io/v2/email-count?domain=${DOMAIN}" | jq -r '.data.total')

echo -e "${BLUE}[>]${NORMAL} Total email count for ${BOLD}${DOMAIN}${NORMAL} is ${BOLD}${TOTAL}${NORMAL}"

echo -ne "${BLUE}[>]${NORMAL} Fetching email list, offset ..."
if [ "${TOTAL}" != "0" ]; then
	for (( i=0; i<=${TOTAL}; i+=100 )); do
		echo -n " ${i} "
		curl -s "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_API_KEY}&limit=100&offset=${i}" | jq -r '.data.emails[].value' >> ${OUTPUT}
	done
  echo
fi
sort -u ${OUTPUT} -o ${OUTPUT}
echo -e "${BLUE}[>]${NORMAL} Email list written to ${BOLD}${OUTPUT}${NORMAL}"
