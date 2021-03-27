#!/usr/bin/env bash

if [[ $# -eq 0 || "$*" == "--help" || "$*" == "-h" ]]; then
  echo "Usage: curling.sh <url_list_file> [proxy]"
  exit 1
fi

BLUE="\e[34m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33"
BOLD="\e[1m"
NORMAL="\e[0m"

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"

URLS=$1
PROXY=$2

if [[ ! -f "${URLS}" ]]; then
  echo -e "${RED}[X]${NORMAL} The file ${BOLD}${URLS}${NORMAL} does not exist!"
  exit 1
fi

if [[ $# -lt 2 ]]; then
  PROXY="http://127.0.0.1:8080"
fi

XARGS="xargs"

if [[ "$OSTYPE" =~ ^darwin ]]; then
  PROCESSES=$(sysctl -n hw.ncpu)
  # xargs on macos doesn't want to play nice :-(
  XARGS="gxargs"
elif [[ "$OSTYPE" =~ ^linux-gnu ]]; then
  PROCESSES=$(awk '/^processor/ {cpu++} END {print cpu}' /proc/cpuinfo)
else
  PROCESSES=2
fi

echo -e "${GREEN}[i]${NORMAL} Using proxy ${BOLD}${PROXY}${NORMAL}"
echo -ne "${GREEN}[i]${NORMAL} Sleeping for 5 seconds (just in case, ctrl-c to cancel!) "
for x in {1..5}; do sleep 1 && echo -n "." ; done
echo

CMD="echo -e \"${BLUE}[>]${NORMAL} Curling ${BOLD}__URL__${NORMAL}\"; \
     curl --proxy \"${PROXY}\" --silent --show-error --insecure --user-agent \"${USER_AGENT}\" -o /dev/null '__URL__'"

cat ${URLS} | while read -r X; do printf "%q\n" "$X"; done | ${XARGS} -P${PROCESSES} -I__URL__ bash -c "$CMD"
