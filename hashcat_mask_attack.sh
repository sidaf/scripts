#!/bin/bash

set -o errexit -o nounset -o pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
DEFAULT_MASKS=("$DIR/masks/increment6chars.hcmask")
#HASHCAT="$DIR/hashcat-5.1.0/hashcat"
HASHCAT="hashcat"

usage() {
  echo "================================================================================"
  echo "usage: $(basename "$0") <hash_file> <hash_type> [mask1 [mask2]]"
  echo
  echo "Perform a mask attack against a list of hashes using the hashcat tool."
  echo
  echo "Required arguments:" 
  echo "hash_file - a file containing a list of hashes"
  echo "hash_type - the hash type, see 'hashcat -h' for a list of possible values"
  echo
  echo "Optional arguments:"
  echo "mask - use a supplied dictionary (or multiple), otherwise defaults to"
  echo
printf '  %s\n' "${DEFAULT_MASKS[@]}"
  echo
  echo "================================================================================"
}

args() {
  if [ $# -lt 1 ]; then
    usage
    exit 1
  fi

  case $1 in
    "" | "-h" | "--help")
      usage
      exit 0
  esac

  HASH_FILE=${1}
  CRED_FILE="$HASH_FILE.cracked"
  if [[ ! -f "$HASH_FILE" ]]; then
    echo "$HASH_FILE not found!"
    exit 1
  fi

  HASH_TYPE=${2:-}
  if [[ ! -n $HASH_TYPE ]]; then
    usage
    exit 1
  else
    if ! [[ "$HASH_TYPE" =~ ^[0-9]+$ ]]; then
      echo "The hash type needs to be an integer value!"
      exit 1
    fi
  fi

  shift 2
  MASKS=("$@")
  if [[ ${#MASKS[@]} -eq 0 ]]; then
    MASKS=("${DEFAULT_MASKS[@]}")
  fi
  for MASK in "${MASKS[@]}"; do
    if [[ ! -f "$MASK" ]]; then
      echo "$MASK not found!"
      exit 1
    fi
  done

  if [ -z ${HASHCAT_DEVICE_ID+x} ]; then
    HASHCAT_DEVICE_ID=3
  fi
}

# main
args "$@"

for MASK in "${MASKS[@]}"; do
  echo "$ hashcat -d $HASHCAT_DEVICE_ID -O -a 3 -m $HASH_TYPE --outfile $CRED_FILE $HASH_FILE $MASK"
  set +e 
  $HASHCAT -d "$HASHCAT_DEVICE_ID" -O -a 3 -m "$HASH_TYPE" --outfile "$CRED_FILE" "$HASH_FILE" "$MASK"
  set -e 
  echo
  if [[ $? -lt 0 ]] || [[ $? -gt 1 ]]; then
    exit $?
  fi
done
