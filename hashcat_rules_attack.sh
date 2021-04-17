#!/bin/bash

set -o errexit -o nounset -o pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
DEFAULT_WORDLISTS=("$DIR/wordlists/passwords/rockyou.txt.gz")
DEFAULT_RULES=("$DIR/rules/hob064_2.rule" "$DIR/rules/best64.rule" "$DIR/rules/InsidePro-PasswordsPro.rule" "$DIR/rules/T0XlC.rule" "$DIR/rules/d3ad0ne.rule" "$DIR/rules/OneRuleToRuleThemAll.rule" "$DIR/rules/d3adhob0_2.rule")
#HASHCAT="$DIR/hashcat-5.1.0/hashcat"
HASHCAT="hashcat"

usage() {
  echo "================================================================================"
  echo "usage: $(basename "$0") <hash_file> <hash_type> [dictionary1 [dictionary2]]"
  echo
  echo "Perform a rules attack against a list of hashes using the hashcat tool."
  echo
  echo "Required arguments:" 
  echo "hash_file - a file containing a list of hashes"
  echo "hash_type - the hash type, see 'hashcat -h' for a list of possible values"
  echo
  echo "Optional arguments:"
  echo "dictionary - use a supplied dictionary (or multiple), otherwise defaults to"
  echo
printf '  %s\n' "${DEFAULT_WORDLISTS[@]}"
  echo
  echo "HASHCAT_RULES - Environment variable to set rules, otherwise defaults to"
  echo
printf '  %s\n' "${DEFAULT_RULES[@]}"
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
  WORDLISTS=("$@")
  if [[ ${#WORDLISTS[@]} -eq 0 ]]; then
    WORDLISTS=("${DEFAULT_WORDLISTS[@]}")
  fi
  for WORDLIST in "${WORDLISTS[@]}"; do
    if [[ ! -f "$WORDLIST" ]]; then
      echo "$WORDLIST not found!"
      exit 1
    fi
  done

  if [ -z ${HASHCAT_DEVICE_ID+x} ]; then
    HASHCAT_DEVICE_ID=3
  fi

  if [ -z ${HASHCAT_RULES+x} ]; then
    HASHCAT_RULES=("${DEFAULT_RULES[@]}")
  fi
}

# main
args "$@"

CRACK_START=$(date +%s)

for RULE in "${HASHCAT_RULES[@]}"; do
  for WORDLIST in "${WORDLISTS[@]}"; do
    echo "$ hashcat -d $HASHCAT_DEVICE_ID -O -a 0 -m $HASH_TYPE --outfile $CRED_FILE $HASH_FILE $WORDLIST -r $RULE"
    set +e 
    $HASHCAT -d "$HASHCAT_DEVICE_ID" -O -a 0 -m "$HASH_TYPE" --outfile "$CRED_FILE" "$HASH_FILE" "$WORDLIST" -r "$RULE"
    set -e 
    echo
    if [[ $? -lt 0 ]] || [[ $? -gt 1 ]]; then
        exit $?
    fi
  done
done

CRACK_STOP=$(date +%s)
CRACK_RUNTIME=$(( $CRACK_STOP - $CRACK_START ))

echo "================================================================================"
echo "Runtime: $CRACK_RUNTIME seconds"
echo "================================================================================"
