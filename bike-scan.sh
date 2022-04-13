#!/bin/bash

logo() {
	echo " _     _ _                                 "
	echo "| |__ (_) | _____       ___  ___ __ _ _ __  "
	echo "| '_ \| | |/ / _ \_____/ __|/ __/ _\` | '_ \ "
	echo "| |_) | |   <  __/_____\__ \ (_| (_| | | | |"
	echo "|_.__/|_|_|\_\___|     |___/\___\__,_|_| |_|"
	echo "Brute force using ike-scan              v1.1"
	echo -e "                       www.interspective.net\n"
}

usage() {
	echo "Usage: $0 [options] [host]"
	echo
	echo "bike-scan is a wrapper to turn ike-scan into a brute-force tool."
	echo "It does this by testing a remote host with every possible combination of"
	echo "transforms, in the chosen order of 'rarity'. Eg. all DES, 3DES, AES, MD5,"
	echo "SHA1, PSK, MOD768 types before testing less common combinations."
	echo "By default, bike-scan will try and brute-force transforms in main mode"
	echo "first, then move onto aggressive mode."
	echo
	echo "Options:"
	echo
	echo "--help or -h              Display this usage message and exit."
	echo
	echo "--main or -M              Main mode scan only."
	echo
	echo "--aggressive or -A        Aggressive mode scan only."
	echo
	echo "-AM                       Switch the mode order to Aggressive then Main"
	echo
	echo "--rarity=<r> or -R<r>     Specify transform 'rarity' and order."
	echo "                          Options include, c, r and v, for Common, Rare"
	echo "                          and Very rare. Default --rarity=cr"
	echo
	echo " Example: $0 -Rcr -AM [host]"
	echo "                          Scan Common and Rare transform combinations"
	echo "                          in Aggressive mode, then Main mode."
	echo
	doexit
}


# Define arrays of transform attributes including descriptions and their rarity. List taken from:
# http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide#Trying_Different_Transforms
#
# You can modify the 'rarity' of any of the attributes as you see fit. Just be sure to use
# 'common', 'rare', or 'vrare' as the option.
# For example, you may be testing systems that make extensive use Blowfish, so changing the
# array element from 'rare' to 'common' will ensure that it will be tested sooner.

crypt=( [0]="Encryption Algorithm"
	[1]="DES,common"
	[2]="IDEA,vrare"
	[3]="Blowfish,rare"
	[4]="RC5,vrare"
	[5]="Triple DES,common"
	[6]="CAST,rare"
	[7]="AES,common"
	[8]="Camellia,vrare"
)

hash=( 	[0]="Hash Algorithm"
	[1]="MD5,common"
	[2]="SHA1,common"
	[3]="Tiger,rare"
	[4]="SHA-256,rare"
	[5]="SHA-384,rare"
	[6]="SHA-512,rare"
)

auth=(	[0]="Authentication Method"
	[1]="Pre-Shared Key,common"
	[2]="DSS Signature,rare"
	[3]="RSA Signature,common"
	[4]="RSA Encryption,rare"
	[5]="Revised RSA Encryption,rare"
	[6]="ElGamel Encryption,rare"
	[7]="Revised ElGamel Encryption,rare"
	[8]="ECDSA Signature,rare"
	[64221]="Hybrid Mode,common"
	[65001]="XAUTH,common"
)

dhgrp=(	[0]="Diffie-Hellman Group"
	[1]="MODP 768,common"
	[2]="MODP 1024,common"
	[3]="EC2N 155,rare"
	[4]="EC2N 185,rare"
	[5]="MODP 1536,common"
	[6]="EC2N 163,rare"
	[7]="EC2N 163,rare"
	[8]="EC2N 183,rare"
	[9]="EC2N 183,rare"
	[10]="EC2N 409,rare"
	[11]="EC2N 409,rare"
	[12]="EC2N 571,rare"
	[13]="EC2N 571,rare"
	[14]="MODP 2048,rare"
	[15]="MODP 3072,rare"
	[16]="MODP 4096,rare"
	[17]="MODP 6144,rare"
	[18]="MODP 8192,rare"
)

# Set default return value
retVal="0"

# Check the -$? on this subroutine.
function doexit() {
	local exit_status=${retVal:-$?}
	echo "Exiting with status: $exit_status"
	exit $exit_status
}

doScanLoop() {
noResponse=()
ikeMode="${2//M/}"
	doScanToArray() {
	scanIndex=0
	scan=()
		# This executes ike-scan and sticks the output into an array.
		while read line; do
			scan[$scanIndex]="$line"
			((scanIndex++))
		# Not sure if the 'wait $1" is needed..
		done< <(ike-scan -r 1 -M $ikeMode -a $2 $1 & wait $!
			echo $?)
		# Check exit code to see if ike-scan spazzed out..
		# Check this to see if it actually is getting the last value.
		if [[ "${scan[$((${#scan[@]}-1))]}" -gt "0" ]]; then
			retVal=1
			doexit
		fi
		
		# This puts the ike-scan transform scan response into array 'noResponse' if
		# the host didn't respond with anything. This is used to determine if the host
		# is responding or not, or if the '--id=' argument to an Aggressive scan.
		if [[ -z "${scan[1]}" ]]; then
			if [[ ! "${noResponse[@]}" =~ "$2" ]]; then
				noResponse[$transformIndex]="$2"
			fi
			# If we get 5 null responses for the first 5 transforms sent then the host
			# isn't responding, possibly not running ike, or just being a bitch.
			if [[ "${#noResponse[@]}" -eq "3" ]] && [[ "$transformIndex" -eq "2" ]]; then
				# The following checks if the scan is Aggressive and adds
				# the '--id=' argument to the running scan.
				if [[ ! "$ikeMode" =~ "thisisarandomid" ]] && [[ "$ikeMode" = "-A" ]]; then
					echo -e "[+] No response from host using aggressive mode scan.\n"
					echo -e "[+] Adding '--id=' to scan arguments and trying again.\n"
					ikeMode="$ikeMode --id=thisisarandomid"
					return 1
				else
					echo -e "[-] No response from host.\n"
					# Put stuff here to do something / report something
					retVal="1"
					doexit
				fi
			fi
		fi
		# This checks to see if the response is a main or aggressive mode handshake
		# and echos the results to the user if it is. \o/
		if [[ "${scan[1]}" =~ "Handshake returned" ]]; then
			echo "Successful command: ike-scan -r 1 -M $ikeMode -a $2 $1"
			echo "${scan[1]}"
			for scanElement in $(seq 2 $((${#scan[@]} - 3))); do
				echo -e "\t${scan[$scanElement]}"
			done
		fi
	}

	doScanNoResponses() {
		for noResponseIndex in ${!noResponse[@]}; do
			doScanToArray $1 ${noResponse[$noResponseIndex]}
		done
	}

	# Main scan subroutine.
	doScan() {
		for transformIndex in ${!array[@]}; do
			doScanToArray $1 ${array[$transformIndex]} $2
			if [[ "$?" -eq "1" ]]; then
				doScanNoResponses $1
				noResponse=()
			fi
		done
	}
	doScan $1
	
	# Check to see if stuff needs to be done from a previous run of 'doScanToArray'.
	if [[ "${#noResponse[@]}" -gt "0" ]]; then
		for ((i=0; i < 3; i++)); do
			doScanNoResponses $1 $ikeMode
		done
	fi
	
	# switch modes if needed.. (make sure you set noresponses=() )
	if [[ "$2" != "M" ]] && [[ -z "$ikeMode" ]] ; then
		echo -e "[+] Starting Aggressive mode scan.\n"
		ikeMode="-A"
		doScan $1 $ikeMode
	fi
	if [[ "$2" == "-AM" ]] && [[ -n "$ikeMode" ]]; then
		echo -e "[+] Starting Main Mode scan.\n"
		ikeMode=""
		doScan $1 $ikeMode
	fi
		
}

buildArray() {
arrayIndex="0"
echo -e "[+] Building transform list using rarity order: ${1/vrare/very rare} ${2/vrare/very rare} ${3/vrare/very rare}\n"
for cryptRarity in $1 $2 $3; do
	for cryptElement in ${!crypt[@]}; do
		if [[ ${crypt[$cryptElement]#*,} == $cryptRarity ]]; then
			for hashRarity in $1 $2 $3; do
				for hashElement in ${!hash[@]}; do
					if [[ ${hash[$hashElement]#*,} == $hashRarity ]]; then
						for authRarity in $1 $2 $3; do
							for authElement in ${!auth[@]}; do
								if [[ ${auth[$authElement]#*,} == $authRarity ]]; then
									for dhgrpRarity in $1 $2 $3; do
										for dhgrpElement in ${!dhgrp[@]}; do
											if [[ ${dhgrp[$dhgrpElement]#*,} == $dhgrpRarity ]]; then
												if [[ $cryptElement == 7 ]]; then
													for cryptAESkeySize in 128 192 256; do
														array[$arrayIndex]="$cryptElement/$cryptAESkeySize,$hashElement,$authElement,$dhgrpElement"
														((arrayIndex++))
													done
												else
													array[$arrayIndex]="$cryptElement,$hashElement,$authElement,$dhgrpElement"
													((arrayIndex++))	
												fi
											fi
										done
									done
								fi
							done
						done
				 	fi
				done			
			done
		fi
	done
done
echo -e "[+] Done. List contains ${#array[@]} transform combinations.\n"
}

# Set default 'rarity' options and order for building transform array
rarityOptions="common rare"

hostError() {
        echo -e "[-] Error: hostname not specified.\n"
	sleep 1
        retVal="1"
        usage
}

if [[ $# -lt "1" ]]; then
	logo
	hostError
else
	hostname=
while test -n "$1"; do
	case "$1" in
		""|--help|-h)
			logo
			usage
			shift
		;;
		-AM)
			ikeMode="-AM"
			shift
		;;
		--main|-M)
			ikeMode="M"
			shift	
		;;
		--aggressive|-A)
			ikeMode="-A"
			shift
		;;
		--rarity=*|-R*)
			# Sub out the value needed.
			if [[ ${1/--rarity=/} == $1 ]]; then
				rarity="${1/#-R/}"
			else
				rarity="${1/#--rarity=/}"
			fi
			# Check if user supplied too many 'rarity' options.
			if [[ ${#rarity} -gt 3 ]]; then
				echo
				echo -e "[-] Error: Too many 'rarity' options specified ($rarity). Maximum of three.\n"
				sleep 1
				retVal="1"
				usage
			# If user supplied 'rarity' options, reset option list ..
			elif [[ ${#rarity} -gt 0 ]]; then
				rarityOptions=
			# .. and build 'rarity' options list with order specified by user.
			fi
			for ((i=0; i < ${#rarity}; i++)); do
				if [[ ${rarity:$i:1} == "c" ]]; then
					rarityOptions="$rarityOptions common"
				elif [[ ${rarity:$i:1} == "r" ]]; then
					rarityOptions="$rarityOptions rare"
				elif [[ ${rarity:$i:1} == "v" ]]; then
					rarityOptions="$rarityOptions vrare"
				fi
			done
			shift
		;;
		-*)
			echo
			echo -e "[-] Error: Unknown argument $1\n"
			sleep 1
			retVal="1"
			usage
			shift
		;;
		*)
			hostname="$1"
			shift
		;;
	esac
done

if [[ -z "$hostname" ]]; then
	hostError
fi
fi

# Build the transform array using 'rarity' selection and then run the scan.
logo
buildArray $rarityOptions
doScanLoop $hostname $ikeMode
doexit

