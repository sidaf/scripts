list=()

for i in `cat $1`; do
	apt-cache showsrc $i | grep "Package:" | cut -d " " -f 2
#	apt-cache show $i | grep "Source:" | cut -d " " -f 2
#	result="$(apt-cache show $i | grep "Source:" | cut -d " " -f 2)"
#	echo $result
#	list+=$result
#	echo ${list[@]}
#	apt-cache showsrc $i | grep "^Build-Depends:"
done

#echo "${list[@]}" | tr ' ' '\n' | sort | uniq
