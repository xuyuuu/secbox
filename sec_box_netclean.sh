#!/bin/sh

default_pattern="can't identify protocol"
default_lock="sec_box_netclean.lck"
default_file="sec_box_netclean.file"

function __handler_inode()
{
	#is inode_num is digital
	if echo "$1" | grep -q "^[0-9]\+$"; then
		echo $1 >> ${default_file}
	fi
}

function handler_inode()
{
	> ${default_file}
	lsof -p $1 | grep "$default_pattern" | while read line
	do
		inode_num=`echo $line | awk '{print $8}'`
		__handler_inode $inode_num
	done
}



if [[ "$1" == "-h" ]]; then
	echo "Usafe: 
./sec_box_netclean.sh -p \$pid -m \$pattern
********\$pid : the pid number
********\$pattern : the pattern string, default: can't identify protocol"
	exit 0;
fi

if [[ "$1" != "-p" ]]; then
	echo "please run './sec_box_netclean.sh -h' for help !"
	exit -1;
fi

if [[ "$3" == "-m" ]]; then
	default_pattern="$4";
fi

handler_inode $2



