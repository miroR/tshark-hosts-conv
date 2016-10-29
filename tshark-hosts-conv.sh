#!/bin/bash
#
# a primitive script to analyze PCAPs.
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
echo 
echo "#############   Pls. read the script to use this.  ################"
echo 

function ask()	# this function borrowed from Advanced BASH Scripting Guide
				# by Mandel Cooper (IIRC)
{
    echo -n "$@" '[y/n] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

if [ $# -eq 0 ]; then
    echo "Must give a PCAP file (and I won't check if it is one)."
	echo "Use this at your own risk!"
	echo "Pls. read some more in the script."
    exit 0
fi

raw=$1
pcap=$(echo $raw|sed 's/\.pcap//')	#obviously, if the ext of your PCAP not
								# '.pcap', modify
								# I don't bother with old .pcap (I came to this
								# later), but rename all new .pcapng to .pcap
tshark -r $pcap.pcap -qz hosts >  $pcap.hosts && echo "$pcap.hosts created" &
tshark -r $pcap.pcap -qz conv,ip >  $pcap.conv-ip && echo "$pcap.conv-ip created" &

echo 
echo "(Possibly) wait (non-auto, human choice-wait) for:"
echo 
echo "$pcap.hosts"
echo 
echo "and"
echo 
echo "$pcap.conv-ip"
echo 
echo "to be created, and then"
echo 
echo "get a useable listing of conversations by non-local IPs"
echo 
echo \$pcap.conv-ip: $pcap.conv-ip
# This is a fake read me. It only waits for you to hit Enter to go on, or hit
# Ctrl-C and bail out.
read FAKE
raw_lines=$(cat $pcap.conv-ip | wc -l)
echo \$raw_lines: $raw_lines
if [ "$raw_lines" -lt "1" ]; then
	echo
	echo "Yes, the below is why this happens!"
	echo
	echo "Maybe just check that $pcap.conv-ip is created,"
	echo "and then hit Enter ? Yes! Those run in the background..."
	echo
	echo "Then, pls. just try not to hit Enter too quickly"
	echo "(some one-three times at start only) ?"
	echo
	echo "\$raw_lines can't be less then 1"
	exit 1
fi
read FAKE

raw_lines_sans_btm=$(echo $raw_lines-1|bc)
echo \$raw_lines_sans_btm: $raw_lines_sans_btm
clean_lines=$(echo $raw_lines_sans_btm-5|bc)
echo \$clean_lines: $clean_lines
read FAKE

cat $pcap.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $1 }' > con-ip_column_1
cat $pcap.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $3 }'  > con-ip_column_3

# I'm not really a programmer... If you want to use this script for yourself,
# get your own listing of local IP's and substitute them for the ones below (I
# have the Chinese ZTE ZXDSL 531VII (IIRC) censor-ready router, used, as far as
# Europe, in mainly former-Communist countries, I never see my temp public IP
# in my traces, but connect to the internet via router's local 192.168.1.4/24
# that it assigns to me):

# Good to be able to skip this for huge traces, and go straight to saving the
# listing
echo "List the non-local-hosts one per line ?"
echo "A huge trace? Don't reply \"y\", would go two loops not one."
ask;
if [ "$?" == 0 ]; then
echo "---";
echo "This iss a listing of non-local IPs"
echo "---";
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//'
fi

echo "---";
echo "Saving the listing of non-local IPs from the trace to:"
echo "    $pcap.non-local-hosts-ls-1"
echo "(takes time for huge traces)"
echo "---";
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' > $pcap.non-local-hosts-ls-1

echo \$pcap.pcap: $pcap.pcap
# legend ought to be inserted every time
read FAKE
for j in $(cat $pcap.non-local-hosts-ls-1); do
	grep $j $pcap.hosts ; read FAKE;
	cat $pcap.conv-ip | head -5 | tail -2
	grep $j $pcap.conv-ip ;
	echo "---"; echo ; read FAKE;
done ;
