#!/bin/bash
#
# a primitive script to analyze PCAPs.
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
function ask()	# this function borrowed from Advance BASH Scripting Guide
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
i=$(echo $raw|sed 's/\.pcap//')	#obviously, if the ext of your PCAP not
								# '.pcap', modify
read FAKE
tshark -r $i.pcap -qz hosts >  $i.hosts &
tshark -r $i.pcap -qz conv,ip >  $i.conv-ip &
read FAKE

# next get a useable listing of what (to) which IP goes/comes (from)
echo \$i.conv-ip: $i.conv-ip
read FAKE
raw_lines=$(cat $i.conv-ip | wc -l)
echo \$raw_lines: $raw_lines
read FAKE
raw_lines_sans_btm=$(echo $raw_lines-1|bc)
echo \$raw_lines_sans_btm: $raw_lines_sans_btm
clean_lines=$(echo $raw_lines_sans_btm-5|bc)
echo \$clean_lines: $clean_lines

cat $i.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $1 }' > 1
cat $i.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $3 }'  > 3

# I'm not really a programmer... If you want to use this script for yourself,
# get your own listing of local IP's and substitu them for the ones below (I
# have the Chinese ZXDSL censor-ready router used, as far as Europe, in mainly
# former-Communist countries, I don't see my temp public IP, but connect to the
# internet via local 192.168.1.4/24 that router assigns to me):
echo "this gets a listing of non-local IP's"
paste 1 3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//'

echo "save that listing to $i.non-local-hosts-ls-1 ?"
ask;
if [ "$?" == 0 ]; then
paste 1 3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' > $i.non-local-hosts-ls-1
fi
read FAKE

echo "insert legend?"
ask;
if [ "$?" == 0 ]; then
	echo \$i: $i
	echo \$j: $j
read FAKE
	for j in $(cat $i.non-local-hosts-ls-1); do
		grep $j $i.hosts ; read FAKE;
		cat $i.conv-ip | head -5 | tail -2
		grep $j $i.conv-ip ; read FAKE;
	done ;
else

	for j in $(cat $i.non-local-hosts-ls-1); do
		grep $j $i.hosts ; read FAKE;
		grep $j $i.conv-ip ; read FAKE;
	done ;
fi
