#!/bin/bash
#
# a simple script to extract full_uri's from PCAPs
#
#	part of the set tshark-hosts-conv, but
#	can be used separately.
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#

function show_help {
  echo "tshark-http-uri.sh - dump full_uri's of a PCAP by frame number"
  echo "Usage: $0 -r <PCAP file> -k <ssl.keylog_file>"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo -e "    \tfor particular uses though"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable (currently"
  echo -e "    \thard-wired to value: /home/<you>/.sslkey.log) used during"
  echo -e "    \tPalemoon, Firefox, or some other NSS supporting browser's run, all"
  echo -e "    \tproperly set, then you don't need to set this flag"
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1	# Frankly, don't understand yet the OPTIND, nor if it is needed here.
KEYLOGFILE=""

while getopts "h?r:k:" opt;
do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  PCAP_FILE=$OPTARG
		#echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
		#read FAKE
        ;;
    k)  KEYLOGFILE=$OPTARG
		#echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
		#read FAKE
        ;;
    esac
done

#echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
	KEYLOGFILE=$SSLKEYLOGFILE
fi
#echo \$KEYLOGFILE: $KEYLOGFILE
#read FAKE

#echo -n \$PCAP_FILE: $PCAP_FILE
#read FAKE
# Files can have a few dots, this is how I'll take the last as separator.
num_dots=$(echo $PCAP_FILE|sed 's/\./\n/g'| wc -l)
num_dots_min_1=$(echo $num_dots - 1 | bc)
#echo \$num_dots: $num_dots
#echo \$num_dots_min_1: $num_dots_min_1
ext=$(echo $PCAP_FILE|cut -d. -f $num_dots)
#echo \$ext: $ext
#read FAKE
#echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/"
dump=$(echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/")
#echo \$dump: $dump
#read FAKE
filename=$dump.$ext
#echo \$filename: $filename
#read FAKE
#echo \$ext: $ext
#read FAKE

# If your SSLKEYLOGFIE is all set with the SSL keys for the PCAP, don't give a
# second argument, but if maybe it is a PCAP not taken by your system, then get
# the pertaining SSL keys and give the file containing them as second argument.

#raw=$1
#i=$(echo $raw|sed 's/\.pcap//')	#obviously, if the ext of your PCAP not
									# '.pcap', modify
#This line only greps for lines with founds -- no alpha after numbers and
# space, not grep'ed in. Good for looking up that frame number in Wireshark
#if [ -e "$2" ]; then
#read FAKE
#echo $2
# I'm duplicating the below as I currently don't know better.
echo tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -q -r $dump.$ext -T fields \
	-e \'frame.number\' -e \'http.request.full_uri\' \| grep \
	-E \'^[0-9]\{1,9\}[[:space:]][[:alpha:]]\' \
	\> ${dump}-frame-http-request-full_uri.txt
tshark -o "ssl.keylog_file: $KEYLOGFILE" -q -r $dump.$ext -T fields \
	-e 'frame.number' -e 'http.request.full_uri' | grep \
	-E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
	> ${dump}-frame-http-request-full_uri.txt
	ls -l ${dump}-frame-http-request-full_uri.txt
#else
#tshark -q -r $i.pcap -T fields \
#	-e 'frame.number' -e 'http.request.full_uri' | grep \
#	-E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
#	> ${i}-frame-http-request-full_uri.txt
#fi
