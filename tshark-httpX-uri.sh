#!/bin/bash
#
# a simple script to extract full_uri's from PCAPs
#
#   part of the set tshark-hosts-conv, but
#   can be used separately.
#
# Copyright (C) 2015,2020,2023 Miroslav Rovis, <https://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#

# Used to be (2 ln):
#   WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
#   TSHARK=/<some-dir>/wireshark-ninja/run/tshark
#   Replaced with:
. shark2use

function show_help {
  echo "tshark-http-uri.sh - dump full_uri's of a PCAP by frame number"
  echo "Usage: ${0##*/} -r <PCAP file> -k <tls.keylog_file>"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo -e "    \tfor particular uses though"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable used during"
  echo -e "    \tPalemoon, Firefox, or some other NSS supporting browser's run, all"
  echo -e "    \tproperly set, then you don't need to set this flag"
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1
KEYLOGFILE=""

while getopts "hr:k:i:" opt;
do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  PCAP_FILE=$OPTARG
        #echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
        ;;
    k)  KEYLOGFILE=$OPTARG
        #echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
        ;;
    i)  ip=$OPTARG
        #echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
        ;;
    esac
done

if [ "$KEYLOGFILE" == "" ]; then
    KEYLOGFILE=$SSLKEYLOGFILE
fi
#echo \$KEYLOGFILE: $KEYLOGFILE

ext=${PCAP_FILE##*.}
dump=${PCAP_FILE%*.pcap}

# If your SSLKEYLOGFILE is all set with the TLS keys for the PCAP, don't give a
# second argument, but if maybe it is a PCAP not taken by your system, then get
# the pertaining TLS keys and give the file containing them as second argument.

if [ -n "$ip" ] && [ "X${ip}" != "X" ]; then
    if [ ! -e "${dump}_${ip}-frame-http-request-full_uri.txt" ]; then
        $TSHARK -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -Y "ip.addr==$ip" -T fields \
            -e 'frame.number' -e 'http.request.full_uri' | grep \
            -E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
            > ${dump}_${ip}-frame-http-request-full_uri.txt
        ls -l ${dump}_${ip}-frame-http-request-full_uri.txt
    fi
    if [ ! -e "${dump}_${ip}-frame-http2-request-full_uri.txt" ]; then
        $TSHARK -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -Y "ip.addr==$ip" -T fields \
            -e 'frame.number' -e 'http2.request.full_uri' | grep \
            -E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
            > ${dump}_${ip}-frame-http2-request-full_uri.txt
        ls -l ${dump}_${ip}-frame-http2-request-full_uri.txt
    fi
else
    echo tshark -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -Y "ip.addr==$ip" -T fields \
        -e \'frame.number\' -e \'http.request.full_uri\' \| grep \
        -E \'^[0-9]\{1,9\}[[:space:]][[:alpha:]]\' \
        \> ${dump}-frame-http-request-full_uri.txt
    if [ ! -e "${dump}-frame-http-request-full_uri.txt" ]; then
        $TSHARK -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -T fields \
            -e 'frame.number' -e 'http.request.full_uri' | grep \
            -E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
            > ${dump}-frame-http-request-full_uri.txt
        ls -l ${dump}-frame-http-request-full_uri.txt
    fi
    echo tshark -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -Y "ip.addr==$ip" -T fields \
        -e \'frame.number\' -e \'http2.request.full_uri\' \| grep \
        -E \'^[0-9]\{1,9\}[[:space:]][[:alpha:]]\' \
        \> ${dump}-frame-http2-request-full_uri.txt
    if [ ! -e "${dump}-frame-http2-request-full_uri.txt" ]; then
        $TSHARK -otls.keylog_file:$KEYLOGFILE -q -r $dump.$ext -T fields \
            -e 'frame.number' -e 'http2.request.full_uri' | grep \
            -E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
            > ${dump}-frame-http2-request-full_uri.txt
        ls -l ${dump}-frame-http2-request-full_uri.txt
    fi
fi
