#!/bin/bash
#
# a primitive script to analyze PCAPs.
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#
# Reset in case getopts has been used previously in the shell.
#

function show_help {
  echo "tshark-hosts-conv.sh - analyze network traces with Tshark and Bash"
  echo "Usage: $0 -r <PCAP file> -k <ssl.keylog_file>"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo -e "    \tfor particular uses though"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable (currently"
  echo -e "    \thard-wired to value: /home/<you>/.sslkey.log) used during"
  echo -e "    \tFirefox or some other NSS supporting browser's run, all properly set,"
  echo -e "    \tthen you don't need to set this flag"
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

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
		echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
		#read FAKE
        ;;
    k)  KEYLOGFILE=$OPTARG
    echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
    #read FAKE
        ;;
    esac
done

echo
echo "########################################################################"
echo "I'm not really a programmer. I'm writing these scripts out of sheer need."
echo "They are currently, and that state may last for longer, in a poor user's"
echo "debugging state. which means lots of "read FAKE" lines that wait for me"
echo "to keel comparing the lines in the script to what they do, while they do"
echo "their work... Patience, please!"
echo "########################################################################"
echo
echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
	KEYLOGFILE=$SSLKEYLOGFILE
fi
echo \$KEYLOGFILE: $KEYLOGFILE
echo \$PCAP_FILE: $PCAP_FILE
dump=$(echo $PCAP_FILE|cut -d. -f1)
echo \$dump: $dump
ext=$(echo $PCAP_FILE|cut -d. -f2)
echo \$ext: $ext
filename=$dump.$ext
echo \$filename: $filename
read FAKE
echo \$ext: $ext

function ask()	# this function borrowed from Advanced BASH Scripting Guide
				# by Mendel Cooper (IIRC)
{
    echo -n "$@" '[y/n] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

#dump=$(echo $raw|sed 's/\.pcap//')	#obviously, if the ext of your PCAP not
#								# '.pcap', modify. I don't bother with old
#								# .pcap (I came to network reading later),
#								# rather I rename all new .pcapng to .pcap

# Often it's logins and passwords that are of interest in traces, and typically
# they live in POST'ed data. So this is the first thing I'll do.

echo "tshark ... $dump.$ext -qz hosts started in background..."
echo "tshark ... $dump.$ext -qz conv,ip started in background..."
echo
echo "You should wait until these are listed (with 'ls -l') when done:"
echo 
echo "$dump.hosts"
echo "$dump.conv-ip"
echo
echo "The script has not been programmed to wait, but your (the human) decision"
echo "to wait here for them to be created, and then get a useable listing"
echo "of conversations by non-local IPs"
echo 
tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz hosts \
	>  $dump.hosts && ls -l $dump.hosts &
tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz conv,ip \
	>  $dump.conv-ip \
	&& ls -l $dump.conv-ip &
if [ -s "$dump.hosts" ]; then
	ls -l $dump.hosts ;
else
	echo "At the time this if statement ran, these:"
	echo "$dump.hosts and $dump.conv-ip"
	echo "were (still) empty files."
fi

sleep 5 && tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -V -Y \
	'http.request.method==POST'\
	> $dump.POST && ls -l $dump.POST  &
sleep 5 && echo "-Y http.request.method==POST started in background..."
sleep 5 && echo

sleep 5 && \
if [ -s "$dump.POST" ]; then
	ls -l $dump.POST ;
else
	echo "At the time this if statement ran, the:"
	echo "$dump.POST"
	echo "was (still) an empty file."
	echo "You should wait until it is listed (with 'ls -l') done."
fi
sleep 5 && echo

# Examining $dump.POST in a session where you logged in somewhere, gets you the
# frame.number's and tcp.stream's that contain the POST'ed data, and with which
# IP the conversation at the login was.
#
# Not all can be done from this terminal. You need to view and analyze the
# files that will be created in the process, such as $dump.POST, in another
# terminal, to make clever decision about what IPs, what filters on them etc.
#
# E.g., if your login was once in entire session, you can go for either the
# frame.number or the tcp.stream that contains it, and after one more section
# (
# the next section gets all http.full_uri's out on entire trace, and also
# offers you to do filtering for any filter including frame.number or
# tcp.stream on the whole trace
#
# NOTE: this filtering on tcp.stream==NNN is not extracting. This is, I guess,
# dissection... To extract tcp.streams use:
#
# tshark-streams.sh
# from
# https://github.com/miroR/tshark-streams
# )
# , [and after one more section] look up the conversation with that IP more
# closely.
#

echo "Run tshark-http-uri.sh on the whole trace?"
ask;
if [ "$?" == 0 ]; then
	tshark-http-uri.sh -k $KEYLOGFILE -r $dump.${ext}
	echo "As long as you want to run tshark with filtering like"
	echo "tshark -r $dump.${ext} -Y \"\$the_filter\" ?"
	echo "give value \"1\" when asked."
	echo -n "1 for do filtering, 0 for none: "
	read do_filtering
	while [ "$do_filtering" == "1" ]; do
		echo
		echo "Give filter (e.g. \"http.cookie\" or \"frame.number==NNN\")"
		echo -n "to run on $dump.${ext} : "
		read the_filter
		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
			$dump.${ext} -V -Y $the_filter
		echo "You now want to save that stdout?"
		ask;
		if [ "$?" == 0 ]; then
			tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
				$dump.${ext} -V -Y $the_filter \
			> ${dump}_${the_filter}.txt
			echo
			ls -l ${dump}_${the_filter}.txt
			echo
			echo "---"
			echo
		fi
		echo -n "1 for do filtering, 0 for none: "
		read do_filtering
	done
fi

echo \$dump.conv-ip: $dump.conv-ip
# This is a fake read. It only waits for you to hit Enter to go on, or hit
# Ctrl-C and bail out.
read FAKE
raw_lines=$(cat $dump.conv-ip | wc -l)
echo \$raw_lines: $raw_lines
if [ "$raw_lines" -lt "1" ]; then
	echo
	echo "Yes, the below is why this happens!"
	echo
	echo "Maybe just check that $dump.conv-ip is created,"
	echo "and then hit Enter ? Yes! Those run in the background... (faster)"
	echo
	echo "Then, pls. just try not to hit Enter too quickly"
	echo "(just one time at start only --if some readme FAKEs not commented out) ?"
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

cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $1 }' > con-ip_column_1
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $3 }'  > con-ip_column_3

# I'm not really a programmer... If you want to use this script for yourself,
# get your own listing of local IP's and substitute them for the ones below (I
# have the Chinese ZTE ZXDSL 931VII censor-ready router, used, as far as
# Europe, in mainly former-Communist countries, I never see my temp public IP
# in my traces, but connect to the internet via router's local, say,
# 192.168.1.4/24 or some other of the range 192.168.1.0/24 that it assigns to
# me):

# Good to be able to skip this for huge traces, and go straight to saving the
# listing
echo "List the non-local-hosts one per line ?"
echo "A huge trace (and the machine not poweful)?"
echo "If you don't reply \"y\", you will have one loop less to go."
ask;
if [ "$?" == 0 ]; then
echo "---";
echo "This is a listing of non-local IPs"
echo "---";
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.2\t//' | sed 's/\t192.168.1.2//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' \
# the below is OpenDNS that I use, also best exempted from analysis (or?):
	| sed 's/81.2.237.32\t//' | sed 's/\t81.2.237.32//'
fi

echo "---";
echo "Saving the listing of non-local IPs from the trace to:"
echo "    $dump.non-local-hosts-ls-1"
echo "(takes time for huge traces)"
echo "---";
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.2\t//' | sed 's/\t192.168.1.2//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' \
# the below is OpenDNS that I use, also best exempted from analysis (or?):
	| sed 's/81.2.237.32\t//' | sed 's/\t81.2.237.32//'	\
	> $dump.non-local-hosts-ls-1

echo "This will be the first run, so you get some measure on the"
echo "conversations, and can decide which one to analyze further"
echo "in the second run."
echo
echo "Second run (if you choose it) will have options on each item."
echo
echo "First run now..."
echo \$dump.\$ext: $dump.$ext
read FAKE
# legend ought to be inserted every time
for j in $(cat $dump.non-local-hosts-ls-1); do
	grep $j $dump.hosts ; read FAKE;
	cat $dump.conv-ip | head -5 | tail -2
	grep $j $dump.conv-ip ;
	echo "---"; echo ; read FAKE;
done ;
echo "Do the second run?"
ask;
if [ "$?" == 0 ]; then
	echo "Second run now... If you don't reply \"y\", no further"
	echo "analysis will be performed for the particular IP."
	# You can simply hit Enter, script will just continue.
	read FAKE
	for j in $(cat $dump.non-local-hosts-ls-1); do
		grep $j $dump.hosts ; read FAKE;
		cat $dump.conv-ip | head -5 | tail -2
		grep $j $dump.conv-ip ;
		echo "The IP: $j"
		read FAKE
		echo "Save the conversation as separate PCAP?"
		ask;
		if [ "$?" == 0 ]; then
			tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -Y "(ip.addr==$j)" -w ${dump}_${j}.${ext}
			echo
			ls -l ${dump}_${j}.${ext}
			echo
			echo "Run tshark-http-uri.sh on:"
			echo "${dump}_${j}.${ext}"
			echo "(the newly created)?"
			ask;
			if [ "$?" == 0 ]; then
				new_dump=${dump}_${j}
				echo \$new_dump: $new_dump
				tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.${ext}
				echo "As long as you want to run tshark with filtering like"
				echo "tshark -r $new_dump.${ext} -Y \"\$the_filter\" ?"
				echo "give value \"1\" when asked."
				echo -n "1 for do filtering, 0 for none: "
				read do_filtering
				while [ "$do_filtering" == "1" ]; do
					echo "Give filter (e.g. \"http.cookie\" or \"frame.number==NNN\")"
					echo -n "to run on $new_dump.${ext} : "
					read the_filter
					tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						$new_dump.${ext} -V -Y $the_filter
					echo "You now want to save that stdout?"
					ask;
					if [ "$?" == 0 ]; then
						tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
							$new_dump.${ext} -V -Y $the_filter \
						> ${new_dump}_${the_filter}.txt
						echo
						ls -l ${new_dump}_${the_filter}.txt
						echo
						echo "---"
						echo
					fi
					echo -n "1 for do filtering, 0 for none: "
					read do_filtering
				done
			fi
		fi
		echo "---"; echo ; read FAKE;
	done ;
fi
