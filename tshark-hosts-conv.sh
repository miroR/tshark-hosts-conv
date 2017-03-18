#!/bin/bash
#
# an script to analyze PCAPs by applying various Tshark display filters
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#
# Oh, it's really PCAPNG's, but the name should be changed back to PCAP. Too
# long! I came to network reading later, so I rename all my .pcapng to .pcap.
#
# Just this, currently: you save, from Wireshark, a packet selection from a
# PCAPNG file (regardless that its extension is .pcap), to a new file with the
# extension .pcap, you don't get a PCAPNG, but the old PCAP format. And that
# (sic!) should change.
# However, you do the same with Tshark, like with some of the commands that can
# be construed with this script, you do get a PCAPNG no matter the extension
# .pcap you give it. At least with Tshark it's fine.
#
# Geared toward newbies. Advanced users and experts, bear with my imperfect
# scripting and detailed explanations!
#
# Lots of the commands below can be done, and often (not always!, just mostly)
# much more easily, comfortably and nicely, with Wireshark. Wireshark remains
# irreplaceable, for me too, but the Tshark (its own Tshark) complements its
# job in an equally indispensable way too.
# 
# Just remember one thing, if trying to do a similar analysis in Wireshark.  In
# case you want to do any sensible analysis on someone else's traces, like I
# offer for you my traces, because I need to solve the issues I have, you need
# to start Wireshark with the right SSL-keys, else you won't get any SSL
# traffic decrypted, with the option, which for the PCAP of an a sample page I
# give below would be:
#
# wireshark -o "ssl.keylog_file: dump_161203_1629_g0n_SSLKEYLOGFILE.txt" \
#     dump_161203_1629_g0n.pcap
#
# And one of the issues I'm unable to solve on my own, for which the above
# command would apply, is this last issue that I posted at:
# Sign Up to StackOverflow Impossible?
# http://www.croatiafidelis.hr/foss/cap/cap-161202-stackoverflow/stackoverflow-signup-3.php
# and I didn't feel like it was good enough to be giving Wireshark screenshots
# when asking for help.
#
# I would like to teach all good people who are censored to learn how to
# publish censorship (unless they live in countries which are hopelessly
# non-free, where that would not help at all) and so, after some public
# attention, they get at least a little more free from censorship.
#

function show_help {
  echo "tshark-hosts-conv.sh - analyze network traces with Tshark and Bash"
  echo "version 0.98.1"
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

#
# Reset in case getopts has been used previously in the shell.
#
OPTIND=1	# I still don't understand the OPTIND, nor if it is needed here.
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
		# This is one of those: an echo-checkup on a variable (above) and its
		# fake read (below). If uncommented, they only wait for you to hit
		# Enter to go on, or hit Ctrl-C and bail out.
		#read FAKE
        ;;
    k)  KEYLOGFILE=$OPTARG
    	#echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
    	#read FAKE
        ;;
    esac
done

# There are lots of echo \$<some variable>... lines in the script. I keep
# them around till I become more at ease with my own script. Can easily
# uncomment them if something's wrong... 
#echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
	KEYLOGFILE=$SSLKEYLOGFILE
fi
#echo \$KEYLOGFILE: $KEYLOGFILE
#echo \$PCAP_FILE: $PCAP_FILE
dump=$(echo $PCAP_FILE|cut -d. -f1)
#echo \$dump: $dump
ext=$(echo $PCAP_FILE|cut -d. -f2)
#echo \$ext: $ext
#read FAKE
#echo \$ext: $ext

if [ ! -e "$dump.$ext" ]; then
	echo "The file you gave:"
	echo "$dump.$ext"
	echo "does not exist, or is not in the current directory."
	sleep 3
	show_help
    exit 0
fi

echo
echo "########################################################################"
echo "#                       *       *   * *   *       *                    #"
echo "I'm not really a programmer. I'm writing these scripts out of sheer need."
echo "They are currently, and that state may last for longer, in a poor user's"
echo "debugging state. which means lots of "read FAKE" lines that wait for me"
echo "to keep comparing the lines in the script to what they do, while they do"
echo "their work... Bear with me, pls.!"
echo
echo "Freely comment out the \"read FAKE\" which is four lines below here, if"
echo "after you check the script decide that you might still use it more."
echo "#                       *       *   * *   *       *                    #"
echo "########################################################################"
echo
read FAKE

tHostsConvLog=tshark-hosts-conv_$(date +%y%m%d_%H%M%S).log
export tHostsConvLog
touch $tHostsConvLog
echo "I have created the file $tHostsConvLog, and you can open it in another"
echo "terminal such as with a command: "
echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "                                                             "
echo " tailf $tHostsConvLog"
echo "                                                 <<===== |   "
echo " ^^^^^^^^^^^^^^^^^^^^^^^^^^^                <<========== |   "
echo " |||||||||||||||||||||||||||                                 "
echo "                                                             "
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
sleep 3
echo
echo "and you might find it useful for further analysis/discussion/other later."

function ask()	# this function borrowed from "Advanced BASH Scripting Guide"
				# (a free book) by Mendel Cooper
{
    echo -n "$@" '[y/[n]] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

function decline()	# the opposite, reverse, the negative if you will, of ask()
{
    echo -n "$@" '[[y]/n] ' ; read ans
    case "$ans" in
        n*|N*) return 1 ;;
        *) return 0 ;;
    esac
}

# The list of hosts, and the conversations is what this script extracts first
echo "tshark ... $dump.$ext -qz hosts started in background..."
echo "tshark ... $dump.$ext -qz conv,ip started in background..."
echo
echo
echo
echo "You should wait until these are listed (with 'ls -l') when done:"
echo
echo "$dump.hosts"
echo "$dump.conv-ip"
echo 
echo 
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "  Go slowly at this start, wait a few seconds, "
echo   
echo "     and read what I write on the screen! "
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo
echo
echo
echo "The script has not been programmed to wait, but your (the human) decision"
echo "to wait here for them to be created, and then get a useable listing"
echo "of conversations by non-local IPs"
echo 
echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -qz hosts \
	>  $dump.hosts" | sed 's/\t//g' | sed 's/  / /g' \
	| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog &&
tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz hosts \
	>  $dump.hosts && ls -l $dump.hosts | sed 's/\t//g' | sed 's/  / /g' \
	| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog \
	&& echo |& tee -a $tHostsConvLog &
echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -qz conv,ip \
	>  $dump.conv-ip" | sed 's/\t//g' | sed 's/  / /g' \
	| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog &&
tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz conv,ip \
	>  $dump.conv-ip \
	&& ls -l $dump.conv-ip |& tee -a $tHostsConvLog \
	&& echo |& tee -a $tHostsConvLog &
if [ -s "$dump.hosts" ]; then
	ls -l $dump.hosts ;
else
	echo "At the time this if statement ran, these:"
	echo "$dump.hosts and $dump.conv-ip"
	echo "were (still) empty files."
	echo "If this is a huge dump on not powerful machine, fire up"
	echo "top"
	echo "in another teminal, and you'll be able to learn"
	echo "when that process will have been completed."
fi

# Often it's logins and passwords that are of interest in traces, and typically
# they live in POST'ed data. So this is the next thing I'll do.
sleep 4 && echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -V -Y \
	'http.request.method==POST'" \| sed \'s/\\t//g\' \| sed \'s/  / /g\' \
	\| sed \'s/  / /g\' \| sed \'s/  / /g\' \
	\> $dump.POST |& tee -a $tHostsConvLog &
sleep 5 && tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -V -Y \
	'http.request.method==POST' > $dump.POST \
	| sed 's/  / /g' | sed 's/  / /g' \
	| sed 's/\t//g' | sed 's/  / /g' && ls -l $dump.POST |& tee -a $tHostsConvLog \
	&& echo |& tee -a $tHostsConvLog &
sleep 5 && echo "-Y http.request.method==POST started in background..." &
sleep 5 && echo &

sleep 5 && \
if [ -s "$dump.POST" ]; then
	ls -l $dump.POST ;
else
	echo "At the time this if statement ran, the:"
	echo "$dump.POST"
	echo "was (still) an empty file."
	echo "If this is a huge dump on not powerful machine, you can fired up"
	echo "top"
	echo "in a teminal, to see the processes running, and know when they're done."
	echo
	echo "You should now wait until $dump.POST is listed done (with 'ls -l')."
fi
sleep 5 && echo &

# Examining $dump.POST in a session where you logged in somewhere, gets you the
# frame.number's and tcp.stream's that contain the POST'ed data, and with which
# IP the conversation at the login was.
#
# Not all can be done from this terminal. You need to view and analyze the
# files that will be created in the process, such as $dump.POST, in another
# terminal, to make clever decision about which traffic, with what IPs to look
# into, and what display filters to apply to understand what, say, went wrong.
#
# E.g., if your login was once in entire session, you can go for either the
# frame.number or the tcp.stream that contains it, and after one more section
# (
# the next section gets all http.full_uri's out on entire trace, and also
# offers you to do filtering for any filter including frame.number or
# tcp.stream on the whole trace
#
# NOTE: this filtering on tcp.stream==NNN is not extracting streams. This is, I
# guess, dissection... To extract tcp.streams use:
#
# tshark-streams.sh
# from
# https://github.com/miroR/tshark-streams
# )
# , ...[and after one more section] look up the conversation with that IP more
# closely.
#

sleep 3 && echo "_Not_ run tshark-http-uri.sh on the whole trace? (Enter == accept)"
ask
if [ "$?" == 0 ]; then
	echo "We skipped running tshark-http-uri.sh on $dump.$ext"
else
	echo "tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext"  \
		| sed 's/\t/ /g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
	tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext |& tee -a $tHostsConvLog
	#ls -l ${dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
	echo |& tee -a $tHostsConvLog
fi
echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "                   || || || "
echo "                   || || || "
echo "                   \/ \/ \/ "
echo
echo "The default is to run the commands, so that mere"
echo "hitting Enter gets things done, without too much fuss."
echo
echo "But the option also is attempted to be given to bail out"
echo "of the running of command at each stage, and get one's"
echo "own choice of commands to run."
echo
echo "Most of this script:"
echo "$0"
echo "is about running filtering commands with Tshark, such as:"
echo "tshark -r $dump.$ext -V -Y \"\$the_filter\""
echo
echo "Examples of entries: \"http.cookie\","
echo "\"frame.number==NNN\" where NNN is a number, \"ssl\", \"ssl.resumed\","
echo " \"tcp.analysis.flags\", \"tcp.analysis.rto\"."
echo 
echo "Many other filters should work too. But not all, such as, at this time,"
echo "not the multiple ipv4 or ipv6 selection filters. Read 'man tshark'"
echo "and run:"
echo " tshark -G fields "
echo "and you'll want to learn about filters."
echo
echo "The script first looks for hardwired filename, in your run it is" 
echo "${dump}_FILTER.ls-1"
echo
echo "Then you are offered to give the filename of the list of filters" 
echo
echo "Lastly, you can input filters one by one." 
echo
echo "First the tshark command with the filter iteration is run, second,"
echo "you are given the option to save it to a file,"
echo "which will have the filter string infixed in its name, in another run."
echo
echo "Just hit Enter"
echo "when asked whether to run or not some filtering command,"
echo "because the default, in such queries, is to run it."
echo
echo "But if you don't want to run a particular command offered,"
echo "you need to type anything starting with \"n\" or \"N\""
echo "Nein, No, Ne, Nada, nein, no, ne, nada ... or just n or N"
echo "when asked."
echo
echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
echo "${dump}.$ext"
decline
echo
if [ -e "${dump}_FILTER.ls-1" ]; then
	# The hardwired name for the filter file is used promptly:
	filter_file=${dump}_FILTER.ls-1
	echo
	echo "Will try to use $filter_file."
	echo
else
	echo "If you have prepared a file with one filter string per line"
	echo "to run on:"
	echo "$dump.$ext"
	echo "type/paste here that filename, if it is in the current dir,"
	# no ~ expansion; how do you do that?
	echo "or type/paste here the full path (no ~ expansion) if it is not."
	echo -n "(It must be readable by user "; echo -n $(whoami); echo -n "): "
	read filter_file
fi
while [ "$?" == "0" ] ; do
	if [ ! -e "$filter_file" ]; then
		echo
		echo "There's no such file by the name that you gave, Tuxian!"
		echo
		break
	fi
	for the_filter in $(cat $filter_file); do
		echo
		echo "\$the_filter: \"$the_filter\""
		echo " ^^^^^^^^^^^"
		echo
		echo "and the command interactively programmed to run next is:"
		echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
			$dump.$ext -V -Y \"$the_filter\"" \
			| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
			| sed 's/  / /g'
		# Remove these two lines if you're editing this to run non-interactively
		echo "Hit Enter"
		read FAKE
		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
			$dump.$ext -V -Y "$the_filter" \
			| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
			| sed 's/  / /g'
		echo "You now want to save that stdout"
		echo " to file:  ${dump}_${the_filter}.txt"
		echo "Was there no output (or tshark complaining"
		echo "it wasn't a field or protocol name)? Reply \"n\"!"
		ask
		if [ "$?" == 0 ]; then
			echo
			echo "\$the_filter: \"$the_filter\""
			echo " ^^^^^^^^^^^"
			echo
			echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
				$dump.$ext -V -Y \"$the_filter\" \
				> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
				| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
			#tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
			#	$dump.$ext -V -Y "$the_filter" \
			#	> "${dump}_${the_filter}.txt"
			# Another no go. Can't do the above when filter-infixed filename
			# has funny name (e.g."ipv6.addr==fe80::f129:4b99:3b9f:7b55", i.e. with
			# double ":", and there are bound to other).
			# Can do the below. In 4 places in this script.
			echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
				$dump.$ext -V -Y \"$the_filter\" \
				> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
				| sed 's/  / /g' | sed 's/  / /g' > CMD
			chmod 755 CMD ; ./CMD
			echo
			echo "More patience might be needed again..."
			echo "I (currently) don't know how to exit the while loop below."
			echo
			echo "Gentle user, if you are stuck at this point with staying"
			echo "inside this loop below because the file keeps at size 0,"
			echo "pls. issue (in another terminal)"
			echo "this command to get out of it: "
			echo
			echo "echo \" \" > ${dump}_${the_filter}.txt"
			echo
			echo "if the command: "
			tail -1 $tHostsConvLog | sed 's/\t//g' | sed 's/  / /' | \
				sed 's/  / /' | sed 's/  / /'
			echo "has completed!"
			echo
			while [ ! -s "${dump}_${the_filter}.txt" ] ; do
				sleep 5; echo -n "+5s "
			done
			ls -l "${dump}_${the_filter}.txt" |& tee -a $tHostsConvLog
			echo |& tee -a $tHostsConvLog
			echo
			echo "---"
			echo
		fi
	done
	break
done
echo
echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
echo "${dump}.$ext"
decline
if [ "$?" == 0 ]; then
	while [ "$?" == "0" ]; do
		echo
		echo "Give the filter string to run on"
		echo -n "$dump.$ext : "
		read the_filter
		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
			$dump.$ext -V -Y $the_filter
		echo
		echo "You now want to save that stdout"
		echo " to file: ${dump}_${the_filter}.txt"
		ask
		if [ "$?" == 0 ]; then
			echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
				$dump.$ext -V -Y \"$the_filter\" \
				> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
				| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
			#tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
			#	$dump.$ext -V -Y "$the_filter" \
			#	| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
			#	| sed 's/  / /g' \\
			#	> "${dump}_${the_filter}.txt"
			# Another no go. Can't do the above when filter-infixed filename
			# has a funny name. Can do the below. In 4 places in the script.
			echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
				$dump.$ext -V -Y \"$the_filter\" \
				> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
				| sed 's/  / /g' | sed 's/  / /g' > CMD
			chmod 755 CMD ; ./CMD
			echo
			ls -l "${dump}_${the_filter}.txt" |& tee -a $tHostsConvLog
			echo |& tee -a $tHostsConvLog
			echo
			echo "---"
			echo
		fi
		echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
		echo "${dump}.$ext"
		decline
	done
fi

#echo \$dump.conv-ip: $dump.conv-ip
#read FAKE
raw_lines=$(cat $dump.conv-ip | wc -l)
#echo \$raw_lines: $raw_lines
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
#read FAKE

raw_lines_sans_btm=$(echo $raw_lines-1|bc)
#echo \$raw_lines_sans_btm: $raw_lines_sans_btm
clean_lines=$(echo $raw_lines_sans_btm-5|bc)
#echo \$clean_lines: $clean_lines
#read FAKE

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
# me).

# Good to be able to skip this for huge traces, and go straight to saving the
# listing
echo "List the non-local-hosts (all with which any conversations were traced)"
echo "one per line ?"
echo "A huge trace (and the machine not poweful)?"
echo "If you don't reply \"y\", you will have one loop less to go."
ask
if [ "$?" == 0 ]; then
echo "---";
echo "This is the listing of non-local IPs"
echo "---";
# the below would contain also OpenDNS that i use, also best exempted from
# analysis (or?):
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.2\t//' | sed 's/\t192.168.1.2//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' #\
#
#	| sed 's/81.2.237.32\t//' | sed 's/\t81.2.237.32//' \
#	| sed 's/81.2.237.32//' | grep -E '[[:print:]]'
fi
read FAKE

echo "---";
echo "Saving the listing of non-local IPs from the trace to:"
echo "    $dump.non-local-hosts-ls-1"
echo "(takes time for huge traces)"
echo "---";
# the below would contain also OpenDNS that i use, also best exempted from
# analysis (or?):
paste con-ip_column_1 con-ip_column_3 | grep -Ev \
	'0\.0\.0\.0|224\.0\.0\.1|255\.255\.255\.255|127\.0\.0\.1' \
	| sed 's/192.168.1.1\t//' | sed 's/\t192.168.1.1//' \
	| sed 's/192.168.1.2\t//' | sed 's/\t192.168.1.2//' \
	| sed 's/192.168.1.4\t//' | sed 's/\t192.168.1.4//' \
	| grep -E '[[:print:]]' \
	> $dump.non-local-hosts-ls-1 |& tee -a $tHostsConvLog
echo
ls -l $dump.non-local-hosts-ls-1 |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
rm con-ip_column_1 con-ip_column_3
echo
echo "At this stage, you can manually edit $dump.non-local-hosts-ls-1"
echo "to add or delete some entries, if you know what you are doing."
read FAKE
echo "This will be the first run, so you get some measure on the"
echo "conversations, and can decide which one to analyze further"
echo "in the second run."
echo
echo "Second run (if you choose it) will have options on each item."
echo
echo "First run now..."
#echo \$dump.\$ext: $dump.$ext
read FAKE
# To me, having the option:
# nameres.network_name: TRUE (or nameres.network_name: TRUE)
# in ~/.wireshark/preferences
# is just not good either of those, and is just not complete information. And
# there's no way, at this time, to get it both displayed in Wireshark, nor with
# some Tshark oneliner, IIUC. So I wrote this loop below.
# Also, legend ought to be inserted every time, except for people with huge
# monitors and speedy eye pupils.

for j in $(cat $dump.non-local-hosts-ls-1); do
	grep $j $dump.hosts
	read FAKE
	cat $dump.conv-ip | head -5 | tail -2
	grep $j $dump.conv-ip
	echo "---"
	echo
	read FAKE
done
# And those nameres.network_name both-hostname-and-IP info you can choose to
# write out to the log. Important piece of the log, so it is delimited by (God,
# I'm not good at all at ascii art! I'll borrow from: Jonathan Racicot's ascii
# art lines from his GPL licensed program NetMinecraft):
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
echo "Write the above listing of conversations by host and by IP to the log?"
echo -n "1 for do write write to the log, 0 for do not write to the log: "
read write_host_ip_conv
if [ "$write_host_ip_conv" == "1" ];then
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
	for j in $(cat $dump.non-local-hosts-ls-1); do
		grep $j $dump.hosts >> $tHostsConvLog
		#read FAKE
		cat $dump.conv-ip | head -5 | tail -2 >> $tHostsConvLog
		grep $j $dump.conv-ip >> $tHostsConvLog
		echo "---" >> $tHostsConvLog
		echo >> $tHostsConvLog
		#read FAKE
	done
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
fi	
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
echo "Do the second run?"
ask
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
		ask
		if [ "$?" == 0 ]; then
			echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext \
				-Y \"(ip.addr==$j)\" -w ${dump}_${j}.$ext" | sed 's/\t//g' | sed 's/  / /g' \
				| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
			tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext \
				-Y "(ip.addr==$j)" -w ${dump}_${j}.$ext
			echo
			ls -l ${dump}_${j}.$ext |& tee -a $tHostsConvLog
			echo |& tee -a $tHostsConvLog
			echo
			echo "Run tshark-http-uri.sh on:"
			echo "${dump}_${j}.$ext"
			echo "(the newly created)?"
			ask
			if [ "$?" == 0 ]; then
				new_dump=${dump}_${j}
				#echo \$new_dump: $new_dump
				echo "tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext"  \
					| sed 's/\t/ /g' | sed 's/  / /g' \
					| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
				tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext
				ls -l ${new_dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
				echo |& tee -a $tHostsConvLog
			fi
			echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
			echo "${new_dump}.$ext"
			decline
			if [ -e "${dump}_FILTER.ls-1" ]; then
				# The hardwired name for the filter file is used promptly: 
				filter_file=${new_dump}_FILTER.ls-1
				echo
				echo "Will try to use $filter_file."
				echo
			else
				echo "If you have prepared a file with one filter string per line"
				echo "to run on:"
				echo "$new_dump.$ext"
				echo "type/paste here that filename, if it is in the current dir,"
				# no ~ expansion; how do you do that?
				echo "or type/paste here the full path (no ~ expansion) if it is not."
				echo -n "(It must be readable by user "; echo -n $(whoami); echo -n "): "
				read filter_file
			fi
			while [ "$?" == "0" ]; do
				if [ ! -e "$filter_file" ]; then
					echo
					echo "There's no such file by the name that you gave, Tuxian!"
					echo
					break
				fi
				for the_filter in $(cat $filter_file); do
					echo
					echo "\$the_filter: \"$the_filter\""
					echo " ^^^^^^^^^^^"
					echo
					echo "and the command interactively programmed to run next is:"
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$new_dump.$ext -V -Y \"$the_filter\"" \
						| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
						| sed 's/  / /g'
					# Remove these two lines if you're editing this to run non-interactively
					echo "Hit Enter"
					read FAKE
					tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						$new_dump.$ext -V -Y $the_filter
					echo "You now want to save that stdout"
					echo " to file: ${new_dump}_${the_filter}.txt"
					echo "Was there no output (or tshark complaining"
					echo "it wasn't a field or protocol name)? Reply \"n\"!"
					ask
					if [ "$?" == 0 ]; then
						echo
						echo "\$the_filter: \"$the_filter\""
						echo " ^^^^^^^^^^^"
						echo
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$new_dump.$ext -V -Y \"$the_filter\" \
							> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
						#tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						#	$new_dump.$ext -V -Y "$the_filter" | sed 's/\t/ /g' \
						#	| sed 's/  / /g' \
						#	| sed 's/  / /g' | sed 's/  / /g' \
						#	> ${new_dump}_${the_filter}.txt
						# Another no go. Can't do the above when filter-infixed filename
						# has a funny name. Can do the below. In 4 places in the script.
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$new_dump.$ext -V -Y \"$the_filter\" \
							> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' > CMD
						chmod 755 CMD ; ./CMD
						echo
						echo "More patience might be needed again..."
						echo "I (currently) don't know how to exit the while loop below."
						echo
						echo "Gentle user, if you are stuck at this point with staying"
						echo "inside this loop below because the file keeps at size 0,"
						echo "pls. issue (in another terminal)"
						echo "this command to get out of it: "
						echo
						echo "echo \" \" > ${new_dump}_${the_filter}.txt"
						echo
						echo "if the command: "
						tail -1 $tHostsConvLog | sed 's/\t//g' | sed 's/  / /' | \
							sed 's/  / /' | sed 's/  / /'
						echo "has completed!"
						echo
						while [ ! -s "${new_dump}_${the_filter}.txt" ] ; do
							sleep 5; echo -n "+5s "
						done
						ls -l ${new_dump}_${the_filter}.txt |& tee -a $tHostsConvLog
						echo |& tee -a $tHostsConvLog
						echo
						echo "---"
						echo
					fi
				done
				break
			done
			echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
			echo "${new_dump}.$ext"
			decline
			while [ "$?" == "0" ]; do
				echo "Give filter (see above in the script"
				echo "for tips) to run on"
				echo -n "$new_dump.$ext : "
				read the_filter
				tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
					$new_dump.$ext -V -Y "$the_filter" \
					| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
					| sed 's/  / /g'
				echo "You now want to save that stdout"
				echo " to file: ${new_dump}_${the_filter}.txt"
				ask
				if [ "$?" == 0 ]; then
					echo "\$?: $? ";
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$new_dump.$ext -V -Y \"$the_filter\" \
						> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
						| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
					#tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
					#	$new_dump.$ext -V -Y "$the_filter"  | sed 's/\t/ /g' \
					#	| sed 's/  / /g' | sed 's/  / /g' | sed 's/  / /g'\
					#	> ${new_dump}_${the_filter}.txt
					# Another no go. Can't do the above when filter-infixed filename
					# has a funny name. Can do the below. In 4 places in the script.
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$new_dump.$ext -V -Y \"$the_filter\" \
						> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
						| sed 's/  / /g' | sed 's/  / /g' > CMD
					chmod 755 CMD ; ./CMD
					echo
					ls -l ${new_dump}_${the_filter}.txt |& tee -a $tHostsConvLog
					echo |& tee -a $tHostsConvLog
					echo
					echo "---"
					echo
				fi
				echo "---"
				echo -n "Hit Enter to accept or \"n\" or \"N\" to decline the filtering on: "
				echo "${new_dump}.$ext"
				decline
				if [ "$?" == 1 ]; then
					break
				fi
			done
		fi
	done
fi
echo "We seem to have exhausted all the loops at this stage, as we are out of"
echo "any now."
echo "Clearly the script is unfinished at this time."
echo "Updated version of this script may appear in the future at:"
echo "https://github.com/miroR/ or if not, try and see:"
echo "if there are any news at http://www.CroatiaFidelis.hr/foss/ ."
