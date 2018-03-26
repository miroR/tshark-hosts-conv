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
# traffic decrypted, with the option, which for the PCAP of a sample page I
# give below would be:
#
# wireshark -o "ssl.keylog_file: dump_161203_1629_g0n_SSLKEYLOGFILE.txt" \
#	 dump_161203_1629_g0n.pcap
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
  echo "Usage: $0 -r <PCAP file> -k <ssl.keylog_file>"
  echo ""
  echo "	-r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo "		for particular uses though"
  echo "	-k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo "		the sessions in the PCAP. If those have been logged in the file"
  echo "		designated by the \$SSLKEYLOGFILE environment variable (usually"
  echo "		set to value such as: /home/$USER/.sslkey.log) used during"
  echo "		Firefox, Pale Moon or some other NSS supporting browser's run,"
  echo "		all properly set, then you don't need to set this flag"
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
		echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
		# This is one of those: an echo-checkup on a variable (above) and its
		# fake read (below). If uncommented, they only wait for you to hit
		# Enter to go on, or hit Ctrl-C and bail out.
		#read FAKE
		;;
	k)  KEYLOGFILE=$OPTARG
		echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
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

# Files can have a few dots, this is how I'll take the last as separator.
num_dots=$(echo $PCAP_FILE|sed 's/\./\n/g'| wc -l)
num_dots_min_1=$(echo $num_dots - 1 | bc)
#echo \$num_dots: $num_dots
#echo \$num_dots_min_1: $num_dots_min_1
ext=$(echo $PCAP_FILE|cut -d. -f $num_dots)
#echo \$ext: $ext
#read FAKE
echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/"
dump=$(echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/")
echo \$dump: $dump
echo \$ext: $ext
#read FAKE
filename=$dump.$ext
echo \$filename: $filename
#read FAKE

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
echo "They have long been, and that state may last for more, in a poor user's"
echo "debugging state. which means lots of "#read FAKE" lines that wait for me"
echo "to keep comparing the lines in the script to what they do, while they do"
echo "their work... Bear with me, pls.!"
echo
echo "Freely (un)comment (out) the \"{#}read FAKE\" which is four lines below"
echo "here, {to}/{if after you} check the script {you feel that you wish to"
echo "use it more}."
echo "#                       *       *   * *   *       *                    #"
echo "########################################################################"
echo
#read FAKE

# The name is hardwired by the name of the stamp in the trace (I'm not changing
# that anymore, I don't think, not any time soon, at least), used in the few of
# my scripts around uncenz. In this directory that $0 (this script) is run, the
# trace is called dump_<time-stamp>_<...>.pcap where <...> is three first
# letters of the hostname (look up the uncenz set for how the name is made).
# So:
#dump=$(ls -1 *.pcap|sed 's/\.pcap//') # very likely gives that same as
                                       # 'dump=...' further above
basename $(realpath $(pwd))
# The below may be a safeguard... On reruns, which means more than one log, it
# should still work.
dump_bis=$(basename $(realpath $(pwd))|sed 's/_tHostsConv//')
if [ "$dump" == "dump_bis" ]; then
	dump=$dump
else
	dump=$dump_bis
fi
echo \$dump: $dump
#read FAKE
# Giving it a timestamp of its own so $0 can be rerun, if needed, and get a new
# log.
tHostsConvLog=${dump}_tHostsConv_$(date +%y%m%d_%H%M%S).log
export tHostsConvLog
touch $tHostsConvLog
echo "I have created the file $tHostsConvLog, and you can open it"
echo "in another terminal such as with a command: "
echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "                                                             "
echo " tail -f $tHostsConvLog"
echo "                                                 <<===== |   "
echo " ^^^^^^^^^^^^^^^^^^^^^^^^^^^                <<========== |   "
echo " |||||||||||||||||||||||||||                                 "
echo "                                                             "
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
sleep 3
echo
echo "and you might find it useful for further analysis/discussion/other later."
echo "# Commands as used by the script, written out for educational purposes." \
	 |& tee -a $tHostsConvLog

function ask()	# this function borrowed from "Advanced BASH Scripting Guide"
				# (a free book) by Mendel Cooper
{
	echo -n "$@" '[y/[n]] ' ; read ans
	case "$ans" in
		y*|Y*) return 0 ;;
		*) return 1 ;;
	esac
}

# If you want to get this script to perfom default actions in non-interactive runs
# just create, in the dir with PCAPs where you will run it, an empty file
# .tshark-hosts-conv_non-interactive. Or

if [ ! -e ".tshark-hosts-conv_non-interactive" ]; then
	echo "Do you want this script to perfom default actions in"
	echo "non-interactive runs on all the PCAPs in this dir?"
	echo "If you change your mind later, delete the empty file:"
	echo ".tshark-hosts-conv_non-interactive"
	echo "that replying y/Y will create."
	ask
	if [ "$?" == 0 ]; then
		touch .tshark-hosts-conv_non-interactive
	fi
fi

if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	rm -f no_overwrite_hosts_conv-ip
else
	rm -f no_overwrite_hosts_conv-ip
	if [ -e "$dump.hosts" ] && [ -e "$dump.conv-ip" ]; then
		echo ls -l \$dump.hosts
		ls -l $dump.hosts
		echo ls -l \$dump.conv-ip
		ls -l $dump.conv-ip
		echo "already exist, KEEP them?" # only overwrite both, or leave alone both
		ask
		if [ "$?" == 0 ]; then touch no_overwrite_hosts_conv-ip
		#ls -l no_overwrite_hosts_conv-ip
		#read FAKE
		fi
	fi
fi

if [ ! -e "no_overwrite_hosts_conv-ip" ]; then
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
	echo "The script has not been programmed to wait. It's your (the human)"
	echo "decision to wait here for them to be created, and then get a useable"
	echo "listing of conversations by their IPs (IPv4 only at this time)"
	echo 
	echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -qz hosts \
		>  $dump.hosts" | sed 's/\t//g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog &&
	tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz hosts \
		>  $dump.hosts && ls -l $dump.hosts | sed 's/\t//g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog \
		&& echo "(but the" |& tee -a $tHostsConvLog \
		&& echo "$dump.hosts" |& tee -a $tHostsConvLog \
		&& echo "needs to be reordered yet)" && echo |& tee -a $tHostsConvLog &
		tshark_hosts_pid=$! ; echo \$tshark_hosts_pid: $tshark_hosts_pid
		#read FAKE
	# if "nameres.network_name: TRUE" set in /home/$USER/.config/wireshark/preferences,
	# it needs correcting here, else some results will be incorrect
	echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -o \"nameres.network_name: FALSE\" -r $dump.$ext -qz conv,ip \
		>  $dump.conv-ip" | sed 's/\t//g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog &&
	tshark -o "ssl.keylog_file: $KEYLOGFILE" -o "nameres.network_name: FALSE" -r $dump.$ext -qz conv,ip \
		>  $dump.conv-ip \
		&& ls -l $dump.conv-ip |& tee -a $tHostsConvLog \
		&& echo "(but the" |& tee -a $tHostsConvLog \
		&& echo "$dump.conv-ip" |& tee -a $tHostsConvLog \
		&& echo "needs to be reordered yet)" |& tee -a $tHostsConvLog \
		&& echo |& tee -a $tHostsConvLog &
		tshark_conv_ip_pid=$! ; echo \$tshark_conv_ip_pid: $tshark_conv_ip_pid
		#read FAKE
	# This is why it needs to be reordered: It ought to be sorted numerically
	# and not all jumbled as, currently, by Wireshark default. Numerically, so that
	# visually, in a quick glance, you easily find the IP4 address you search, being
	# all IP4 addresses in consecutive order. IP4 only, IP6 remain untouched, yet.
	echo "If the $dump.hosts has been created and is not empty"
	echo "then pls. hit Enter and the order in:"
	echo "$dump.hosts"
	echo "will be fixed to be in consecutive numerical order."
	#read FAKE
	# just " grep $tshark_hosts_pid " could match other non-related stuff, not
	# allowing $0 to go on, rarely, but it happened to me
	while ( ps aux | grep "\<$tshark_hosts_pid\>" | grep tshark | grep -v grep ) || \
		( ps aux | grep "\<$tshark_conv_ip_pid\>" | grep tshark | grep -v grep ) ; do
	sleep 1; echo "tshark process $tshark_hosts_pid or $tshark_conv_ip_pid still running"
	done
	#read FAKE
	rm -f $dump.hosts-all-jumbled;
	mv -v $dump.hosts $dump.hosts-all-jumbled
	rm -f $dump.hosts-1top; rm -f $dump.hosts-3btm; rm -f $dump.hosts-2body;
	raw_lines=$(cat $dump.hosts-all-jumbled | wc -l)
	echo \$raw_lines: $raw_lines
	clean_lines=$(cat $dump.hosts-all-jumbled | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
	echo \$clean_lines: $clean_lines
	raw_lines_sans_top=$(echo $raw_lines-4|bc)
	echo \$raw_lines_sans_top: $raw_lines_sans_top
	ip6lines=$(echo $raw_lines_sans_top-$clean_lines|bc)
	#read FAKE
	cat $dump.hosts-all-jumbled | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -n  > $dump.hosts-2body
	head -4 $dump.hosts-all-jumbled > $dump.hosts-1top
	tail -$ip6lines $dump.hosts-all-jumbled > $dump.hosts-3btm
	cat $dump.hosts-1top $dump.hosts-2body $dump.hosts-3btm > $dump.hosts
	ls -l $dump.hosts |& tee -a $tHostsConvLog
	# Checking:
	echo cat \$dump.hosts-all-jumbled \| wc -l
	cat $dump.hosts-all-jumbled | wc -l
	echo cat \$dump.hosts \| wc -l
	cat $dump.hosts | wc -l
	#read FAKE
	# This is why it needs to be reordered: It ought to be sorted by "Relative start"
	# which is not the Wireshark default. By "Total" "Bytes" loses all relations
	# btwn conversations.
	echo "If the $dump.conv-ip has been created and is not empty"
	echo "then pls. hit Enter and the order in:"
	echo "$dump.conv-ip"
	echo "will be fixed to be by \"Relative Start\"."
	#read FAKE
	if [ -e "$dump.conv-ip-by-bytes" ]; then rm -v $dump.conv-ip-by-bytes ; fi
	mv -v $dump.conv-ip $dump.conv-ip-by-bytes
	rm -f $dump.conv-ip-1top; rm -f $dump.conv-ip-3btm; rm -f $dump.conv-ip-2body;
	raw_lines=$(cat $dump.conv-ip-by-bytes | wc -l)
	echo \$raw_lines: $raw_lines
	raw_lines_sans_btm=$(echo $raw_lines-1|bc)
	echo \$raw_lines_sans_btm: $raw_lines_sans_btm
	clean_lines=$(echo $raw_lines_sans_btm-5|bc)
	echo \$clean_lines: $clean_lines
	#read FAKE
	for i in $(cat $dump.conv-ip-by-bytes | head -$raw_lines_sans_btm | tail -$clean_lines | awk '{ print $10 }' | sort -n); do
		grep $i $dump.conv-ip-by-bytes >> $dump.conv-ip-2body
	done
	head -5 $dump.conv-ip-by-bytes > $dump.conv-ip-1top
	tail -1 $dump.conv-ip-by-bytes > $dump.conv-ip-3btm
	cat $dump.conv-ip-1top $dump.conv-ip-2body $dump.conv-ip-3btm > $dump.conv-ip
	ls -l $dump.conv-ip |& tee -a $tHostsConvLog
	#read FAKE
	# This is very approximative. It will not find  that $dump.hosts is empty
	# in small PCAPs on not too powerful machines
	sleep 2 && if [ -s "$dump.hosts" ]; then
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
	rm -f $dump.hosts-all-jumbled;
	rm -f $dump.hosts-1top; rm -f $dump.hosts-3btm; rm -f $dump.hosts-2body;
	rm -f $dump.conv-ip-by-bytes;
	rm -f $dump.conv-ip-1top; rm -f $dump.conv-ip-3btm; rm -f $dump.conv-ip-2body;
else
	echo "$dump.hosts"
	echo "and"
	echo "$dump.conv-ip"
	echo "(likely) left from previous run:" |& tee -a $tHostsConvLog
	# And if it needs to be reordered, please rerun, and overwrite it.
	ls -l $dump.hosts |& tee -a $tHostsConvLog
	# And if it needs to be reordered, please rerun, and overwrite it.
	ls -l $dump.conv-ip |& tee -a $tHostsConvLog
fi
rm -f no_overwrite_hosts_conv-ip

if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	rm -f no_overwrite_POST
else
	rm -f no_overwrite_POST
	if [ -e "$dump.POST" ]; then
		echo ls -l \$dump.POST
		ls -l $dump.POST
		echo "already exists, keep it?"
		ask
		if [ "$?" == 0 ]; then touch no_overwrite_POST
		#ls -l no_overwrite_POST
		#read FAKE
		fi
	fi
fi

# Often it's logins and passwords that are of interest in traces, and typically
# they live in POST'ed data. So this is the next thing I'll do.
if [ ! -e "no_overwrite_POST" ]; then
	sleep 4 && echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -V -Y \
		'http.request.method==POST'" \> $dump.POST | sed 's/\t//g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' \
		|& tee -a $tHostsConvLog &
	sleep 5 && tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -V -Y \
		'http.request.method==POST' > $dump.POST \
		| sed 's/  / /g' | sed 's/  / /g' \
		| sed 's/\t//g' | sed 's/  / /g' && ls -l $dump.POST |& tee -a $tHostsConvLog \
		&& echo |& tee -a $tHostsConvLog &
	sleep 5 && echo "... -Y http.request.method==POST started in background..." &
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
else
		echo "$dump.POST"
		echo "(likely) left from previous run:" |& tee -a $tHostsConvLog
		ls -l $dump.POST |& tee -a $tHostsConvLog
fi
rm -f no_overwrite_POST

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

if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	rm -f no_overwrite_request-full_uri
	echo "tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext"  \
		| sed 's/\t/ /g' | sed 's/  / /g' \
		| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
	tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext |& tee -a $tHostsConvLog
	ls -l ${dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
	echo |& tee -a $tHostsConvLog
else
	rm -f no_overwrite_request-full_uri
	if [ ! -e "no_overwrite_request-full_uri" ]; then
		sleep 3 && echo "NOT run tshark-http-uri.sh on the whole trace? (Enter == do run!)"
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
	else
			echo "${dump}-frame-http-request-full_uri.txt"
			echo "(likely) left from previous run:" |& tee -a $tHostsConvLog
			ls -l ${dump}-frame-http-request-full_uri.txt |& tee -a $tHostsConvLog
	fi
	rm -f no_overwrite_request-full_uri
fi

echo
echo "           =   -   =   -   =   -   =   -   =   -   = " 
echo "The HELP (next) should become optional reading... in some future version."
echo "           =   -   =   -   =   -   =   -   =   -   = " 
echo
echo "Move on through it by hitting Enter"
# You could try uncommenting the "#read FAKE"'s below if you are a struggling
# beginner
echo -n "2 " ; sleep 1 ; echo "1 " ; sleep 1
#read FAKE
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "                   || || || "
echo "                   || || || "
echo "                   \/ \/ \/ "
echo
echo "The defaults for some commands is run only if chosen to, and mere"
echo "hitting Enter or setting the script to non-interactive does not run"
echo "those. Other commands are run by default and you only get the option"
echo "not to run them if you are in interactive mode."
echo "I will try and make non-interactive mode to be a good initial quick"
echo "examination of a PCAP, after perusing of which output, in the next"
echo "run, you can reuse what you have previously done."
# But there are more settings that would need to be set... There may be
# non-default runs that one would wish the other way in non-interactive, and
# defaults to be left out... Will cater for more options n the future.
echo ""
#read FAKE
echo "The quick initial non-interactive run is suitable for, say, preparing a"
echo "list of filters (which can be listed in a filtering file) to run on"
echo "the PCAP, and more."
echo ""
echo "Because most of the hard work of this script:"
echo "$0"
echo "is about running filtering commands with Tshark, such as:"
echo "tshark -r $dump.$ext -V -Y \"\$the_filter\""
echo
#read FAKE
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
#read FAKE
echo "The script (in interactive only) first looks for hardwired filename, in"
echo "this run it is" 
echo "${dump}_FILTER.ls-1"
echo
echo "Then you are offered to give the filename of the list of filters" 
echo
echo "Lastly, you can input filters one by one." 
echo
#read FAKE
echo "First the tshark command with the filter iteration is run,"
echo "second, you are given the option to save it to a file,"
echo "which will have the filter string infixed in its name, in another run."
echo
#read FAKE
if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	echo "Filtering is done in non-interactive mode only on prepared \$filter_file's"
	echo "(and, of course, the results are saved in files"
	echo "named by the respective filters)."
		if [ -e "${dump}_FILTER.ls-1" ]; then
			# The hardwired name for the filter file is used promptly:
			filter_file=${dump}_FILTER.ls-1
			echo
			echo "Will try to use $filter_file."
			for the_filter in $(cat $filter_file); do
				echo
				echo "\$the_filter: \"$the_filter\""
				echo " ^^^^^^^^^^^"
				echo
				echo "and the command non-interactively programmed to run next is:"
				echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
					$dump.$ext -V -Y \"$the_filter\"" \
					| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
					| sed 's/  / /g'
				tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
					$dump.$ext -V -Y "$the_filter" \
					| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
					| sed 's/  / /g'
				filter_result=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
					$dump.$ext -V -Y "$the_filter")
				echo \$filter_result: $filter_result
				#read FAKE
				if [ -n "$filter_result" ]; then echo not null ; fi
				if [ ! -n "$filter_result" ]; then echo null ; fi
				#read FAKE
				if [ -n "$filter_result" ]; then
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$dump.$ext -V -Y \"$the_filter\" \
						> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
						| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$dump.$ext -V -Y \"$the_filter\" \
						> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
						| sed 's/  / /g' | sed 's/  / /g' > CMD
					chmod 755 CMD ; ./CMD
					cp -iav CMD CMD_$(date +%y%m%d_%H%M%S)
					echo
					
				fi
			done
		else
			echo "No ${dump}_FILTER.ls-1 found, not filtering on $dump.$ext"
		fi
else
	echo -n "Do filtering (y/Y) on: "
	echo "$dump.$ext ?"
	echo "(anything else will decline filtering)"
	ask
	if [ "$?" == 0 ]; then
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
				#read FAKE
				tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
					$dump.$ext -V -Y "$the_filter" \
					| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
					| sed 's/  / /g'
				echo "You now want to save that stdout"
				echo " to file:  ${dump}_${the_filter}.txt"
				echo "Was there no output (or tshark complaining"
				echo "it wasn't a field or protocol name)? Reply \"n\"!"
				echo "NOTE: Even if you reply 'y', if the result would be"
				echo "      empty, this won't be saving to any file."
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
					# double ":", and there are bound to be other).
					# Can do the below. In 4 places in this script.
					filter_result=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						$dump.$ext -V -Y "$the_filter")
					echo \$filter_result: $filter_result
					#read FAKE
					if [ -n "$filter_result" ]; then echo not null ; fi
					if [ ! -n "$filter_result" ]; then echo null ; fi
					#read FAKE
					echo
					if [ -n "$filter_result" ]; then
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$dump.$ext -V -Y \"$the_filter\" \
							> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$dump.$ext -V -Y \"$the_filter\" \
							> ${dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' > CMD
						chmod 755 CMD ; ./CMD
						cp -iav CMD CMD_$(date +%y%m%d_%H%M%S)
						echo
						
					fi
					echo "---"
				fi
			done
			break
		done
		echo "(More) filters if desired..."
		echo "Or give empty string (just hit Enter),"
		echo "and you'll be out after two short interactions more."
		# Haven't yet fixed a few snags like this one... But it works.
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
				echo -n "Enter y/Y to accept or \"n\" or \"N\" to decline the filtering on: "
				echo "${dump}.$ext"
				ask
			done
		fi
	else
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" |& tee -a $tHostsConvLog
		echo "Any filtering skipped by user's choice." |& tee -a $tHostsConvLog
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" |& tee -a $tHostsConvLog
	echo Continuing... ; echo -n "2 " ; sleep 1 ;
	echo "1 " ; sleep 1
	fi
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

cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $1 }' > conv-ip_column_1
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
	| awk '{ print $3 }'  > conv-ip_column_3
#read FAKE

# I'm not really a programmer... If you want to use this script for yourself,
# get your own listing of local IP's and substitute them for the ones below (I
# have the Chinese ZTE ZXDSL 931VII censor-ready router, used, as far as
# Europe, in mainly former-Communist countries, I never see my temp public IP
# in my traces, but connect to the internet via router's local, say,
# 192.168.1.4/24 or some other of the range 192.168.1.0/24 that it assigns to
# me).

if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	echo "an extra pre-listing of hosts-[to-be-]worked skipped in non-interactive"
else
	# Good to be able to skip this for huge traces, and go straight to saving the
	# listing
	echo "List the hosts-[to-be-]worked (all with which any conversations were"
	echo "traced) one per line ?"
	echo "A huge trace (and the machine not poweful)?"
	echo "if you don't reply \"y\", you will have one loop on the trace less to go,"
	echo "and later the hosts-[to-be-]worked list will anyway be created)"
	ask
	if [ "$?" == 0 ]; then
		echo "---";
		echo "This is the listing of hosts-[to-be-]worked IPs"
		echo "---";
		paste conv-ip_column_1 conv-ip_column_3 \
			| sed 's/192\.168\.1\..*\t//' | sed 's/\t192\.168\.1\..*//' \
			| sed "s/192\.168\.1\..*$//" \
			| sed 's/\([1-9][0-9]\{,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' \
			| grep -E '[[:print:]]'
	fi
fi
#read FAKE

echo "---";
echo "Saving the listing of hosts-[to-be-]worked IPs from the trace to:"
echo "	$dump.hosts-worked-ls-1"
echo "(takes time for huge traces)"
echo "---";

paste conv-ip_column_1 conv-ip_column_3 \
	| sed 's/192\.168\.1\..*\t//' | sed 's/\t192\.168\.1\..*//' \
	| sed "s/192\.168\.1\..*$//" \
	| sed 's/\([1-9][0-9]\{,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' \
	| grep -E '[[:print:]]' \
	> $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
#read FAKE
echo
ls -l $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
rm conv-ip_column_1 conv-ip_column_3
echo
echo "At this stage, you can manually edit $dump.hosts-worked-ls-1"
echo "to add or delete some entries, if you know what you are doing."
#read FAKE
echo "This will be the first run, so you get some measure on the"
echo "conversations, and can decide which one to analyze further"
echo "in the second run."
echo
echo "Second run (if you choose it) will have options on each item."
echo
echo "First run now..."

for j in $(cat $dump.hosts-worked-ls-1); do
	grep $j $dump.hosts
	#read FAKE
	cat $dump.conv-ip | head -5 | tail -2
	grep $j $dump.conv-ip
	echo "---"
	echo
	#read FAKE
done
# And those nameres.network_name both-hostname-and-IP info you can choose to
# write out to the log. Important piece of the log, so it is delimited by (God,
# I'm not good at all at ascii art! I'll borrow from: Jonathan Racicot's ascii
# art lines from his GPL licensed program NetMinecraft):
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	echo "it's good to have the listing of conversations by host and by IP"
	echo "set default for non-interactive mode"
	# but I'm duplicating :-( the code (for now)
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
	for j in $(cat $dump.hosts-worked-ls-1); do
	echo \$j: $j
		# needs to be checked for duplicate finds
		# as well as for empty finds
		#grep $j $dump.hosts
		#grep $j $dump.hosts|wc -l
		#echo grep \$j \$dump.hosts \| awk \'{ print \$1 }\'
		#grep $j $dump.hosts | awk '{ print $1 }'
		#read FAKE
		if [ "$(grep $j $dump.hosts|wc -l)" == "1" ] ;then
			#grep $j $dump.hosts
			grep $j $dump.hosts >> $tHostsConvLog
			#read FAKE
		else
			#echo "The case is:"
			#echo grep \$j \$dump.hosts\|wc -l
			#grep $j $dump.hosts|wc -l
			#read FAKE
			#echo grep \$j \$dump.hosts \| awk \'{ print \$1 }\'
			#read FAKE
			#grep $j $dump.hosts | awk '{ print $1 }'
			#read FAKE
			#echo ls -l \$dump.hosts
			#ls -l $dump.hosts
			#read FAKE
			if grep $j $dump.hosts ; then
				# Two runs to get the false finds out needed here.
				for instance in $(grep $j $dump.hosts | awk '{ print $1 }'); do
					echo \$instance: $instance
					#read FAKE
					if grep $instance $dump.conv-ip ; then
						echo grep \$instance \$dump.hosts
						grep $instance $dump.hosts
						# This instance left in the $dump.hosts.
						#read FAKE
					else
						echo "The $instance is false duplicate"
						# (I'm really not sure if this suffices... It does if the first
						# instance is false duplicate... More testing needed...)
						# I'll make a temporary $dump.hosts_TEMP without such
						# But until this while loop is done, I have to be using it... So:
						cp -iav $dump.hosts $dump.hosts_ORIG
						grep -v $instance $dump.hosts > $dump.hosts_TEMP
						mv -iv $dump.hosts_TEMP $dump.hosts
						#read FAKE
					fi
				done
			else
				echo "NOTICE-could-not-be-resolved-NOTICE" |& tee -a $tHostsConvLog
			fi
			if grep $j $dump.hosts ; then
				# Two runs to get the false finds out needed here.
				for instance in $(grep $j $dump.hosts | awk '{ print $1 }'); do
					echo \$instance: $instance
					#read FAKE
					if grep $instance $dump.conv-ip ; then
						echo grep \$instance \$dump.hosts
						grep $instance $dump.hosts
						grep $instance $dump.hosts >> $tHostsConvLog
						#read FAKE
					else
						echo "The $instance is false duplicate"
						# (I'm really not sure if this suffices... It does if the first
						# instance is false duplicate... More testing needed...)
						# I'll make a temporary $dump.hosts_TEMP without such
						# But until this while loop is done, I have to be using it... So:
						cp -iav $dump.hosts $dump.hosts_ORIG
						grep -v $instance $dump.hosts > $dump.hosts_TEMP
						mv -iv $dump.hosts_TEMP $dump.hosts
						#read FAKE
					fi
				done
			fi
			if [ -e "$dump.hosts_ORIG" ]; then \
				mv -iv $dump.hosts_ORIG $dump.hosts ; fi
		fi
		
		cat $dump.conv-ip | head -5 | tail -2 >> $tHostsConvLog
		grep $j $dump.conv-ip >> $tHostsConvLog
		echo "---" >> $tHostsConvLog
		echo >> $tHostsConvLog
	done
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
else
	echo "In the main part of the first run, all is recorded in the logs."
	echo "Write (duplicates will be discarded, non-resolved marked such) the listing"
	echo "of conversations by host and by IP to the log?"
	ask
	if [ "$?" == "0" ]; then
		echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
		for j in $(cat $dump.hosts-worked-ls-1); do
		echo \$j: $j
			# needs to be checked for duplicate finds
			# as well as for empty finds
			#grep $j $dump.hosts
			#grep $j $dump.hosts|wc -l
			#echo grep \$j \$dump.hosts \| awk \'{ print \$1 }\'
			#grep $j $dump.hosts | awk '{ print $1 }'
			#read FAKE
			if [ "$(grep $j $dump.hosts|wc -l)" == "1" ] ;then
				#grep $j $dump.hosts
				grep $j $dump.hosts >> $tHostsConvLog
				#read FAKE
			else
				#echo "The case is:"
				#echo grep \$j \$dump.hosts\|wc -l
				#grep $j $dump.hosts|wc -l
				#read FAKE
				#echo grep \$j \$dump.hosts \| awk \'{ print \$1 }\'
				#read FAKE
				#grep $j $dump.hosts | awk '{ print $1 }'
				#read FAKE
				#echo ls -l \$dump.hosts
				#ls -l $dump.hosts
				#read FAKE
				if grep $j $dump.hosts ; then
					# Two runs to get the false finds out needed here.
					for instance in $(grep $j $dump.hosts | awk '{ print $1 }'); do
						echo \$instance: $instance
						#read FAKE
						if grep $instance $dump.conv-ip ; then
							echo grep \$instance \$dump.hosts
							grep $instance $dump.hosts
							# This instance left in the $dump.hosts.
							#read FAKE
						else
							echo "The $instance is false duplicate"
							# (I'm really not sure if this suffices... It does if the first
							# instance is false duplicate... More testing needed...)
							# I'll make a temporary $dump.hosts_TEMP without such
							# But until this while loop is done, I have to be using it... So:
							cp -iav $dump.hosts $dump.hosts_ORIG
							grep -v $instance $dump.hosts > $dump.hosts_TEMP
							mv -iv $dump.hosts_TEMP $dump.hosts
							#read FAKE
						fi
					done
				else
					echo "NOTICE-could-not-be-resolved-NOTICE" |& tee -a $tHostsConvLog
				fi
				if grep $j $dump.hosts ; then
					# Two runs to get the false finds out needed here.
					for instance in $(grep $j $dump.hosts | awk '{ print $1 }'); do
						echo \$instance: $instance
						#read FAKE
						if grep $instance $dump.conv-ip ; then
							echo grep \$instance \$dump.hosts
							grep $instance $dump.hosts
							grep $instance $dump.hosts >> $tHostsConvLog
							#read FAKE
						else
							echo "The $instance is false duplicate"
							# (I'm really not sure if this suffices... It does if the first
							# instance is false duplicate... More testing needed...)
							# I'll make a temporary $dump.hosts_TEMP without such
							# But until this while loop is done, I have to be using it... So:
							cp -iav $dump.hosts $dump.hosts_ORIG
							grep -v $instance $dump.hosts > $dump.hosts_TEMP
							mv -iv $dump.hosts_TEMP $dump.hosts
							#read FAKE
						fi
					done
				fi
				if [ -e "$dump.hosts_ORIG" ]; then \
					mv -iv $dump.hosts_ORIG $dump.hosts ; fi
			fi
			
			cat $dump.conv-ip | head -5 | tail -2 >> $tHostsConvLog
			grep $j $dump.conv-ip >> $tHostsConvLog
			echo "---" >> $tHostsConvLog
			echo >> $tHostsConvLog
		done
		echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
	fi
fi
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	# the second run is done in non-interactive, each conv saved to separate
	# file and tshark-http-uri.sh run on it
	for j in $(cat $dump.hosts-worked-ls-1); do
		grep $j $dump.hosts ; #read FAKE;
		cat $dump.conv-ip | head -5 | tail -2
		grep $j $dump.conv-ip ;
		echo "The IP: $j"
		#read FAKE
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
		new_dump=${dump}_${j}
		#echo \$new_dump: $new_dump
		echo "tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext"  \
			| sed 's/\t/ /g' | sed 's/  / /g' \
			| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
		tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext
		ls -l ${new_dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
		echo |& tee -a $tHostsConvLog
		echo "Filtering is done in non-interactive mode only on prepared \$filter_file's"
		echo "(and, of course, the results are saved in files"
		echo "named by the respective filters)."
			if [ -e "${new_dump}_FILTER.ls-1" ]; then
				# The hardwired name for the filter file is used promptly:
				filter_file=${new_dump}_FILTER.ls-1
				echo
				echo "Will try to use $filter_file."
				for the_filter in $(cat $filter_file); do
					echo
					echo "\$the_filter: \"$the_filter\""
					echo " ^^^^^^^^^^^"
					echo
					echo "and the command non-interactively programmed to run next is:"
					echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
						$new_dump.$ext -V -Y \"$the_filter\"" \
						| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
						| sed 's/  / /g'
					tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						$new_dump.$ext -V -Y "$the_filter" \
						| sed 's/\t/ /g' | sed 's/  / /g' | sed 's/  / /g' \
						| sed 's/  / /g'
					filter_result=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
						$new_dump.$ext -V -Y "$the_filter")
					echo \$filter_result: $filter_result
					#read FAKE
					if [ -n "$filter_result" ]; then echo not null ; fi
					if [ ! -n "$filter_result" ]; then echo null ; fi
					#read FAKE
					if [ -n "$filter_result" ]; then
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$new_dump.$ext -V -Y \"$the_filter\" \
							> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
						echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
							$new_dump.$ext -V -Y \"$the_filter\" \
							> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
							| sed 's/  / /g' | sed 's/  / /g' > CMD
						chmod 755 CMD ; ./CMD
						cp -iav CMD CMD_$(date +%y%m%d_%H%M%S)
						echo
						
					fi
				done
			else
				echo "No ${new_dump}_FILTER.ls-1 found, not filtering on $new_dump.$ext"
			fi
	done
else
	echo "Do the second run?"
	ask
	if [ "$?" == 0 ]; then
		echo "Second run now... If you don't reply \"y\", no further"
		echo "analysis will be performed for the particular IP."
		# You can simply hit Enter, script will just continue.
		#read FAKE
		for j in $(cat $dump.hosts-worked-ls-1); do
			grep $j $dump.hosts ; #read FAKE;
			cat $dump.conv-ip | head -5 | tail -2
			grep $j $dump.conv-ip ;
			echo "The IP: $j"
			#read FAKE
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
   				new_dump=${dump}_${j}
   				#echo \$new_dump: $new_dump
				if [ "$?" == 0 ]; then
   					echo "tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext"  \
   						| sed 's/\t/ /g' | sed 's/  / /g' \
   						| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
   					tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext
   					ls -l ${new_dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
   					echo |& tee -a $tHostsConvLog
   				fi
   				echo -n "Do filtering (y/Y) on: "
   				echo "${new_dump}.$ext ?"
   				echo "(anything else will decline filtering)"
   				ask
				if [ "$?" == "0" ]; then
					if [ -e "${new_dump}_FILTER.ls-1" ]; then
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
							echo "Hit Enter"
							#read FAKE
							tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
								$new_dump.$ext -V -Y $the_filter
							echo "You now want to save that stdout"
							echo " to file: ${new_dump}_${the_filter}.txt"
							echo "Was there no output (or tshark complaining"
							echo "it wasn't a field or protocol name)? Reply \"n\"!"
							echo "NOTE: Even if you reply 'y', if the result would be"
							echo "      empty, this won't be saving to any file."
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
								filter_result=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r \
									$new_dump.$ext -V -Y "$the_filter")
								echo \$filter_result: $filter_result
								#read FAKE
								if [ -n "$filter_result" ]; then echo not null ; fi
								if [ ! -n "$filter_result" ]; then echo null ; fi
								#read FAKE
								if [ -n "$filter_result" ]; then
									echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
										$new_dump.$ext -V -Y \"$the_filter\" \
										> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
										| sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog
									echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r \
										$new_dump.$ext -V -Y \"$the_filter\" \
										> ${new_dump}_${the_filter}.txt" | sed 's/\t/ /g' | sed 's/  / /g' \
										| sed 's/  / /g' | sed 's/  / /g' > CMD
									chmod 755 CMD ; ./CMD
									cp -iav CMD CMD_$(date +%y%m%d_%H%M%S)
									echo
									
								fi
								echo "---"
							fi
						done
						break
					done
					export new_dump
				fi
				echo -n "Do filtering (y/Y) on: "
				echo "${new_dump}.$ext ?"
				echo "(anything else will decline filtering)"
				ask
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
					echo -n "Do filtering (y/Y) on: "
					echo "${new_dump}.$ext ?"
					echo "(anything else will decline filtering)"
					ask
					if [ "$?" == 1 ]; then
						break
					fi
				done
			fi
		done
	fi
fi
# Cleanup of empty files produced needed here.
for i in $(ls -1); do
	if [ ! -s "$i" ]; then
		ls -l $i |& tee -a $tHostsConvLog
	fi
done
if [ -e ".tshark-hosts-conv_non-interactive" ]; then
	echo "Removing the empty files listed..." |& tee -a $tHostsConvLog
	cat $dump.hosts | grep -v '^#' | grep '[[:print:]]' > $dump.hosts.TMP
	ls -l $dump.hosts $dump.hosts.TMP
	#read FAKE
	if [ ! -s "$dump.hosts.TMP" ]; then
		mv -iv $dump.hosts.TMP $dump.hosts
	else
		rm -v $dump.hosts.TMP
	fi
	for i in $(ls -1); do
		if [ ! -s "$i" ]; then
			rm -v $i |& tee -a $tHostsConvLog
		fi
	done
else
	echo "Remove these empty files listed? (recommended)"
	ask;
	if [ "$?" == 0 ]; then
		# Now first temporarily remove comments from $dump.hosts. If the
		# content is then 0 size, remove $dump.hosts too, else remove the
		# temporary copy
		cat $dump.hosts | grep -v '^#' > $dump.hosts.TMP
		ls -l $dump.hosts $dump.hosts.TMP
		#read FAKE
		if [ ! -s "$dump.hosts.TMP" ]; then
			mv -iv $dump.hosts.TMP $dump.hosts
		else
			rm -v $dump.hosts.TMP
		fi
		for i in $(ls -1); do
			if [ ! -s "$i" ]; then
				rm -v $i |& tee -a $tHostsConvLog
			fi
		done
	fi
fi
sleep 3 # else the returning prompt may confuse the use with an empty echo
# This listing is necessary in case there have been more runs of $0
ls -l ${dump}_*.log      # but should be only one (if there weren't, say, any
                         # crashes during previous run)
#read FAKE
if [ -e "CMD" ]; then
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" |& tee -a $tHostsConvLog
	echo "The filtering commands that were actually run in this session:" |& tee -a $tHostsConvLog
	cat CMD_* |& tee -a $tHostsConvLog ;
	rm -f  CMD*
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" |& tee -a $tHostsConvLog
fi
ls -l $tHostsConvLog     # should list the same one file as above
if [ -e "../${dump}_tHostsConv.log" ]; then
	mv -v ../${dump}_tHostsConv.log ../${dump}_tHostsConv.log_$(date +%y%m%d_%H%M%S)
fi
	mv -v $tHostsConvLog ../${dump}_tHostsConv.log   # we remove the
												# stamp off it, it's not really
												# needed any more
echo "We seem to have exhausted all the loops at this stage, as we are out of"
echo "any now."
echo "The script is still rough and unpolished, with duplicated code..."
echo "Updated version of this script may appear in the future at:"
echo "https://github.com/miroR/ or if not, try and see:"
echo "if there are any news at https://www.CroatiaFidelis.hr/foss/ ."
