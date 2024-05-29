#!/bin/bash
#
# an script to do some basic analysis of PCAPs with Tshark
#
# Copyright (C) 2015,2023 Miroslav Rovis, <https://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#

# it is necessary to have a configuration file such as:
. /home/$USER/.tshark_hosts_conv.conf
# pcap_size_limit and opennic need to be set in it

. shark2use

function show_help {
  echo "tshark-hosts-conv.sh - analyze network traces with Tshark and Bash"
  echo "Usage: ${0##*/} -r <PCAP file> -k <tls.keylog_file>"
  echo ""
  echo "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo "        for particular uses though"
  echo "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo "        the sessions in the PCAP. If those have been logged in the file"
  echo "        designated by the \$SSLKEYLOGFILE environment variable (usually"
  echo "        set to value such as: /home/$USER/.sslkey.log) used during"
  echo "        Firefox, Pale Moon or some other NSS supporting browser's run,"
  echo "        all properly set, then you don't need to set this flag"
}

if [ $# -eq 0 ]; then
     show_help
    exit 0
fi

#
# Reset in case getopts has been used previously in the shell.
#
OPTIND=1
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
        #read NOP
        ;;
    k)  KEYLOGFILE=$OPTARG
        echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
        #read NOP
        ;;
    esac
done

if [ "$KEYLOGFILE" == "" ]; then
    KEYLOGFILE=$SSLKEYLOGFILE
fi
dump=$(echo $PCAP_FILE|cut -d. -f1)
ext=$(echo $PCAP_FILE|cut -d. -f2)

num_dots=$(echo $PCAP_FILE|sed 's/\./\n/g'| wc -l)
num_dots_min_1=$(echo $num_dots - 1 | bc)
ext=$(echo $PCAP_FILE|cut -d. -f $num_dots)
dump=$(echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/")
echo \$dump: $dump
echo \$ext: $ext
#read NOP

# if $dump and $ext are empty, you get "." which exists!, adding -f condition
if [ ! -e "$dump.$ext" ] || [ ! -f "$dump.$ext" ]; then
    echo "The file you gave:"
    echo "$dump.$ext"
    echo "does not exist, or is not in the current directory"
    sleep 3
    show_help
    exit 0
fi

basename $(realpath $(pwd))
# The below may be a safeguard... On reruns, which means more than one log, it
# should still work.
dump_bis=$(basename $(realpath $(pwd))|sed 's/_tHostsConv//')
echo \$dump: $dump
echo \$dump_bis: $dump_bis
#read NOP
if [ "$dump" == "$dump_bis" ]; then
    dump=$dump
else
    # I've been using this script from pre-mkdir'ed ${dump}_tHostsConv.
    # This is accomodation for such use.
    echo "Dear user, you're supposed to be in ${dump}_tHostsConv dir,"
    echo "    and you're _not_ , apparently, see:"
    echo \$dump_bis: $dump_bis
    # However, should've found better way to check for that...
    # So...
    mkdir -pv ${dump}_tHostsConv
    cd ${dump}_tHostsConv
    pwd
    dump_bis=$(basename $(realpath $(pwd))|sed 's/_tHostsConv//')
    echo \$dump_bis: $dump_bis
    if [ "$dump" == "$dump_bis" ]; then
        echo "All is fine with the dir."
    fi
    # Also I would pre-ln make this symlink.
    if [ ! -e "$dump.$ext" ]; then
        ln -s ../$dump.$ext
        ls -lL $dump.$ext
        ls -l $dump.$ext
    fi
fi
echo \$dump: $dump
#read NOP
# Giving it a timestamp of its own so ${0##/} can be rerun, if needed, and get
# a new log.
ts=$(date +%s)
tHostsConvLog=${dump}_tHostsConv_${ts}.log  # currently to log into
tHostsConvLogR=${dump}_tHostsConv.log       # for grep'ing, not to re-process
                                            #+ lines that get nothing or which
                                            #+ have been done in previous run
export tHostsConvLog
export tHostsConvLogR
echo \$tHostsConvLogR: $tHostsConvLogR
ls -l ../$tHostsConvLogR
#read NOP
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
echo "It is needed for re-runs."
echo "You may also find it useful for further analysis/other later."
echo "# Commands as used by the script, written out for educational purposes." \
     |& tee -a $tHostsConvLog

function ask()    # this function taken from "Advanced BASH Scripting Guide"
                  # (a free book) by Mendel Cooper
{
    echo -n "$@" '[y/[n]] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

# If you want to get this script to perform default actions in non-interactive runs
# just create, in the dir with PCAPs where you will run it, an empty file
# .non-interactive. Or

if [ ! -e ".non-interactive" ]; then
    echo "Do you want this script to perform default actions in"
    echo "non-interactive runs on all the PCAPs in this dir?"
    echo "If you change your mind later, delete the empty file:"
    echo ".non-interactive"
    echo "that replying y/Y will create."
    ask
    if [ "$?" == 0 ]; then
        touch .non-interactive
    fi
fi

ls -lL --time-style=posix-long-iso $dump.$ext
echo "(ls -lL --time-style=posix-long-iso $dump.$ext)"
ls -lL --time-style=posix-long-iso $dump.$ext | awk '{print $5}'
echo "(ls -lL --time-style=posix-long-iso $dump.$ext | awk '{print $5}')"
#read NOP
pcap_size=$(ls -lL --time-style=posix-long-iso $dump.$ext | awk '{print $5}')
echo \$pcap_size: $pcap_size
#read NOP
# The list of hosts, and the conversations is what this script extracts first
echo "$TSHARK ... $dump.$ext -qz hosts may have started in background..."
echo "$TSHARK ... $dump.$ext -qz conv,ip may have started in background..."
echo
echo
echo
echo "If so, you should wait until these are listed (with 'ls -l') when done:"
echo
echo "$dump.hosts"
echo "$dump.conv-ip"
echo
echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "  And go slowly at this start, wait a few seconds, "
echo
echo "     and read what I write on the screen! "
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo
echo
echo
echo "This script has not been programmed to wait. You, the human, wait, if needed."
echo
if [ ! -e "$dump.hosts" ] || [ ! -s "$dump.hosts" ]; then 
    $TSHARK -otls.keylog_file:$KEYLOGFILE -r $dump.$ext -qz hosts \
        >  $dump.hosts && ls -l $dump.hosts | sed 's/\t//g' | sed 's/  / /g' \
        | sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog \
        && echo "(but the" |& tee -a $tHostsConvLog \
        && echo "$dump.hosts" |& tee -a $tHostsConvLog \
        && echo "needs to be reordered yet)" && echo |& tee -a $tHostsConvLog &
        tshark_hosts_pid=$! ; echo \$tshark_hosts_pid: $tshark_hosts_pid
        #read NOP
else
    echo "Keeping existing $dump.hosts ."
fi
# if "nameres.network_name: TRUE" set in /home/$USER/.config/wireshark/preferences,
# it needs correcting here, else some results will be incorrect

# even if $dump.POST is empty, it could be from previous interrupted run, it is
# kept anyway and not deleted
if [ ! -e "$dump.conv-ip" ]; then
    echo \$pcap_size: $pcap_size
    echo \$pcap_size_limit: $pcap_size_limit
    echo \$pcap_size_limit_do_anyway: $pcap_size_limit_do_anyway
    #read NOP
    if [ "$pcap_size" -gt "$pcap_size_limit" ] && [ "$pcap_size_limit_do_anyway" != "y" ]; then
        while ( ps aux | grep "\<$tshark_hosts_pid\>" | grep tshark | grep -v grep ); do
            sleep 1; echo "delaying till tshark process $tshark_hosts_pid is done, as $dump.$ext large"
        done
    else
        echo "\$pcap_size gt \$pcap_size_limit and \$pcap_size_limit_do_anyway condition not met"
    fi
    #read NOP
    $TSHARK -otls.keylog_file:$KEYLOGFILE -onameres.network_name:FALSE -r $dump.$ext -qz conv,ip \
        >  $dump.conv-ip \
        && ls -l $dump.conv-ip |& tee -a $tHostsConvLog \
        && echo "(but the" |& tee -a $tHostsConvLog \
        && echo "$dump.conv-ip" |& tee -a $tHostsConvLog \
        && echo "needs to be reordered yet)" |& tee -a $tHostsConvLog \
        && echo |& tee -a $tHostsConvLog &
        tshark_conv_ip_pid=$! ; echo \$tshark_conv_ip_pid: $tshark_conv_ip_pid
        #read NOP
    echo "$dump.hosts"
    echo "will be fixed to be sorted by 'Relative start'."
    #read NOP
    # just " grep $tshark_hosts_pid " could match other non-related stuff, not
    # allowing $0 to go on, rarely, but it happened to me
    while ( ps aux | grep "\<$tshark_hosts_pid\>" | grep tshark | grep -v grep ) || \
        ( ps aux | grep "\<$tshark_conv_ip_pid\>" | grep tshark | grep -v grep ) ; do
    sleep 2; echo "tshark process $tshark_hosts_pid or $tshark_conv_ip_pid still running"
    done
    #read NOP
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
    #read NOP
    cat $dump.hosts-all-jumbled | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -n  > $dump.hosts-2body
    head -n4 $dump.hosts-all-jumbled > $dump.hosts-1top
    tail -$ip6lines $dump.hosts-all-jumbled > $dump.hosts-3btm
    cat $dump.hosts-1top $dump.hosts-2body $dump.hosts-3btm > $dump.hosts
    ls -l $dump.hosts |& tee -a $tHostsConvLog
    # Checking:
    echo cat \$dump.hosts-all-jumbled \| wc -l
    cat $dump.hosts-all-jumbled | wc -l
    echo cat \$dump.hosts \| wc -l
    cat $dump.hosts | wc -l
    #read NOP
    # This is why it needs to be reordered: It ought to be sorted by "Relative start"
    # which is not the Wireshark default. By "Total" "Bytes" loses all relations
    # btwn conversations.
    echo "$dump.conv-ip"
    echo "will be fixed to be by \"Relative Start\"."
    #read NOP
    if [ -e "$dump.conv-ip-by-bytes" ]; then rm -v $dump.conv-ip-by-bytes ; fi
    mv -v $dump.conv-ip $dump.conv-ip-by-bytes
    rm -f $dump.conv-ip-1top; rm -f $dump.conv-ip-3btm; rm -f $dump.conv-ip-2body;
    raw_lines=$(cat $dump.conv-ip-by-bytes | wc -l)
    echo \$raw_lines: $raw_lines
    raw_lines_sans_btm=$(echo $raw_lines-1|bc)
    echo \$raw_lines_sans_btm: $raw_lines_sans_btm
    clean_lines=$(echo $raw_lines_sans_btm-5|bc)
    echo \$clean_lines: $clean_lines
    #read NOP
    # With Wireshark 4.0.2 tshark prints with interpolated space btwn number
    # and bytes,kB,MB. Reverting to no-space.
    mv -iv $dump.conv-ip-by-bytes $dump.conv-ip-by-bytes_RAW
    cat $dump.conv-ip-by-bytes_RAW | sed 's/\([0-9]\) bytes/\1bytes/g' \
        | sed 's/\([0-9]\) kB/\1kB/g' | sed 's/\([0-9]\) MB/\1MB/g' \
        > $dump.conv-ip-by-bytes
    rm -v $dump.conv-ip-by-bytes_RAW
    for i in $(cat $dump.conv-ip-by-bytes | head -$raw_lines_sans_btm \
        | tail -$clean_lines | awk '{ print $10 }' | sort -n); do
        # In case of (minimal) negative start value (rare, but happens) the
        # value needs to be escaped.
        char1=$(echo $i| cut -c1)
        if [ "$char1" == "-" ]; then
            echo $i | sed "s/-\($i\)/\\-\1/"
            i=$(echo $i | sed "s/-\($i\)/\\-\1/")
            echo \$i: "$i"
            i=$(echo "\\$i")
            echo \$i: "$i"
        fi
        echo "grep \"$i\" $dump.conv-ip-by-bytes >> $dump.conv-ip-2body"
        grep "$i" $dump.conv-ip-by-bytes >> $dump.conv-ip-2body
    done
    head -n5 $dump.conv-ip-by-bytes > $dump.conv-ip-1top
    tail -n1 $dump.conv-ip-by-bytes > $dump.conv-ip-3btm
    cat $dump.conv-ip-1top $dump.conv-ip-2body $dump.conv-ip-3btm > $dump.conv-ip
    ls -l $dump.conv-ip |& tee -a $tHostsConvLog
    #read NOP
    # This is very approximative. It will not find that $dump.hosts is empty
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
    echo "Keeping existing $dump.conv-ip ."
fi

if [ ! -e "$dump.POST" ]; then
    if [ "$pcap_size" -gt "$pcap_size_limit" ] && [ "$pcap_size_limit_do_anyway" != "y" ]; then
        while ( ps aux | grep "\<$tshark_conv_ip_pid\>" | grep tshark | grep -v grep ); do
            sleep 1; echo "delaying till tshark process $tshark_conv_ip_pid is done, as $dump.$ext large"
        done
    else
        echo "\$pcap_size gt \$pcap_size_limit and \$pcap_size_limit_do_anyway condition not met"
    fi
    sleep 5 && $TSHARK -otls.keylog_file:$KEYLOGFILE -r $dump.$ext -V -Y \
        'http.request.method==POST' > $dump.POST &
    tshark_post_pid=$! ; echo \$tshark_post_pid: $tshark_post_pid
    sleep 5 && echo "... -Y http.request.method==POST started in background..." &
    if [ "$pcap_size" -gt "$pcap_size_limit" ] && [ "$pcap_size_limit_do_anyway" != "y" ]; then
        while ( ps aux | grep "\<$tshark_post_pid\>" | grep tshark | grep -v grep ); do
            sleep 2; echo "delaying till tshark process $tshark_post_pid is done, as $dump.$ext large"
        done
    else
        echo "\$pcap_size gt \$pcap_size_limit and \$pcap_size_limit_do_anyway condition not met"
    fi
    ls -l $dump.POST |& tee -a $tHostsConvLog \
    && echo |& tee -a $tHostsConvLog &
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
    echo ls -l \$dump.POST
    ls -l $dump.POST
fi
ls -l ../$tHostsConvLogR
#read NOP
if [ -e "../$tHostsConvLogR" ] && [ -s "../$tHostsConvLogR" ]; then
    grep ${dump}-frame-http-request-full_uri.txt ../$tHostsConvLogR
    echo "(grep ${dump}-frame-http-request-full_uri.txt)" ../$tHostsConvLogR
    dump_http_full_uri=''
    if ( grep -q ${dump}-frame-http-request-full_uri.txt ../$tHostsConvLogR ); then
        echo "${dump}_${ip}-frame-http-request-full_uri.txt previously processed"
        echo "setting dump_http_full_uri to 'y'"
        dump_http_full_uri=y
    fi
    grep ${dump}-frame-http2-request-full_uri.txt ../$tHostsConvLogR
    echo "(grep ${dump}-frame-http2-request-full_uri.txt)" ../$tHostsConvLogR
    dump_http2_full_uri=''
    if ( grep -q ${dump}-frame-http2-request-full_uri.txt ../$tHostsConvLogR ); then
        echo "${dump}_${ip}-frame-http2-request-full_uri.txt previously processed"
        echo "setting dump_http2_full_uri to 'y'"
        dump_http2_full_uri=y
    fi
fi
echo \$dump_http_full_uri: $dump_http_full_uri
echo \$dump_http2_full_uri: $dump_http2_full_uri
#read NOP
if [ ! -e "${dump}-frame-http-request-full_uri.txt" ] && [ ! -e "${dump}-frame-http2-request-full_uri.txt" ]; then
    if [ "$dump_http_full_uri" != "y" ] || [ "$dump_http2_full_uri" != "y" ]; then
        echo "tshark-httpX-uri.sh -k $KEYLOGFILE -r $dump.$ext" |& tee -a $tHostsConvLog
        #read NOP
        tshark-httpX-uri.sh -k $KEYLOGFILE -r $dump.$ext |& tee -a $tHostsConvLog
        if [ -e "${dump}-frame-http-request-full_uri.txt" ]; then
            ls -l ${dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
            echo |& tee -a $tHostsConvLog
        fi
        if [ -e "${dump}-frame-http2-request-full_uri.txt" ]; then
            ls -l ${dump}-frame-http2-request-full_uri.txt >> $tHostsConvLog
            echo |& tee -a $tHostsConvLog
        fi
    else
        echo "Not re-processing some of ${dump}-frame-http{,2}-request-full_uri.txt"
        echo "             (not doing since would be empty)."
    fi
else
    echo "Keeping existing ${dump}-frame-http{,2}-request-full_uri.txt."
fi

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
    echo "(just one time at start only --if some read NOPs not commented out) ?"
    echo
    echo "\$raw_lines can't be less then 1"
    exit 1
fi
#read NOP

raw_lines_sans_btm=$(echo $raw_lines-1|bc)
clean_lines=$(echo $raw_lines_sans_btm-5|bc)

cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $1 }' > conv-ip_column_1
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $3 }'  > conv-ip_column_3

# There will need often arise to have col_A (A for hex 10, the awk's $10), to
# eliminate double entries for the combined hosts/conv-ip listing
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $10 }'  > conv-ip_column_A
#read NOP

echo "---";
echo "This is the listing of hosts-[to-be-]worked IPs"
echo "---";

# The ..+ in third line allows for terminated tor connections that turn into
# 192.168.1.N to 192.168.1.N (where N is same), otherwise the program stalls.
paste conv-ip_column_1 conv-ip_column_3 \
    | sed 's/192\.168\.1\..*\t//' | sed 's/\t192\.168\.1\..*//' \
    | sed "s/192\.168\.1\...+$//" \
    | sed 's/\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' \
    | grep -E '[[:print:]]'
#read NOP

echo "---";
echo "Saving the listing of hosts-[to-be-]worked IPs from the trace to:"
echo "    $dump.hosts-worked-ls-1"
echo "(takes time for huge traces)"
echo "---";

paste conv-ip_column_1 conv-ip_column_3 \
    | sed 's/192\.168\.1\..*\t//' | sed 's/\t192\.168\.1\..*//' \
    | sed "s/192\.168\.1\...+$//" \
    | sed 's/\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' \
    | grep -E '[[:print:]]' \
    > $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
#read NOP
echo
ls -l $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
rm conv-ip_column_1 conv-ip_column_3
echo
if [ ! -e ".non-interactive" ]; then
    echo "At this stage, you can manually edit $dump.hosts-worked-ls-1"
    echo "to add or delete some entries, if you know what you are doing."
    echo "(Hit Enter to move on.)"
    #read NOP
fi
# $dump.hosts-worked-ls-1 needs to be sed'ed now.
echo "making "." mean "\." for grep, next"
#read NOP
sed 's/\./\\\./g' $dump.hosts-worked-ls-1 > $dump.hosts-worked-ls-1-mod
cat $dump.hosts-worked-ls-1-mod
echo "(cat $dump.hosts-worked-ls-1-mod)"

# But we would still get two lines grep's per iteration. Not with the change,
# prepared with this:
paste $dump.hosts-worked-ls-1 conv-ip_column_A|sed 's/\t/@/' \
    > $dump.hosts-worked-ls-1-tmp
echo "mv -v $dump.hosts-worked-ls-1-tmp $dump.hosts-worked-ls-1"
mv -v $dump.hosts-worked-ls-1-tmp $dump.hosts-worked-ls-1
#read NOP
cat $dump.hosts-worked-ls-1
echo "(cat $dump.hosts-worked-ls-1)"
echo "--=-=~=-=--"
#read NOP
paste $dump.hosts-worked-ls-1-mod conv-ip_column_A|sed 's/\t/@/' \
    > $dump.hosts-worked-ls-1-mod-tmp
echo "mv -v $dump.hosts-worked-ls-1-mod-tmp $dump.hosts-worked-ls-1-mod"
mv -v $dump.hosts-worked-ls-1-mod-tmp $dump.hosts-worked-ls-1-mod
rm conv-ip_column_A
#read NOP
cat $dump.hosts-worked-ls-1-mod
echo "(cat $dump.hosts-worked-ls-1-mod)"
echo "--=-=~=-=--"
#read NOP
# And those nameres.network_name both-hostname-and-IP info you can choose to
# write out to the log.
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
echo "it's good to have the listing of conversations by host and by IP"
echo "set default for non-interactive mode"
> $dump.conv-ip_l
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $dump.conv-ip_l
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
for j in $(cat $dump.hosts-worked-ls-1); do
    echo \$j: $j
    ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
    starttime=$(echo $j|sed 's/.*@\(.*\)/\1/')
    echo \$ip: $ip
    echo \$starttime: $starttime
    # needs to be checked for duplicate finds
    # as well as for empty finds
    if ( grep "\<$ip\>" $dump.hosts ); then
        grep "\<$ip\>" $dump.hosts >> $dump.conv-ip_l
        grep "\<$ip\>" $dump.hosts >> $tHostsConvLog
        #read NOP
    else
        echo "$ip   NOTICE-not-resolved-NOTICE" |& tee -a $dump.conv-ip_l
        echo "$ip   NOTICE-not-resolved-NOTICE" |& tee -a $tHostsConvLog
    fi
    grep "\<$ip\>" $dump.conv-ip | grep $starttime
    #read NOP
    cat $dump.conv-ip | head -n5 | tail -n2 >> $dump.conv-ip_l
    cat $dump.conv-ip | head -n5 | tail -n2 >> $tHostsConvLog
    grep "\<$ip\>" $dump.conv-ip | grep $starttime >> $dump.conv-ip_l
    grep "\<$ip\>" $dump.conv-ip | grep $starttime >> $tHostsConvLog
    echo "---" >> $dump.conv-ip_l
    echo "---" >> $tHostsConvLog
    echo >> $tHostsConvLog
    echo >> $dump.conv-ip_l
done
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $dump.conv-ip_l
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" >> $tHostsConvLog
if [ -e "../$dump.conv-ip_l" ]; then
    mv -v ../$dump.conv-ip_l ../$dump.conv-ip_l_${ts}
fi
mv -v $dump.conv-ip_l ../
if ( diff ../$dump.conv-ip_l ../$dump.conv-ip_l_${ts} ); then
    mv -v ../$dump.conv-ip_l_${ts} ../$dump.conv-ip_l
fi
echo |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
# It is good to use OpenNIC. It can be kept in say $opennic_file
# e.g. in /etc/resolv_conf_opennic with content such as:
# nameserver <the IP>
# nameserver <another IP>
# and in  /etc/resolv_conf_opennic necessary to set a line like:
# opennic_file=/etc/resolv_conf_opennic
grep nameserver $opennic_file | awk '{print $2}'| tr '\12' '@' | sed 's/@\([0-9]\)/\\\|\1/' |  sed 's/@//'
opennic=$(grep nameserver $opennic_file | awk '{print $2}'| tr '\12' '@' | sed 's/@\([0-9]\)/\\\|\1/' |  sed 's/@//')
#debug 5 ln
echo \$opennic: $opennic
for j in $(cat $dump.hosts-worked-ls-1|grep -v 192.168.1.[0-9]|grep -v 255.255.255.255|grep -v "$opennic"); do
    echo $j
done
#read NOP
if [ "$pcap_size" -lt "$pcap_size_limit" ] || [ "$pcap_size_limit_do_anyway" == "y" ]; then
    for j in $(cat $dump.hosts-worked-ls-1|grep -v 192.168.1.[0-9]|grep -v 255.255.255.255|grep -v "$opennic"); do
        echo \$j: $j
        ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
        echo \$ip: $ip
        grep "\<$ip\>" $dump.hosts
        cat $dump.conv-ip | head -n5 | tail -n2
        grep "\<$ip\>" $dump.conv-ip
        echo "The IP: $ip"
        # grep the previously written log if exists
        if [ -e "../$tHostsConvLogR" ] && [ -s "../$tHostsConvLogR" ]; then
            grep ${dump}_${ip}-frame-http-request-full_uri.txt ../$tHostsConvLogR
            echo "(grep ${dump}_${ip}-frame-http-request-full_uri.txt)" ../$tHostsConvLogR
            dump_ip_http_full_uri=''
            if ( grep -q ${dump}_${ip}-frame-http-request-full_uri.txt ../$tHostsConvLogR ); then
                echo "${dump}_${ip}-frame-http-request-full_uri.txt previously processed"
                echo "setting dump_ip_http_full_uri to 'y'"
                dump_ip_http_full_uri=y
            fi
            grep ${dump}_${ip}-frame-http2-request-full_uri.txt ../$tHostsConvLogR
            echo "(grep ${dump}_${ip}-frame-http2-request-full_uri.txt)" ../$tHostsConvLogR
            dump_ip_http2_full_uri=''
            if ( grep -q ${dump}_${ip}-frame-http2-request-full_uri.txt ../$tHostsConvLogR ); then
                echo "${dump}_${ip}-frame-http2-request-full_uri.txt previously processed"
                echo "setting dump_ip_http2_full_uri to 'y'"
                dump_ip_http2_full_uri=y
            fi
        fi
        echo \$dump_ip_http_full_uri: $dump_ip_http_full_uri
        echo \$dump_ip_http2_full_uri: $dump_ip_http2_full_uri
        #read NOP
        if [ ! -e "${dump}_${ip}-frame-http-request-full_uri.txt" ] && [ ! -e "${dump}_${ip}-frame-http2-request-full_uri.txt" ]; then
            if [ "$dump_ip_http_full_uri" != "y" ] || [ "$dump_ip_http2_full_uri" != "y" ]; then
                tshark-httpX-uri.sh -k $KEYLOGFILE -r $dump.$ext -i $ip
                if [ -e "${dump}_${ip}-frame-http-request-full_uri.txt" ]; then
                    ls -l ${dump}_${ip}-frame-http-request-full_uri.txt |& tee -a $tHostsConvLog
                    echo |& tee -a $tHostsConvLog
                fi
                if [ -e "${dump}_${ip}-frame-http2-request-full_uri.txt" ]; then
                    ls -l ${dump}_${ip}-frame-http2-request-full_uri.txt |& tee -a $tHostsConvLog
                    echo |& tee -a $tHostsConvLog
                fi
            fi
        fi
    done
    echo
    for j in $(cat $dump.hosts-worked-ls-1|grep -v 192.168.1.[0-9]|grep -v 255.255.255.255|grep -v "$opennic"); do
        echo \$j: $j
        ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
        echo \$ip: $ip
        grep "\<$ip\>" $dump.hosts
        cat $dump.conv-ip | head -n5 | tail -n2
        grep "\<$ip\>" $dump.conv-ip
        echo "The IP: $ip"
        #new_dump=${dump}_${ip}
        if [ -d "../${dump}_${ip}_files" ]; then
            dump_ip_files_cont="${dump}_${ip}_files_cont"
            dump_ip_files_cont=$(ls -1 ../${dump}_${ip}_files)
            echo "X${dump_ip_files_cont}X"
        fi
        if [ -d "../${dump}_${ip}_files" ] &&  [ "X${dump_ip_files_cont}X" != "XX" ] || \
            ( grep "empty dir ${dump}_${ip}_files deleted" ../$tHostsConvLogR ); then
            echo "Work on ${dump}_${ip} to extract ${dump}_${ip}_files not needed."
        else
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r $dump.$ext \
                -Y "(ip.addr==$ip)" -w ${dump}_${ip}.$ext
            echo
            ls -l ${dump}_${ip}.$ext |& tee -a $tHostsConvLog
            echo |& tee -a $tHostsConvLog
            echo
            # tshark can extract all HTTP objects (--export-object), but it can't
            # run --export-object combined with filtering on convs or streams
            # (or I haven't figured out how). So do extracting by each ip PCAP.
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r ${dump}_${ip}.$ext \
                -q --export-object http,${dump}_${ip}_files
            echo "ls -l ${dump}_${ip}_files" |& tee -a $tHostsConvLog
            ls -l ${dump}_${ip}_files |& tee -a $tHostsConvLog
            if ( rmdir ${dump}_${ip}_files &> /dev/null ); then
                if [ ! -e "${dump}_${ip}_files" ]; then
                    echo "empty dir ${dump}_${ip}_files deleted" |& tee -a $tHostsConvLog
                fi
            fi
            mv -v ${dump}_${ip}_files ../
        fi
        # bloat, just the _files dir good to have, and the localhost
        if ( echo ${dump}_${ip}.$ext | grep 127.0.0.1 ); then
            ls -l ${dump}_${ip}.$ext
        else
            rm -v ${dump}_${ip}.$ext |& tee -a $tHostsConvLog
        fi
        echo |& tee -a $tHostsConvLog
    done
else
    echo "\$pcap_size larger then $pcap_size_limit (set in /home/$USER/.tshark_hosts_conv.conf):" |& tee -a $tHostsConvLog
    echo "############################################################" |& tee -a $tHostsConvLog
    echo "Generally it is better to preprocess/filter larger \$dump.\$ext before work" |& tee -a $tHostsConvLog
    echo "I.e. we won't work this file: " |& tee -a $tHostsConvLog
    ls -l $dump.$ext |& tee -a $tHostsConvLog
    echo "set pcap_size_limit_do_anyway to y and run ${0##*/} on $dump.$ext again" |& tee -a $tHostsConvLog
    echo "          if you really want to work it.              " |& tee -a $tHostsConvLog
    echo "    (${0##*/} has skipped lots of lines in this script)              " |& tee -a $tHostsConvLog
    echo "############################################################" |& tee -a $tHostsConvLog
fi

# Cleanup of empty files produced needed here.
for i in $(ls -1); do
    if [ ! -s "$i" ]; then
        ls -l $i |& tee -a $tHostsConvLog
    fi
done
if [ -e ".non-interactive" ]; then
    echo "Removing the empty files listed..." |& tee -a $tHostsConvLog
    cat $dump.hosts | grep -v '^#' | grep '[[:print:]]' > $dump.hosts.TMP
    ls -l $dump.hosts $dump.hosts.TMP
    if [ ! -s "$dump.hosts.TMP" ]; then
        mv -v $dump.hosts.TMP $dump.hosts
    else
        rm -v $dump.hosts.TMP
    fi
    for i in $(ls -1); do
        if [ ! -s "$i" ]; then
            rm -v $i |& tee -a $tHostsConvLog
        fi
    done
else
    # Now first temporarily remove comments from $dump.hosts. If the
    # content is then 0 size, remove $dump.hosts too, else remove the
    # temporary copy; also necessary to remove any blanks
    cat $dump.hosts | grep -v '^#' | sed 's/ //'| sed 's/ //' \
        | sed  's/ //' > $dump.hosts.TMP
    ls -l $dump.hosts $dump.hosts.TMP
    if [ ! -s "$dump.hosts.TMP" ]; then
        mv -v $dump.hosts.TMP $dump.hosts
    else
        rm -v $dump.hosts.TMP
    fi
    for i in $(ls -1); do
        if [ ! -s "$i" ]; then
            rm -v $i |& tee -a $tHostsConvLog
        fi
    done
fi
if [ -e "$dump.hosts-worked-ls-1" ]; then
    rm -v $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
fi
if [ -e "$dump.hosts-worked-ls-1-mod" ]; then
    rm -v $dump.hosts-worked-ls-1-mod |& tee -a $tHostsConvLog
fi
sleep 3 # else the returning prompt may confuse the use with an empty echo
# This listing is necessary in case there have been more runs of ${0##/}
ls -l ${dump}_*.log      # but should be only one (if there weren't, say, any
                         # crashes during previous run)
ls -l $tHostsConvLog     # should list the same one file as above
# if exists, just append to it, temporary solution, to do all re-run grep'ing in one file
if [ -e "../${dump}_tHostsConv.log" ]; then
    #mv -v ../${dump}_tHostsConv.log ../${dump}_tHostsConv.log_${ts}
    cat $tHostsConvLog >> ../${dump}_tHostsConv.log
    rm -v $tHostsConvLog
else
    mv -v $tHostsConvLog ../${dump}_tHostsConv.log
fi
echo "We seem to have exhausted all the loops at this stage, as we are out of"
echo "any now."
echo "Updated version of this script may appear in the future at:"
echo "https://github.com/miroR/ or if not, try and see:"
echo "if there are any news at https://www.CroatiaFidelis.hr/foss/ ."
# vim: set tabstop=4 expandtab:
