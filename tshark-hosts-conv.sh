#!/bin/bash
#
# an script to do some basic analysis of PCAPs with Tshark
#
# Copyright (C) 2015 Miroslav Rovis, <http://www.CroatiaFidelis.hr/>
# Use this at your own risk!
# released under BSD license, see LICENSE, or assume general BSD license,
#

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
OPTIND=1    # I still don't understand the OPTIND, nor if it is needed here.
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

ts=$(date +%s)

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
#read FAKE
filename=$dump.$ext
echo \$filename: $filename

# if $dump and $ext are empty, you get "." which exists!, adding -f condition
if [ ! -e "$dump.$ext" ] || [ ! -f "$dump.$ext" ]; then
    echo "The file you gave:"
    echo "$dump.$ext"
    echo "does not exist, or is not in the current directory"
    echo "(unless it's the current dir :-) )."
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
#read FAKE
if [ "$dump" == "$dump_bis" ]; then
    dump=$dump
else
    # I've been using this script from pre-mkdir'ed ${dump}_tHostsConv, only.
    # This is accomodation such use.
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
#read FAKE
# Giving it a timestamp of its own so ${0##/} can be rerun, if needed, and get
# a new log.
tHostsConvLog=${dump}_tHostsConv_${ts}.log
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

function ask()    # this function borrowed from "Advanced BASH Scripting Guide"
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
echo "This script has not been programmed to wait. You, the human, wait, if needed."
echo 
$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r $dump.$ext -qz hosts \
    >  $dump.hosts && ls -l $dump.hosts | sed 's/\t//g' | sed 's/  / /g' \
    | sed 's/  / /g' | sed 's/  / /g' |& tee -a $tHostsConvLog \
    && echo "(but the" |& tee -a $tHostsConvLog \
    && echo "$dump.hosts" |& tee -a $tHostsConvLog \
    && echo "needs to be reordered yet)" && echo |& tee -a $tHostsConvLog &
    tshark_hosts_pid=$! ; echo \$tshark_hosts_pid: $tshark_hosts_pid
    #read FAKE
# if "nameres.network_name: TRUE" set in /home/$USER/.config/wireshark/preferences,
# it needs correcting here, else some results will be incorrect
$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -o "nameres.network_name: FALSE" -r $dump.$ext -qz conv,ip \
    >  $dump.conv-ip \
    && ls -l $dump.conv-ip |& tee -a $tHostsConvLog \
    && echo "(but the" |& tee -a $tHostsConvLog \
    && echo "$dump.conv-ip" |& tee -a $tHostsConvLog \
    && echo "needs to be reordered yet)" |& tee -a $tHostsConvLog \
    && echo |& tee -a $tHostsConvLog &
    tshark_conv_ip_pid=$! ; echo \$tshark_conv_ip_pid: $tshark_conv_ip_pid
    #read FAKE
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

if [ ! -e "$dump.POST" ]; then
    sleep 5 && $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r $dump.$ext -V -Y \
        'http.request.method==POST' > $dump.POST \
        && ls -l $dump.POST |& tee -a $tHostsConvLog \
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
    echo ls -l \$dump.POST
    ls -l $dump.POST
fi

tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext |& tee -a $tHostsConvLog
ls -l ${dump}-frame-http-request-full_uri.txt >> $tHostsConvLog
echo |& tee -a $tHostsConvLog

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
clean_lines=$(echo $raw_lines_sans_btm-5|bc)

cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $1 }' > conv-ip_column_1
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $3 }'  > conv-ip_column_3

# There will need often arise to have col_A (A for hex 10, the awk's $10), to
# eliminate double entries for the combined hosts/conv-ip listing
cat $dump.conv-ip | head -$raw_lines_sans_btm | tail -$clean_lines \
    | awk '{ print $10 }'  > conv-ip_column_A
#read FAKE

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
#read FAKE

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
#read FAKE
echo
ls -l $dump.hosts-worked-ls-1 |& tee -a $tHostsConvLog
echo |& tee -a $tHostsConvLog
rm conv-ip_column_1 conv-ip_column_3
echo
if [ ! -e ".non-interactive" ]; then
    echo "At this stage, you can manually edit $dump.hosts-worked-ls-1"
    echo "to add or delete some entries, if you know what you are doing."
    echo "(Hit Enter to move on.)"
    #read FAKE
fi
# $dump.hosts-worked-ls-1 needs to be sed'ed now.
echo "making "." mean "\." for grep, next"
#read FAKE
sed 's/\./\\\./g' $dump.hosts-worked-ls-1 > $dump.hosts-worked-ls-1-mod
cat $dump.hosts-worked-ls-1-mod
echo "(cat $dump.hosts-worked-ls-1-mod)"

# But we would still get two lines grep's per iteration. Not with the change,
# prepared with this:
paste $dump.hosts-worked-ls-1 conv-ip_column_A|sed 's/\t/@/' \
    > $dump.hosts-worked-ls-1-tmp
echo "mv -v $dump.hosts-worked-ls-1-tmp $dump.hosts-worked-ls-1"
mv -v $dump.hosts-worked-ls-1-tmp $dump.hosts-worked-ls-1
#read FAKE
cat $dump.hosts-worked-ls-1
echo "(cat $dump.hosts-worked-ls-1)"
echo "--=-=~=-=--"
#read FAKE
paste $dump.hosts-worked-ls-1-mod conv-ip_column_A|sed 's/\t/@/' \
    > $dump.hosts-worked-ls-1-mod-tmp
echo "mv -v $dump.hosts-worked-ls-1-mod-tmp $dump.hosts-worked-ls-1-mod"
mv -v $dump.hosts-worked-ls-1-mod-tmp $dump.hosts-worked-ls-1-mod
rm conv-ip_column_A
#read FAKE
cat $dump.hosts-worked-ls-1-mod
echo "(cat $dump.hosts-worked-ls-1-mod)"
echo "--=-=~=-=--"
#read FAKE
#echo
#echo "First run now..."
#> $dump.conv-ip_try
#ls -l $dump.conv-ip_try
#for j in $(cat $dump.hosts-worked-ls-1-mod); do
#    ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
#    starttime=$(echo $j|sed 's/.*@\(.*\)/\1/')
#    echo "grep $ip $dump.hosts"
#    grep $ip $dump.hosts
#    grep $ip $dump.hosts >> $dump.conv-ip_try
#    #read FAKE
#    #cat $dump.conv-ip | head -5 | tail -2
#    echo "grep \$ip $dump.conv-ip | grep \$starttime"
#    echo "grep $ip $dump.conv-ip | grep $starttime"
#    grep $ip $dump.conv-ip | grep $starttime
#    grep $ip $dump.conv-ip | grep $starttime >> $dump.conv-ip_try
#    echo "--=-=~=-=--"
#    #read FAKE
#    cat $dump.conv-ip_try
#    echo "(cat $dump.conv-ip_try)"
#    echo "---"
#    echo
#    #read FAKE
#done
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
    if ( grep $ip $dump.hosts ); then
        grep $ip $dump.hosts >> $dump.conv-ip_l
        grep $ip $dump.hosts >> $tHostsConvLog
        #read FAKE
    else
        echo "$ip   NOTICE-could-not-be-resolved-NOTICE" |& tee -a $dump.conv-ip_l
        echo "$ip   NOTICE-could-not-be-resolved-NOTICE" |& tee -a $tHostsConvLog
    fi
    grep $ip $dump.conv-ip | grep $starttime
    #read FAKE
    cat $dump.conv-ip | head -5 | tail -2 >> $dump.conv-ip_l
    cat $dump.conv-ip | head -5 | tail -2 >> $tHostsConvLog
    grep $ip $dump.conv-ip | grep $starttime >> $dump.conv-ip_l
    grep $ip $dump.conv-ip | grep $starttime >> $tHostsConvLog
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
for j in $(cat $dump.hosts-worked-ls-1|grep -v 192.168.1.[0-9]); do
    echo \$j: $j
    ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
    echo \$ip: $ip
    grep $ip $dump.hosts
    cat $dump.conv-ip | head -5 | tail -2
    grep $ip $dump.conv-ip
    echo "The IP: $ip"
    tshark-http-uri.sh -k $KEYLOGFILE -r $dump.$ext -i $ip
    ls -l ${dump}-frame-http-request-full_uri.txt |& tee -a $tHostsConvLog
    echo |& tee -a $tHostsConvLog
done
for j in $(cat $dump.hosts-worked-ls-1|grep 192.168.1.[0-9]); do
    echo \$j: $j
    ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
    echo \$ip: $ip
    grep $ip $dump.hosts
    cat $dump.conv-ip | head -5 | tail -2
    grep $ip $dump.conv-ip
    echo "The IP: $ip"
    $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -q -r $dump.$ext -Y "(ip.src==$ip)&&(ip.dst==$ip)" -T fields \
        -e 'frame.number' -e 'http.request.full_uri' | grep \
        -E '^[0-9]{1,9}[[:space:]][[:alpha:]]' \
        > ${dump}_${ip}-frame-http-request-full_uri.txt
    ls -l ${dump}-frame-http-request-full_uri.txt |& tee -a $tHostsConvLog
    echo |& tee -a $tHostsConvLog
done
for j in $(cat $dump.hosts-worked-ls-1|grep -v 192.168.1.[0-9]); do
    echo \$j: $j
    ip=$(echo $j|sed 's/\(.*\)@.*/\1/')
    echo \$ip: $ip
    grep $ip $dump.hosts
    cat $dump.conv-ip | head -5 | tail -2
    grep $ip $dump.conv-ip
    echo "The IP: $ip"
    new_dump=${dump}_${ip}
    $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r $dump.$ext \
        -Y "(ip.addr==$ip)" -w $new_dump.$ext
    echo
    ls -l $new_dump.$ext |& tee -a $tHostsConvLog
    echo |& tee -a $tHostsConvLog
    echo
    # Keep the new method. Not use the old, except for export to _files/ dir
    #if [ -e "${dump}_${ip}-frame-http-request-full_uri.txt" ]; then
    #    cp -iav ${dump}_${ip}-frame-http-request-full_uri.txt \
    #        ${dump}_${ip}-frame-http-request-full_uri.txt.new-method
    #fi
    #tshark-http-uri.sh -k $KEYLOGFILE -r $new_dump.$ext
    #ls -l ${new_dump}-frame-http-request-full_uri.txt |& tee -a $tHostsConvLog
    #echo |& tee -a $tHostsConvLog
    #
    # Currently tshark can extract all HTTP GET and POST payload (--export-object), but it can't
    # run --export-object combined with filtering on convs or streams
    # (or I haven't figured out how). So do extracting by each ip conv.
    $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r $new_dump.$ext \
        -q --export-object http,${new_dump}_files
    echo "ls -l ${new_dump}_files" |& tee -a $tHostsConvLog
    ls -l ${new_dump}_files |& tee -a $tHostsConvLog
    if ( rmdir ${new_dump}_files &> /dev/null ); then
        if [ ! -e "${new_dump}_files" ]; then
            echo "empty dir ${new_dump}_files deleted" |& tee -a $tHostsConvLog 
        fi
    fi
    if [ -e "${new_dump}_files" ]; then
        if [ -e "../${new_dump}_files" ]; then
            mv -v ../${new_dump}_files ../${new_dump}_files_${ts}
        fi
        mv -v ${new_dump}_files ../
    fi
    # bloat, just the _files dir good to have, and the localhost
    if ( echo $new_dump.$ext | grep 127.0.0.1 ); then
        ls -l $new_dump.$ext 
    else
        rm -v $new_dump.$ext |& tee -a $tHostsConvLog 
    fi
    echo |& tee -a $tHostsConvLog
done

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
sleep 3 # else the returning prompt may confuse the use with an empty echo
# This listing is necessary in case there have been more runs of ${0##/}
ls -l ${dump}_*.log      # but should be only one (if there weren't, say, any
                         # crashes during previous run)
ls -l $tHostsConvLog     # should list the same one file as above
if [ -e "../${dump}_tHostsConv.log" ]; then
    mv -v ../${dump}_tHostsConv.log ../${dump}_tHostsConv.log_${ts}
fi
mv -v $tHostsConvLog ../${dump}_tHostsConv.log  # we remove the
                                                # stamp off it, it's not really
                                                # needed any more
echo "We seem to have exhausted all the loops at this stage, as we are out of"
echo "any now."
echo "The script is still rough and unpolished, with duplicated code..."
echo "Updated version of this script may appear in the future at:"
echo "https://github.com/miroR/ or if not, try and see:"
echo "if there are any news at https://www.CroatiaFidelis.hr/foss/ ."
# vim: set tabstop=4 expandtab:
