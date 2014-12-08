#!/bin/bash
########################################################
#
# fw-main.sh
# main executable for solowall-iptables
# solowall-iptables (c) Torsten Mueller 2014
# 
########################################################

function main(){
    # Please note:
    # while some rules are unnecessary (e.g.: ALLOWING established Outgoing traffic, unnecessary since default 
    # policy is to allow all outgoing anyways), they speed up the server because default policies are applied 
    # after all rules have been checked.

    # read base config
    DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
    source ${DIR}/conf/options.conf 


    ### Flush all existing Tables
    flushTables
    
    ### SET DEFAULT POLICIES AND RULES
    # Set default policies
    $IPTABLES -P INPUT DROP
    $IPTABLES -P FORWARD DROP
    $IPTABLES -P OUTPUT ACCEPT

    # Disable IP forwarding in sysctl:
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
    echo 0 > /proc/sys/net/ipv4/conf/default/forwarding

    # local loopback is a friend
    $IPTABLES -A INPUT -i lo -j ACCEPT
    $IPTABLES -A OUTPUT -o lo -j ACCEPT

    # allow packets that already have a connection
    $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    ### Add custom tables
    # DENYLOG is the default chain to jump to when a packet is to be droppped/rejected and
    # shall be logged first
    $IPTABLES -N DENYLOG
    $IPTABLES -A DENYLOG -j $DENYACTION

    # DENYHARDEN is the chain all hardening rules jump to. 
    $IPTABLES -N DENYHARDEN
    $IPTABLES -A DENYHARDEN -j $DENYACTION
    
    # SPEEDLIMIT is the chain all rate limiting rules jump to. 
    $IPTABLES -N SPEEDLIMIT
    $IPTABLES -A SPEEDLIMIT -j $DENYACTION

    ### ACCEPT WHITELISTED IPs
    # Before some more elaborate (and CPU intensive) rules are evaluated, lets quickly
    # accept traffic from all IPs listed in ip-whitelist.conf. 
    FILE=${DIR}/conf/ip-whitelist.conf

    while read line;
        do
            line=${line//[[:space:]]/}
            if [[ $line != *#* && "$line" != "" ]]
                then
                    $IPTABLES -A INPUT -s $line -m state --state NEW -j ACCEPT
            fi
        done < $FILE

    ### DROP REJECT stuff to follow

    # INVALID packets are dropped. 
    if $LOGINVALID;
        then
            $IPTABLES -I DENYLOG -m state --state INVALID -m hashlimit --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-mode dstport --hashlimit-name invalidlog --hashlimit-htable-expire 100000 -j LOG --log-prefix "$LOGID $LOGPREF_INVALID"
            $IPTABLES -A INPUT -m state --state INVALID -j DENYLOG
        else 
            $IPTABLES -A INPUT -m state --state INVALID -j $DENYACTION
     fi

    # Drop multicast and broadcast
    $IPTABLES -A INPUT -m pkttype --pkt-type multicast -j $DENYACTION
    $IPTABLES -A INPUT -m pkttype --pkt-type broadcast -j $DENYACTION

    # Protection against outgoing UDP flood; outgoing DNS and NTP will always be allowed whatever options are set
    if $PROTECT_UDP;
        then
            $IPTABLES -N UDPDROP
            $IPTABLES -A OUTPUT -p udp --dport 53 -j ACCEPT
            $IPTABLES -A OUTPUT -p udp --dport 123 -j ACCEPT            
            if $LOG_UDP;
                then
                    $IPTABLES -A UDPDROP -m hashlimit --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-mode dstport --hashlimit-name udplog --hashlimit-htable-expire 100000 -j LOG --log-prefix "$LOGID $UDP_LOGPREFIX"
            fi
            $IPTABLES -A OUTPUT -p udp -j UDPDROP
            $IPTABLES -A UDPDROP -p udp -j $DENYACTION
                    
            if [ $DENY_UDP == false ];
                then
                    $IPTABLES -I UDPDROP -p udp -m limit --limit $UDP_LIMIT --limit-burst $UDP_BURST -j RETURN
            fi
    fi

    # Require SYN on NEW connections
    if [ $HARDEN_REQ_SYN == true ];
        then
            $IPTABLES -A INPUT -p tcp ! --syn -m state --state NEW -j $DENYACTION
    fi  
    # Slow down some portscans
    if [ $HARDEN_FURTIVE_SPEED -gt 0 ];
        then
            $IPTABLES -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit $HARDEN_FURTIVE_SPEED/s --limit-burst $HARDEN_FURTIVE_SPEED -j ACCEPT   
    fi  

    # Turn on Logging for hardening rules 
    if [ $HARDEN_LOGGING == true ];
        then
            $IPTABLES -I DENYHARDEN -m hashlimit --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-mode dstport --hashlimit-name hardenlog --hashlimit-htable-expire 100000 -j LOG --log-prefix "$LOGID $LOGPREF_HARDEN_TCP"
    fi

    # add the hardening rules
    if [ $HARDEN_PARANOID -gt 0 ];
        then
            # The XMAS Scan is a port scan:
            $IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DENYHARDEN

            # nmap null scan:
            $IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DENYHARDEN

            # nmap fin stealth portscan:
            $IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN -j DENYHARDEN
    fi
    # add even more hardening rules
    if [ $HARDEN_PARANOID -gt 1 ];
        then
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,PSH PSH -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ALL ALL -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DENYHARDEN
            $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DENYHARDEN
    fi

    # Handle PINGing 
    if [ $HARDEN_PING -eq 1 ];
        then
            echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
    elif [ $HARDEN_PING -eq 2 ];
        then
        echo "";
            $IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit  --limit $HARDEN_PINGRATE/s --limit-burst $HARDEN_PINGRATE -j ACCEPT
            $IPTABLES -A INPUT -p icmp --icmp-type echo-request -j DROP
    fi

    # Synflood protection
    if [ $HARDEN_SYNCOOKIES == true ];
        then
            echo 1 > /proc/sys/net/ipv4/tcp_syncookies
            echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog
            echo 3 > /proc/sys/net/ipv4/tcp_synack_retries
    fi
     
    # /proc hardening
    if [ $HARDEN_PROC == true ];
        then
            # Broadcast echo protection  
             echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
             # Disable ICMP redirect acceptance
             echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
             echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
             # Bad error message protection enabled
             echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
             # IP spoofing protection
             echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
             # Disable source routed packets
             echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
    fi
    # Martian logging
    if [ $HARDEN_LOG_MARTIANS == true ];
        then
            echo 1 >/proc/sys/net/ipv4/conf/all/log_martians
    fi

    # Now check against rate limits
    FILE=${DIR}/conf/limits.conf
     pp=() # port 
     ll=() # limit
     bb=() # burst
     
    while read line;do
        line=${line//[[:space:]]/}
        if [[ $line != *#* && "$line" != "" ]]
            then
                IFS='=' read -a Array <<< "${line}"

                if [[ ${Array[0]} =~ "burst" ]];
                    then    
                        y="${Array[0]%burst*}"
                        bb[${y}]=${Array[1]}
                      
                elif [[ ${Array[0]} =~ "limit" ]]
                    then 
                        x="${Array[0]%limit*}"
                        pp=( "${pp[@]}" "${x}" )
                        
                        if [ -z ${Array[1]} ]; 
                            then 
                                exitWithError "ERROR IN LIMITS CONFIG: Limit value missing in entry for port ${x}"
                            else 
                                ll[${x}]="${Array[1]}"
                        fi

                else
                    exitWithError "ERROR IN LIMITS CONFIG: entry without suffix (\"limit\" or \"burst\") found!"
                  
            fi

        fi
    done < $FILE

    for i in "${pp[@]}"
        do
            port=${i}
            limit=${ll[${i}]}
            name="port${i}"
            # if no burst value is given, we use limit as burst
            if [ -z ${bb[${i}]} ]; 
                then 
                    x=${ll[${i}]}
                    # check if time unit is given, needs to be removed for burst value
                    if [[ $x == *\/* ]]
                        then 
                            x="${x%/*}"
                    fi
                    burst=${x}
                else 
                    burst=${bb[${i}]}
            fi            
            $IPTABLES -A INPUT -p tcp --dport ${port} -m hashlimit --hashlimit-above ${limit} --hashlimit-burst ${burst} --hashlimit-mode srcip --hashlimit-name ${name} --hashlimit-htable-expire 100000 -j SPEEDLIMIT
        done
    if [ $LOG_LIMITS == true ];
        then
            $IPTABLES -I SPEEDLIMIT -m hashlimit --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-mode dstport --hashlimit-name speedlog --hashlimit-htable-expire 100000 -j LOG --log-prefix "$LOGID $LOGPREF_LIMIT"
    fi
    
    ### NOW CHECK PORTS ON INCOMING PACKETS
    # Almost done. Here comes the final group of rules: check whether the destination port may accept incoming traffic
    FILE=${DIR}/conf/port-whitelist.conf
    while read line;do
        line=${line//[[:space:]]/}
        if [[ $line != *#* && "$line" != "" ]]      
            then
                # find lines that do not have a = in them, indicating: all ips can access this port
                if [[ $line == *\=all* ]];
                    then 
                        port="${line%=*}"
                        $IPTABLES -A INPUT -p tcp --dport ${port} -j ACCEPT
                # Now identify lines containing a " ; ", indicating payload is an ip list
                 elif [[ $line == *\;* ]]
                    then 
                        port="${line%=*}"
                        iplist="${line#*=}"
                        IFS=';' 
                        for item in $iplist
                        do
                           $IPTABLES -A INPUT -p tcp --dport ${port} -s ${item} -j ACCEPT
                        done    
                 # Now identify lines containing a " - ". They carry an ip range
                 elif [[ $line == *\-* ]]
                    then 
                        port="${line%=*}"
                        range="${line#*=}"
                        tmp="${range%-*}"
                        start="${tmp##*.}"
                        net="${tmp%.*}"                    
                        end="${range#*-}"
                        out="${net}.${start}-${net}.${end}"
                        $IPTABLES -A INPUT -p tcp --dport ${port} -m iprange --src-range ${out} -j ACCEPT
                # and else we have a simple port=ip association
                else 
                    port="${line%=*}"
                    ip="${line#*=}"
                    $IPTABLES -A INPUT -p tcp --dport ${port} -s ${ip} -j ACCEPT
                fi
                
        fi
    done < $FILE

    echo "Firewall initialised."

} # end of main function


 function flushTables(){

    ### RESET RULES, CHAINS, COUNTERS
    # Flush all rules
    $IPTABLES -F
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
     
    # Remove all custom chains
    $IPTABLES -X
    $IPTABLES -t nat -X
    $IPTABLES -t mangle -X
     
    # zero all packet and byte counters 
    $IPTABLES -Z
    $IPTABLES -t nat -Z
    $IPTABLES -t mangle -Z

    ## And reset default policies
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
 } 
 function exitWithError(){
    echo -e "***************************************************"
    echo -e "*** AN ERROR OCCURRED:"
    echo -e "***\n***\n*** $1 "
    echo -e "***\n*** Now flushing all rules in iptables !\n***\n***"
    flushTables
    exit 1
 }
 main



