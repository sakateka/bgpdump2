set args -q -p 1 -B 192.168.202.119 -S 1.2.3.4 latest-bview2
#break timer_walk
break bgpdump_ribwalk_cb
set auto-load safe-path /
set print pretty
handle SIGPIPE nostop noprint pass
