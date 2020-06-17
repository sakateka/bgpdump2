#break bgpdump_add_prefix
#break bgpdump_blaster
set args -q -p 1 -B 192.168.202.119 latest-bview2
#break timer_walk
break bgpdump_ribwalk_cb
set auto-load safe-path /
set print pretty
handle SIGPIPE nostop noprint pass
