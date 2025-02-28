## Build from source

### Install dependencies
```sh
sudo apt install libbz2-dev liblz-dev
```

###  Setup and compile
```sh
meson setup build
meson compile -C build

build/src/bgpdump2 -h
Usage: build/src/bgpdump2 [options] <file1> <file2> ...
-h, --help                     Display this help and exit.
-V, --version                  Print the program version.
-v, --verbose                  Print verbose information.
-d, --debug                    Display debug information.
-m, --compat-mode              Display in libbgpdump -m compatible mode.
-b, --brief                    List information (i.e., simple prefix-nexthops).
-B, --blaster <addr>[:port]    Blast RIB to a BGP speaker.
-D, --blaster-dump             Blast BGP stream to a file.
-T, --prefix-limit             Prefix limit for Blaster mode.
-S, --next-hop-self <addr>     Overwrite nexthop attribute.
-a, --autnum <asn>             Blaster Mode. Specify ASN. (default asn 65535)
                               At most 8 ASNs can be specified.
-w, --withdraw-delay           Blaster Mode. Send withdraw after <N> seconds.
-P, --peer-table               Display the peer table and exit.
-p, --peer <index>[,<index>]   Specify peers by peer_index.
                               At most 16 peers can be specified.
-u, --diff                     Shows unified diff. Specify two peers.
-U, --diff-verbose             Shows the detailed info of unified diff.
-r, --diff-table               Specify to create diff route_table.
-c, --count                    Count the route number.
-j, --plen-dist                Count the route number by prefixlen.
-k, --peer-stat                Shows prefix-length distribution.
-N, --bufsiz                   Specify the size of read buffer.
                               (default: 16MiB)
-M, --nroutes                  Specify the size of the route_table.
                               (default: 1000K)
-g, --benchmark                Measure the time to lookup.
-q, --quiet                    Minimal verbosity output
-l, --lookup <addr>            Specify lookup address.
-L, --lookup-file <file>       Specify lookup address from a file.
-4, --ipv4                     Specify that the query is IPv4. (default)
-6, --ipv6                     Specify that the query is IPv6.
-H, --heatmap <file-prefix>    Produces the heatmap.
-t, --log <log-name>           Turn on logging.
```

## Load test example
```sh
ulimit -n 65536
build/src/bgpdump2 -B $TARGET_IP:$TARGET_PORT \
    -p $INDEX [-p $INDEX ...] \
    [-a $LOCAL_AS] \
    [-T $PREFIX_COUNT] \
    -q \
    [-S $LOCAL_ADDR] mrt-file.bz2
```

### Bird config example
```c
router id 127.0.0.1;

protocol bgp mybgp {
│   local 127.0.0.1 port 6666 as 65535;
│   neighbor 127.0.0.1 internal;
│   ipv4 { export none; import all; };
│   ipv6 { export none; import all; };
}
```
