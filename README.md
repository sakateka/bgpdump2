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
-h, --help                      Display this help and exit.
-V, --version                   Print the program version.
-m, --compat-mode               Display in libbgpdump -m compatible mode.
-b, --brief                     List information (i.e., simple prefix-nexthops).
-B, --blaster <addr>[:port]     Blast RIB to a BGP speaker.
-w, --withdraw-delay  <secs>    Blaster Mode. Send withdraw after <N> seconds.
-D, --blaster-dump              Blast BGP stream to a file.
-T, --prefix-limit              Prefix limit for Blaster mode.
-S, --next-hop-self <addr>      Overwrite nexthop attribute.
-P, --peer-table                Display the peer table and exit.
-p, --peer <index>[,<index>]    Select peers by peer_index (max 32) (default all).
-a, --autnum <asn> [-a ...]     Blaster Mode. Specify ASN (max 8) (default asn 65535).
-u, --diff                      Shows unified diff. Specify two peers.
-U, --diff-verbose              Shows the detailed info of unified diff.
-r, --diff-table                Specify to create diff route_table.
-c, --count                     Count the route number.
-j, --plen-dist                 Count the route number by prefixlen.
-k, --peer-stat                 Shows prefix-length distribution.
-N, --bufsiz                    Specify the size of read buffer (default: 16MiB).
-M, --nroutes                   Specify the size of the route_table (default: 1000K).
-g, --benchmark                 Measure the time to lookup.
-L, --lookup <addr>             Specify lookup address.
-f, --lookup-file <file>        Specify lookup address from a file.
-H, --heatmap <file-prefix>     Produces the heatmap.
-l, --log <trace|debug|info...> Turn on logging.
```

## Load test example

`lbzcat` is significantly faster than the built-in `bz2` decompressor.
`lbzcat` scales linearly with the number of threads.
```sh
time lbzcat -n 10 -d data/rib.20250227.0000.bz2 > /dev/null

real	0m2.097s
user	0m20.732s
sys	0m0.153s

$ time bzcat -d data/rib.20250227.0000.bz2 > /dev/null

real	0m15.806s
user	0m15.763s
sys	0m0.042s
```

```sh
build/src/bgpdump2 -B $TARGET_IP:$TARGET_PORT \
    -p $INDEX [-p $INDEX ...] \
    [-a $LOCAL_AS] \
    [-T $PREFIX_COUNT] \
    -q \
    [-S $LOCAL_ADDR] <(lbzcat -n 10 -d data/*.bz2)
```

### Bird config example
```c
router id 127.0.0.1;

protocol bgp mybgp {
    local 127.0.0.1 port 6666 as 65535;
    neighbor 127.0.0.1 internal;
    ipv4 { export none; import all; };
    ipv6 { export none; import all; };
}
```
