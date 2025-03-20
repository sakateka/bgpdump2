/*
 * Bgpdump2: A Tool to Read and Compare the BGP RIB Dump Files.
 * Copyright (C) 2015.  Yasuhiro Ohara <yasu@nttv6.jp>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <config.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_parse.h"
#include "bgpdump_peer.h"
#include "bgpdump_route.h"

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

const char *optstring = "hVmbB:w:DT:S:Pp:a:uUrcjkN:M:gL:f:H:l:";
const struct option longopts[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {"compat-mode", no_argument, NULL, 'm'},
    {"brief", no_argument, NULL, 'b'},
    {"blaster", required_argument, NULL, 'B'},
    {"withdraw-delay", required_argument, NULL, 'w'},
    {"blaster-dump", no_argument, NULL, 'D'},
    {"prefix-limit", required_argument, NULL, 'T'},
    {"next-hop-self", required_argument, NULL, 'S'},
    {"peer-table", no_argument, NULL, 'P'},
    {"peer", required_argument, NULL, 'p'},
    {"autnum", required_argument, NULL, 'a'},

    {"diff", no_argument, NULL, 'u'},
    {"diff-verbose", no_argument, NULL, 'U'},
    {"diff-table", no_argument, NULL, 'r'},
    {"count", no_argument, NULL, 'c'},
    {"plen-dist", no_argument, NULL, 'j'},
    {"peer-stat", no_argument, NULL, 'k'},
    {"bufsiz", required_argument, NULL, 'N'},

    {"nroutes", required_argument, NULL, 'M'},

    {"benchmark", no_argument, NULL, 'g'},
    {"lookup", required_argument, NULL, 'L'},
    {"lookup-file", required_argument, NULL, 'f'},
    {"heatmap", required_argument, NULL, 'H'},
    {"log", required_argument, NULL, 'l'},
    {NULL, 0, NULL, 0}
};

const char opthelp[] = "\
-h, --help                      Display this help and exit.\n\
-V, --version                   Print the program version.\n\
-m, --compat-mode               Display in libbgpdump -m compatible mode.\n\
-b, --brief                     List information (i.e., simple prefix-nexthops).\n\
-B, --blaster <addr>[:port]     Blast RIB to a BGP speaker.\n\
-w, --withdraw-delay  <secs>    Blaster Mode. Send withdraw after <N> seconds.\n\
-D, --blaster-dump              Blast BGP stream to a file.\n\
-T, --prefix-limit              Prefix limit for Blaster mode.\n\
-S, --next-hop-self <addr>      Overwrite nexthop attribute.\n\
-P, --peer-table                Display the peer table and exit.\n\
-p, --peer <index>[,<index>]    Select peers by peer_index (max %d) (default all).\n\
-a, --autnum <asn> [-a ...]     Blaster Mode. Specify ASN (max %d) (default asn %d).\n\
-u, --diff                      Shows unified diff. Specify two peers.\n\
-U, --diff-verbose              Shows the detailed info of unified diff.\n\
-r, --diff-table                Specify to create diff route_table.\n\
-c, --count                     Count the route number.\n\
-j, --plen-dist                 Count the route number by prefixlen.\n\
-k, --peer-stat                 Shows prefix-length distribution.\n\
\
-N, --bufsiz                    Specify the size of read buffer (default: %s).\n\
-M, --nroutes                   Specify the size of the route_table (default: %s).\n\
\
-g, --benchmark                 Measure the time to lookup.\n\
-L, --lookup <addr>             Specify lookup address.\n\
-f, --lookup-file <file>        Specify lookup address from a file.\n\
-H, --heatmap <file-prefix>     Produces the heatmap.\n\
-l, --log <trace|debug|info...> Turn on logging.\n\
";

int longindex;

int compat_mode = 0;
int brief = 0;
int peer_table_only = 0;
int udiff = 0;
int udiff_verbose = 0;
int udiff_lookup = 0;
int route_count = 0;
int plen_dist = 0;
int stats = 0;
unsigned long long bufsiz = 0;
unsigned long long nroutes = 0;
int benchmark = 0;
int lookup = 0;
char *lookup_addr = NULL;
char *lookup_file = NULL;
int heatmap = 0;
char *heatmap_prefix;
int blaster = 0;
char *blaster_addr = NULL;
int blaster_dump = 0;
uint64_t prefix_limit = 0;
struct sockaddr_in nhs_addr4;
struct sockaddr_in6 nhs_addr6;
int withdraw_delay = 0;

extern char *progname;
extern int qaf;

extern unsigned long autnums[];
extern int autsiz;

void
usage() {
    printf("Usage: %s [options] <file1> <file2> ...\n", progname);
    printf(
        opthelp,
        PEER_INDEX_MAX,
        AUTLIM,
        DEFAULT_AS_NUM,
        BGPDUMP_BUFSIZ_DEFAULT,
        ROUTE_LIMIT_DEFAULT
    );
}

void
version() {
    printf("Version: %s\n", PACKAGE_VERSION);
}

int
bgpdump_getopt(int argc, char **argv) {
    int status = 0;
    char *endptr;

    log_enable_name("info");

    while (1) {
        int ch = getopt_long(argc, argv, optstring, longopts, &longindex);

        if (ch == -1)
            break;

        switch (ch) {
        case 'h':
            usage();
            exit(0);
            break;
        case 'V':
            version();
            exit(0);
            break;
        case 'm':
            compat_mode++;
            break;
        case 'b':
            brief++;
            break;
        case 'B':
            blaster++;
            blaster_addr = optarg;
            break;
        case 'w':
            withdraw_delay = strtoul(optarg, &endptr, 0);
            break;
        case 'D':
            blaster_dump++;
            break;
        case 'T':
            prefix_limit = strtoul(optarg, &endptr, 0);
            break;
        case 'S':
            if (inet_pton(AF_INET, optarg, &nhs_addr4.sin_addr)) {
                nhs_addr4.sin_port = 1; // addr is set
                char sbuf[64];
                inet_ntop(AF_INET, &nhs_addr4.sin_addr, sbuf, sizeof(sbuf));
                LOG(INFO, "rewrite ipv4 next hop to %s\n", sbuf);
            } else if (inet_pton(AF_INET6, optarg, &nhs_addr6.sin6_addr)) {
                nhs_addr6.sin6_port = 1; // addr is set
                char sbuf[64];
                inet_ntop(AF_INET6, &nhs_addr6.sin6_addr, sbuf, sizeof(sbuf));
                LOG(INFO, "rewrite ipv6 next hop to %s\n", sbuf);
            }
            break;

        case 'P':
            peer_table_only++;
            break;
        case 'p':
            for (char *nums = optarg, *endptr;; nums = NULL) {
                char *token = strtok(nums, ",");
                if (token == NULL) {
                    break;
                }
                int val = strtoul(token, &endptr, 0);
                if (endptr && *endptr != '\0') {
                    printf("malformed peer_index: '%s'\n", optarg);
                    exit(-1);
                }
                if (peer_index_add(val)) {
                    printf(
                        "too many peer indices, more then %d\n", PEER_INDEX_MAX
                    );
                    exit(-1);
                }
            }
            break;
        case 'a':
            for (char *nums = optarg, *endptr;; nums = NULL) {
                char *token = strtok(nums, ",");
                if (token == NULL) {
                    break;
                }
                int val = strtoul(token, &endptr, 0);
                if (endptr && *endptr != '\0') {
                    printf("malformed autnum: %s\n", optarg);
                    exit(-1);
                }
                autnums[autsiz % AUTLIM] = val;
                autsiz++;
                if (autsiz >= AUTLIM) {
                    printf("too many autnums, more then %d\n", AUTLIM);
                    exit(-1);
                }
            }
            break;
        case 'u':
            udiff++;
            break;
        case 'U':
            udiff++;
            udiff_verbose++;
            break;
        case 'r':
            udiff_lookup++;
            break;
        case 'c':
            route_count++;
            break;
        case 'j':
            plen_dist++;
            break;
        case 'k':
            stats++;
            break;
        case 'N':
            bufsiz = resolv_number(optarg, &endptr);
            if (*endptr != '\0') {
                printf("malformed bufsiz: %s\n", optarg);
                exit(-1);
            }
            break;
        case 'M':
            nroutes = resolv_number(optarg, &endptr);
            if (*endptr != '\0') {
                printf("malformed nroutes: %s\n", optarg);
                exit(-1);
            }
            break;

        case 'g':
            benchmark++;
            break;
        case 'L':
            lookup++;
            lookup_addr = optarg;
            break;
        case 'f':
            lookup++;
            lookup_file = optarg;
            break;
        case 'H':
            heatmap++;
            heatmap_prefix = optarg;
            break;
        case 'l':
            log_enable_name(optarg);
            break;

        case 0:
            /* Process flag pointer. */
            break;
        case ':':
            fprintf(stderr, "A missing option argument.\n");
            status = -1;
            break;
        case '?':
            fprintf(stderr, "An unknown/ambiguous option.\n");
            status = -1;
            break;
        default:
            usage();
            status = -1;
            break;
        }
    }

    return status;
}
