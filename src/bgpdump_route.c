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
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_peer.h"
#include "bgpdump_route.h"

extern uint32_t timestamp;
extern uint16_t peer_index;

struct bgp_route *routes;
int route_limit = 0;
int route_size = 0;

uint8_t addr_none[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void
route_init() {
    route_limit = nroutes;
    routes = malloc(route_limit * sizeof(struct bgp_route));
    assert(routes);
    memset(routes, 0, route_limit * sizeof(struct bgp_route));
}

void
route_finish() {
    free(routes);
}

struct bgp_route *
route_table_create() {
    struct bgp_route *table;
    int table_size = nroutes * sizeof(struct bgp_route);
    table = malloc(table_size);
    assert(table);
    memset(table, 0, table_size);
    return table;
}

void
route_print_brief(struct bgp_route *route) {
    char buf[64], buf2[64];
    if (inet_ntop(route->af, route->prefix, buf, sizeof(buf)) == NULL) {
        LOG(WARN,
            "failed to convert route prefix to af=%d: %s\n",
            route->af,
            strerror(errno));
    }
    if (inet_ntop(route->af, route->nexthop, buf2, sizeof(buf2)) == NULL) {
        LOG(WARN,
            "failed to convert nexthop to af=%d: %s\n",
            route->af,
            strerror(errno));
    }
    printf("%s/%d %s\n", buf, route->prefix_length, buf2);
}

void
route_print(struct bgp_route *route) {
    int i;
    char buf[64], buf2[64];
    if (inet_ntop(route->af, route->prefix, buf, sizeof(buf)) == NULL) {
        LOG(WARN,
            "failed to convert route prefix to af=%d: %s\n",
            route->af,
            strerror(errno));
    }
    if (inet_ntop(route->af, route->nexthop, buf2, sizeof(buf2)) == NULL) {
        LOG(WARN,
            "failed to convert nexthop to af=%d: %s\n",
            route->af,
            strerror(errno));
    }
    printf("%s/%d %s", buf, route->prefix_length, buf2);
    if (route->label) {
        printf(" label %u", route->label);
    }
    printf(" origin_as: %lu", (unsigned long)route->origin_as);
    printf(" as-path[%d]:", route->path_size);
    for (i = 0; i < MIN(route->path_size, ROUTE_PATH_LIMIT); i++)
        printf(" %lu", (unsigned long)route->path_list[i]);
    printf("\n");
}

void
route_print_compat(struct bgp_route *route) {
    int i;
    char prefix[64];
    char nexthop[64];
    char peer_addr[64];
    unsigned long peer_asn;

    char *p, *e;
    char as_path[128];
    char *origin;

    unsigned long localpref;
    unsigned long med;
    unsigned long community;

    if (inet_ntop(route->af, route->prefix, prefix, sizeof(prefix)) == NULL) {
        LOG(WARN,
            "failed to convert route prefix to af=%d: %s\n",
            route->af,
            strerror(errno));
    }
    int plen = route->prefix_length;
    int af = plen == 4 ? AF_INET : AF_INET6;
    if (inet_ntop(af, route->nexthop, nexthop, sizeof(nexthop)) == NULL) {
        LOG(WARN,
            "failed to convert nexthop to af=%d: %s\n",
            af,
            strerror(errno));
    }
    inet_ntop(
        AF_INET, &peer_table[peer_index].ipv4_addr, peer_addr, sizeof(peer_addr)
    );
    peer_asn = peer_table[peer_index].asnumber;

    p = as_path;
    e = as_path + sizeof(as_path);
    for (i = 0; i < MIN(route->path_size, ROUTE_PATH_LIMIT); i++) {
        if (i == 0)
            snprintf(p, e - p, "%lu", (unsigned long)route->path_list[i]);
        else
            snprintf(p, e - p, " %lu", (unsigned long)route->path_list[i]);
        p = as_path + strlen(as_path);
    }

    switch (route->origin) {
    case '0':
        origin = "IGP";
        break;
    case '1':
        origin = "EGP";
        break;
    case '2':
    default:
        origin = "INCOMPLETE";
        break;
    }

    char *atomicaggr;
    char *atomicaggr_asn_addr;

    localpref = route->localpref;
    med = route->med;
    community = route->community[0];

    atomicaggr = (route->atomic_aggregate > 0 ? "AG" : "NAG");
    atomicaggr_asn_addr = "";

#if 0
  printf ("TABLE_DUMP2|Timestamp|B|Peer IP Address|Peer ASN|"
          "Prefix/Plen|AS-Path|Origin|Nexthop|LocalPref|MED|"
          "Community|AtomAggr|AggrAS AggrAddr|\n");
#endif

    printf(
        "TABLE_DUMP2|%lu|B|%s|%lu|"
        "%s/%d|%s|%s|%s|%lu|%lu|"
        "%lu|%s|%s|\n",
        (unsigned long)timestamp,
        peer_addr,
        (unsigned long)peer_asn,
        prefix,
        plen,
        as_path,
        origin,
        nexthop,
        (unsigned long)localpref,
        (unsigned long)med,
        (unsigned long)community,
        atomicaggr,
        atomicaggr_asn_addr
    );
}
