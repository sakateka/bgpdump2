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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "ptree.h"

#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_query.h"
#include "bgpdump_route.h"

void
ptree_list(struct ptree *ptree) {
    uint64_t count = 0;
    struct ptree_node *x;
    struct bgp_route *br;
    char buf[64], buf2[64];

    printf("listing ptree.\n");
    for (x = ptree_head(ptree); x; x = ptree_next(x)) {
        if (x->data) {
            br = x->data;
            inet_ntop(br->af, br->prefix, buf, sizeof(buf));
            inet_ntop(br->nexthop_af, br->nexthop, buf2, sizeof(buf2));
            printf("%s/%d: %s\n", buf, br->prefix_length, buf2);
            count++;
        }
        if (log_enabled(DEBUG))
            ptree_node_print(x);
    }
    printf("number of routes: %llu\n", (unsigned long long)count);
}

void
ptree_query(
    struct ptree *ptree, struct query *query_table, uint64_t query_size
) {

    for (uint64_t i = 0; i < query_size; i++) {
        struct query *q = &query_table[i];
        struct ptree_node *x = ptree_search(q->destination, q->plen, ptree);
        if (x) {
            struct bgp_route *route = x->data;
            memcpy(q->nexthop, route->nexthop, MAX_ADDR_LENGTH); // copy answer
            if (!benchmark)
                route_print(route);
        } else if (!benchmark) {
            char buf[64];
            int af = q->plen == 4 ? AF_INET : AF_INET6;
            inet_ntop(af, q->destination, buf, sizeof(buf));
            LOG(WARN, "%s: no route found.\n", buf);
        }
    }
}
