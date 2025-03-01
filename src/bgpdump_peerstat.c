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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ptree.h"

#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_peer.h"
#include "bgpdump_peerstat.h"
#include "bgpdump_route.h"

struct peer_stat peer_stat[PEER_MAX];

void
peer_stat_init() {
    int i, index;

    for (i = 0; i < PEER_MAX; i++)
        memset(&peer_stat[i], 0, sizeof(struct peer_stat));

    if (peer_spec_size) {
        for (i = 0; i < peer_spec_size; i++) {
            index = peer_spec_index[i];
            peer_stat[index].nexthop_count = ptree_create();
            peer_stat[index].origin_as_count = ptree_create();
            peer_stat[index].as_path_count = ptree_create();
            peer_stat[index].as_path_len_count = ptree_create();
        }
    } else {
        for (i = 0; i < PEER_MAX; i++) {
            peer_stat[i].nexthop_count = ptree_create();
            peer_stat[i].origin_as_count = ptree_create();
            peer_stat[i].as_path_count = ptree_create();
            peer_stat[i].as_path_len_count = ptree_create();
        }
    }
}

void
peer_stat_finish() {
    int i, index;
    if (peer_spec_size) {
        for (i = 0; i < peer_spec_size; i++) {
            index = peer_spec_index[i];
            ptree_delete(peer_stat[index].nexthop_count);
            ptree_delete(peer_stat[index].origin_as_count);
            ptree_delete(peer_stat[index].as_path_count);
            ptree_delete(peer_stat[index].as_path_len_count);
        }
    } else {
        for (i = 0; i < PEER_MAX; i++) {
            ptree_delete(peer_stat[i].nexthop_count);
            ptree_delete(peer_stat[i].origin_as_count);
            ptree_delete(peer_stat[i].as_path_count);
            ptree_delete(peer_stat[i].as_path_len_count);
        }
    }

    for (i = 0; i < PEER_MAX; i++)
        memset(&peer_stat[i], 0, sizeof(struct peer_stat));
}

void
peer_stat_save(int peer_index, struct bgp_route *route, uint8_t prefix_length) {
    struct ptree *t;
    struct ptree_node *n;
    uint64_t count;
    uint32_t path_size;
    uint32_t path_list[ROUTE_PATH_LIMIT];
    uint32_t netval;

    memset(path_list, 0, sizeof(uint32_t) * ROUTE_PATH_LIMIT);

    peer_stat[peer_index].route_count++;
    peer_stat[peer_index].route_count_by_plen[prefix_length]++;

    t = peer_stat[peer_index].nexthop_count;
    n = ptree_search_exact(&route->nexthop[0], 32, t);
    if (n) {
        count = (uint64_t)n->data;
        count++;
        n->data = (void *)count;
    } else {
        count = 1;
        ptree_add(route->nexthop, 32, (void *)count, t);
    }

    t = peer_stat[peer_index].origin_as_count;
    netval = htonl(route->origin_as);
    n = ptree_search_exact((uint8_t *)&netval, 32, t);
    if (n) {
        count = (uint64_t)n->data;
        count++;
        n->data = (void *)count;
    } else {
        count = 1;
        ptree_add((uint8_t *)&netval, 32, (void *)count, t);
    }

    t = peer_stat[peer_index].as_path_count;
    path_size = MIN(route->path_size, ROUTE_PATH_LIMIT);
    for (uint32_t i = 0; i < path_size; i++)
        path_list[i] = htonl(route->path_list[i]);
    n = ptree_search_exact((uint8_t *)path_list, 32 * path_size, t);
    if (n) {
        count = (uint64_t)n->data;
        count++;
        n->data = (void *)count;
    } else {
        count = 1;
        ptree_add((uint8_t *)path_list, 32 * path_size, (void *)count, t);
    }

    t = peer_stat[peer_index].as_path_len_count;
    n = ptree_search_exact((uint8_t *)&route->path_size, 8, t);
    if (n) {
        count = (uint64_t)n->data;
        count++;
        n->data = (void *)count;
    } else {
        count = 1;
        ptree_add(&route->path_size, 8, (void *)count, t);
    }
}

void
peer_stat_show() {
    int i, j, index;
    struct ptree *t;
    struct ptree_node *n;
    char buf[32];
    uint32_t netval;
    uint32_t val;
    uint64_t data;
    uint64_t count;
    int match = 0;

    for (i = 0; i < peer_size; i++) {
        match = 0;
        if (peer_spec_size) {
            for (j = 0; j < peer_spec_size; j++)
                if (i == peer_spec_index[j])
                    match++;
        } else
            match++;

        if (match)
            index = i;
        else
            continue;

        LOG(INFO, "peer[%d]:\n", index);
        LOG(INFO, "Number of routes: %lu\n", peer_stat[index].route_count);
        LOG(INFO, "Number of routes per plen:");
        for (j = 0; j < 33; j++) {
            if (j % 5 == 0)
                fprintf(stderr, "\n");
            fprintf(
                stderr,
                "    /%-2d: %6llu",
                j,
                (unsigned long long)peer_stat[index].route_count_by_plen[j]
            );
        }
        fprintf(stderr, "\n");

        count = 0;
        t = peer_stat[index].nexthop_count;
        for (n = ptree_head(t); n; n = ptree_next(n)) {
            if (!n->data)
                continue;

            memset(&val, 0, sizeof(val));
            memcpy(&val, n->key, (n->keylen + 7) / 8);
            inet_ntop(AF_INET, &val, buf, sizeof(buf));
            data = (uint64_t)n->data;

            LOG(DEBUG, "nexthop: %s/%d: count: %lu\n", buf, n->keylen, data);
            count++;
        }
        printf("Number of nexthops: %lu\n", (unsigned long)count);

        count = 0;
        t = peer_stat[index].origin_as_count;
        for (n = ptree_head(t); n; n = ptree_next(n)) {
            if (!n->data)
                continue;

            memset(&netval, 0, sizeof(netval));
            memcpy(&netval, n->key, (n->keylen + 7) / 8);
            val = ntohl(netval);
            data = (uint64_t)n->data;

            LOG(DEBUG, "origin_as: %u/%d: count: %lu\n", val, n->keylen, data);
            count++;
        }
        LOG(INFO, "Number of origin_as: %lu\n", (unsigned long)count);

        count = 0;
        t = peer_stat[index].as_path_count;
        for (n = ptree_head(t); n; n = ptree_next(n)) {
            if (!n->data)
                continue;

            uint32_t *p;
            data = (uint64_t)n->data;

            if (log_enabled(DEBUG)) {
                LOG(DEBUG, "unique as path:[");
                for (p = (uint32_t *)n->key;
                     (void *)p < (void *)n->key + ((n->keylen + 7) / 8);
                     p++) {
                    if ((void *)n->key < (void *)p)
                        fprintf(stderr, " ");
                    val = ntohl(*p);
                    fprintf(stderr, "%lu", (unsigned long)val);
                }
                fprintf(stderr, "]: count: %llu\n", (unsigned long long)data);
            }
            count++;
        }
        LOG(INFO, "Number of unique as paths: %lu\n", (unsigned long)count);

        count = 0;
        t = peer_stat[index].as_path_len_count;
        for (n = ptree_head(t); n; n = ptree_next(n)) {
            if (!n->data)
                continue;

            uint8_t len = *(uint8_t *)n->key;
            data = (uint64_t)n->data;

            LOG(DEBUG, "as_path_len: %d/%d: count: %lu\n", len, n->keylen, data
            );
            count++;
        }
        LOG(INFO, "Number of as path len: %lu\n", (unsigned long)count);
    }
}
