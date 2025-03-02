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

#include "bgpdump_ptree.h"
#include "bgpdump_route.h"
#include "ptree.h"

#include "bgpdump_data.h"
#include "bgpdump_log.h"
#include "bgpdump_peer.h"

struct peer peer_null;
struct peer peer_table[PEER_MAX];
int peer_size = 0;

int peer_spec_index[PEER_INDEX_MAX];
int peer_spec_size = 0;

struct bgp_route *peer_route_table[PEER_INDEX_MAX];
uint64_t peer_route_size[PEER_INDEX_MAX];
struct ptree *peer_ptree[PEER_INDEX_MAX];

int
peer_index_add(int val) {
    for (int i = 0; i < peer_spec_size; i++) {
        if (peer_spec_index[i] == val) {
            return 0;
        }
    }
    if (peer_spec_size == PEER_INDEX_MAX) {
        return -1;
    }
    peer_spec_index[peer_spec_size] = val;
    peer_spec_size++;
    return 0;
}

void
peer_table_init() {
    memset(&peer_null, 0, sizeof(struct peer));
    memset(peer_table, 0, sizeof(peer_table));
}

void
peer_print(int index, struct peer *peer) {
    char buf[64], buf2[64], buf3[64];
    inet_ntop(AF_INET, &peer->bgp_id, buf, sizeof(buf));
    inet_ntop(AF_INET, &peer->ipv4_addr, buf2, sizeof(buf2));
    inet_ntop(AF_INET6, &peer->ipv6_addr, buf3, sizeof(buf3));
    LOG(DEBUG,
        "# peer_table[%d] changed: %s asn:%u [%s|%s]\n",
        index,
        buf,
        peer->asnumber,
        buf2,
        buf3);
}

void
peer_route_count_show() {
    printf("#timestamp,peer_idx1:peer1,peer_idx2:peer2,...\n");
    printf("%u,", timestamp);
    for (int i = 0; i < peer_size; i++) {
        if (i > 0)
            printf(",");
        printf("%d:%lu", i, peer_table[i].route_count);
    }
    printf("\n");
    fflush(stdout);
}

void
peer_route_count_clear() {
    int i;
    for (i = 0; i < peer_size; i++)
        peer_table[i].route_count = 0;
}

void
peer_route_count_by_plen_show() {
    for (int i = 0; i < peer_size; i++) {
        if (peer_spec_size) {
            int match = 0;
            for (int j = 0; j < peer_spec_size; j++)
                if (i == peer_spec_index[j])
                    match++;

            if (!match)
                continue;
        }

        printf("%u,", timestamp);
        for (int i = 0; i < 33; i++) {
            if (i > 0)
                printf(",");
            printf("%lu", peer_table[i].route_count_by_plen[i]);
        }
        printf("\n");
    }
}

void
peer_route_count_by_plen_clear() {
    int i, j;
    for (i = 0; i < peer_size; i++)
        for (j = 0; j < 33; j++)
            peer_table[i].route_count_by_plen[j] = 0;
}

char *
fmt_peer_spec_index(char *buf, size_t buf_size) {
    char *p = buf;
    int64_t size = (int64_t)buf_size;
    p[0] = '\0';

    for (int i = 0; i < peer_spec_size; i++) {
        if (size < 2) {
            break;
        }
        if (i > 0) {
            p[0] = ',';
            p++;
            size--;
        }
        int n = snprintf(p, size, "%d", peer_spec_index[i]);
        if (n <= 0) {
            break;
        }
        p += n;
        size -= n;
    }
    buf[buf_size - 1] = '\0';
    return buf;
}
