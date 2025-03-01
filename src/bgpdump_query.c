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
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "bgpdump_log.h"
#include "bgpdump_query.h"
#include "bgpdump_route.h"

#define QUERY_LIMIT_DEFAULT (1000 * 1000 * 1000)
struct query *query_table;
uint64_t query_limit = QUERY_LIMIT_DEFAULT;
uint64_t query_size = 0;

void
query_init() {
    query_table = malloc(query_limit * sizeof(struct query));
    assert(query_table);
    memset(query_table, 0, query_limit * sizeof(struct query));
}

void
query_addr(char *lookup_addr) {
    printf("looking up an address: %s\n", lookup_addr);
    if (inet_pton(
            AF_INET, lookup_addr, query_table[query_size++].destination
        )) {
    } else if (inet_pton(
                   AF_INET6, lookup_addr, query_table[query_size++].destination
               )) {
    } else {
        LOG(ERROR, "failed to parse lookup_addr: %s", lookup_addr);
        exit(1);
    }
}

unsigned long
query_file_count(char *lookup_file) {
    unsigned long count = 0;
    char *p, buf[32];
    FILE *fp;

    fp = fopen(lookup_file, "r");
    if (fp == NULL) {
        printf("warning: couldn't open file: %s\n", lookup_file);
        return 0;
    }

    while (1) {
        p = fgets(buf, sizeof(buf), fp);
        if (p == NULL)
            break;
        count++;
    }
    fclose(fp);
    return count;
}

void
query_file(char *lookup_file) {
    FILE *fp;
    char *p, buf[32];
    fp = fopen(lookup_file, "r");
    if (fp == NULL) {
        printf("warning: couldn't open file: %s\n", lookup_file);
        return;
    }

    while (1) {
        if (query_limit == query_size)
            break;
        p = fgets(buf, sizeof(buf), fp);
        if (p == NULL)
            break;
        p = index(buf, '\n');
        if (p)
            *p = '\0';

        query_addr(buf);
    }
    fclose(fp);
}

#define HAS_QUERY_NEXTHOP(q) (memcmp((q)->nexthop, addr_none, MAX_ADDR_LENGTH))

void
query_list() {
    for (uint64_t i = 0; i < query_size; i++) {
        if (HAS_QUERY_NEXTHOP(&query_table[i])) {
            char buf[64], buf2[64];
            int af = query_table[i].plen == 4 ? AF_INET : AF_INET6;
            inet_ntop(af, query_table[i].destination, buf, sizeof(buf));
            inet_ntop(af, query_table[i].nexthop, buf2, sizeof(buf2));
            printf("destination: %s nexthop: %s\n", buf, buf2);
        }
    }
}
