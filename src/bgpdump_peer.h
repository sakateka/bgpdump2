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
#pragma once

#include <netinet/in.h>

struct peer {
    struct in_addr bgp_id;
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    uint32_t asnumber;
    uint64_t route_count;
    uint64_t route_count_by_plen[129];
    struct ptree *ipv4_root;
    struct ptree *ipv6_root;
    struct ptree *path_root;
    uint32_t ipv4_count;
    uint32_t ipv6_count;
    uint32_t path_count;
};

#define PEER_MAX 256

#define PEER_INDEX_MAX 32

extern struct peer peer_null;
extern struct peer peer_table[];
extern int peer_size;

extern int32_t peer_spec_index[];
extern int32_t peer_spec_size;

extern struct bgp_route *peer_route_table[];
extern uint64_t peer_route_size[];
extern struct ptree *peer_ptree[];

void
peer_table_init();
void
peer_print(int index, struct peer *peer);
void
peer_route_count_show();
void
peer_route_count_clear();
void
peer_route_count_by_plen_show();
void
peer_route_count_by_plen_clear();
char *
fmt_peer_spec_index(char *buf, size_t buf_size);
