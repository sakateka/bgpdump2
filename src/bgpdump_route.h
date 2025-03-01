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

#ifndef _BGPDUMP_ROUTE_H_
#define _BGPDUMP_ROUTE_H_

#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>

#define ROUTE_LIMIT_DEFAULT "1000K"
#define ROUTE_PATH_LIMIT 128
#define ROUTE_COMM_LIMIT 32
#define ROUTE_EXTD_COMM_LIMIT 16
#define ROUTE_LARGE_COMM_LIMIT 16

#include "bgpdump.h"

struct __attribute__((__packed__)) bgp_extd_comm {
    uint8_t type;
    uint8_t subtype;
    uint8_t value[6];
};

struct __attribute__((__packed__)) bgp_large_comm {
    uint32_t global;
    uint32_t local1;
    uint32_t local2;
};

struct __attribute__((__packed__)) bgp_route {
    uint8_t flag;
    uint8_t prefix[MAX_ADDR_LENGTH];
    uint8_t af;
    uint8_t nexthop_af;
    uint8_t prefix_length;
    uint8_t nexthop[MAX_ADDR_LENGTH];
    uint8_t path_size;
    uint32_t origin_as;
    uint32_t path_list[ROUTE_PATH_LIMIT];
    uint8_t origin;
    uint8_t atomic_aggregate;
    uint32_t localpref;
    uint32_t med;
    uint32_t label;
    uint32_t community[ROUTE_COMM_LIMIT];
    struct bgp_extd_comm extd_community[ROUTE_COMM_LIMIT];
    uint8_t community_size;
    uint8_t extd_community_size;
    uint8_t large_community_size;
    struct bgp_large_comm large_community[ROUTE_LARGE_COMM_LIMIT];
    /* Misc flags */
    u_int localpref_set : 1, med_set : 1;
};

struct __attribute__((__packed__)) bgp_path_ {
    struct ptree_node *pnode;
    uint32_t refcount;
    uint16_t path_length;
    uint8_t af;
    uint8_t safi;
    /* List of all prefixes per path */
    CIRCLEQ_HEAD(bgp_path_head_, bgp_prefix_) path_qhead;
};

struct __attribute__((__packed__)) bgp_prefix_ {
    struct ptree_node *pnode;
    char prefix[MAX_ADDR_LENGTH];
    struct bgp_path_ *path;
    uint8_t prefix_length;
    uint8_t afi;
    uint16_t index;
    uint32_t label;
    /* List of all prefixes per path */
    CIRCLEQ_ENTRY(bgp_prefix_) prefix_qnode;
};

extern struct bgp_route *routes;
extern int route_limit;
extern int route_size;

extern char addr_none[];

#define IS_ROUTE_NULL(route)                                                   \
    ((route)->prefix_length == 0 &&                                            \
     !memcmp((route)->prefix, addr_none, MAX_ADDR_LENGTH) &&                   \
     !memcmp((route)->nexthop, addr_none, MAX_ADDR_LENGTH))

void
route_init();
void
route_finish();

struct bgp_route *
route_table_create();

void
route_print_brief(struct bgp_route *route);
void
route_print(struct bgp_route *route);
void
route_print_compat(struct bgp_route *route);

#endif /*_BGPDUMP_ROUTE_H_*/

/*
 * Local Variables:
 * c-basic-offset: 2
 * End:
 */
