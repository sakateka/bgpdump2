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

#ifndef _BGPDUMP_DATA_H_
#define _BGPDUMP_DATA_H_

#include "bgpdump_route.h"
#include <stddef.h>
#include <stdint.h>

#define BGP_AFI_IPV4 1
#define BGP_AFI_IPV6 2

#define BGP_SAFI_UNICAST 1
#define BGP_SAFI_MULTICAST 2
#define BGP_SAFI_MPLS 4
#define BGP_SAFI_MPLS_VPN 128
#define BGP_SAFI_VPN_MULTICAST 129
#define BGP_SAFI_FLOW 133

#define BGPDUMP_TYPE_DEPRECATED_MRT_NULL 0
#define BGPDUMP_TYPE_DEPRECATED_MRT_START 1
#define BGPDUMP_TYPE_DEPRECATED_MRT_DIE 2
#define BGPDUMP_TYPE_DEPRECATED_MRT_I_AM_DEAD 3
#define BGPDUMP_TYPE_DEPRECATED_MRT_PEER_DOWN 4
#define BGPDUMP_TYPE_DEPRECATED_BGP 5
#define BGPDUMP_TYPE_DEPRECATED_RIP 6
#define BGPDUMP_TYPE_DEPRECATED_IDRP 7
#define BGPDUMP_TYPE_DEPRECATED_RIPNG 8
#define BGPDUMP_TYPE_DEPRECATED_BGP4PLUS 9
#define BGPDUMP_TYPE_DEPRECATED_BGP4PLUS_01 10

#define BGPDUMP_TYPE_OSPFV2 11
#define BGPDUMP_TYPE_TABLE_DUMP 12
#define BGPDUMP_TYPE_TABLE_DUMP_V2 13
#define BGPDUMP_TYPE_BGP4MP 16
#define BGPDUMP_TYPE_BGP4MP_ET 17
#define BGPDUMP_TYPE_ISIS 32
#define BGPDUMP_TYPE_ISIS_ET 33
#define BGPDUMP_TYPE_OSPFV3 48
#define BGPDUMP_TYPE_OSPFV3_ET 49

#define BGPDUMP_TABLE_V2_PEER_INDEX_TABLE 1
#define BGPDUMP_TABLE_V2_RIB_IPV4_UNICAST 2
#define BGPDUMP_TABLE_V2_RIB_IPV4_MULTICAST 3
#define BGPDUMP_TABLE_V2_RIB_IPV6_UNICAST 4
#define BGPDUMP_TABLE_V2_RIB_IPV6_MULTICAST 5
#define BGPDUMP_TABLE_V2_RIB_GENERIC 6
#define BGPDUMP_TABLE_V2_RIB_GEO_PEER_TABLE 7
#define BGPDUMP_TABLE_V2_RIB_IPV4_UNICAST_ADDPATH 8
#define BGPDUMP_TABLE_V2_RIB_IPV4_MULTICAST_ADDPATH 9
#define BGPDUMP_TABLE_V2_RIB_IPV6_UNICAST_ADDPATH 10
#define BGPDUMP_TABLE_V2_RIB_IPV6_MULTICAST_ADDPATH 11
#define BGPDUMP_TABLE_V2_RIB_GENERIC_ADDPATH 12

#define FLAG_PEER_ADDRESS_IPV6 0x01
#define FLAG_AS_NUMBER_SIZE 0x02

#define OPTIONAL 0b10000000
#define TRANSITIVE 0b01000000
#define PARTIAL 0b00100000
#define EXTENDED 0b00010000

#define ORIGIN 1
#define AS_PATH 2
#define NEXT_HOP 3
#define MULTI_EXIT_DISC 4
#define LOCAL_PREF 5
#define ATOMIC_AGGREGATE 6
#define AGGREGATOR 7
#define COMMUNITY 8
#define MP_REACH_NLRI 14
#define MP_UNREACH_NLRI 15
#define EXTENDED_COMMUNITY 16
#define LARGE_COMMUNITY 32

struct mrt_header {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

struct mrt_info {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

extern uint32_t timestamp;

/*
 * Data structure used for parsing BGP path attributes.
 * For each attribute the location is set using the pa_start array.
 * For quick presence check the respective bit in the bitmap is set.
 */
struct bgpdump_pa_map_ {
    uint8_t pa_bitmap[32];   /* one bit for each PA found */
    uint8_t *pa_start[256];  /* start for each PA */
    uint16_t pa_length[256]; /* length for each PA */
};

void
bgpdump_process_bgp_attributes(struct bgp_route *, uint8_t *, uint8_t *);

uint16_t
bgpdump_process_mrt_header(struct mrt_header *h, struct mrt_info *info);

void
bgpdump_process_table_dump_v2(
    struct mrt_header *h, struct mrt_info *info, uint8_t *data_end
);
char *
bgpdump_print_extd_comm(struct bgp_extd_comm *comm);

void
bgpdump_index_bgp_pa(
    struct bgpdump_pa_map_ *pa_map, uint8_t *buffer, uint16_t buffer_len
);

uint16_t
bgpdump_filter_bgp_pa_copy_nh(
    struct bgpdump_pa_map_ *pa_map, uint8_t *filtered_path, uint8_t *nexthop
);

#endif /*_BGPDUMP_DATA_H_*/
