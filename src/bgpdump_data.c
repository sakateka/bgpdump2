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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "bgpdump.h"
#include "bgpdump_data.h"
#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_peer.h"
#include "bgpdump_peerstat.h"
#include "bgpdump_route.h"
#include "bgpdump_udiff.h"
#include "ptree.h"

extern struct bgp_route *diff_table[];
extern struct ptree *diff_ptree[];

uint32_t timestamp;
uint16_t peer_index;

#define BUFFER_OVERRUN_CHECK(P, SIZE, END)                                     \
    _BUFFER_OVERRUN_CHECK(P, SIZE, END, __FILE_NAME__, __LINE__, __FUNCTION__)
#define _BUFFER_OVERRUN_CHECK(P, SIZE, END, file, line, desc)                  \
    if ((P) + (SIZE) > (END)) {                                                \
        LOG(ERROR,                                                             \
            "[%s:%d] %s buffer %p size=%ld overrun=%ld.\n",                    \
            file,                                                              \
            line,                                                              \
            desc,                                                              \
            (P),                                                               \
            (size_t)(SIZE),                                                    \
            (END) - ((P) + (SIZE)));                                           \
        exit(-1);                                                              \
    }

#define read_u8(r, e) _read_u8(r, e, __FILE_NAME__, __LINE__)
static inline uint8_t
_read_u8(uint8_t **r, uint8_t *end, const char *file, int line) {
    _BUFFER_OVERRUN_CHECK(*r, 1, end, file, line, "read_u8");
    uint8_t out = (uint8_t)**r;
    *r += 1;
    return out;
}

#define read_u16(r, e) _read_u16(r, e, __FILE_NAME__, __LINE__)
static inline uint16_t
_read_u16(uint8_t **r, uint8_t *end, const char *file, int line) {
    _BUFFER_OVERRUN_CHECK(*r, 2, end, file, line, "read_u16");
    uint16_t out = ntohs(*(uint16_t *)*r);
    *r += 2;
    return out;
}

#define read_u24(r, e) _read_u24(r, e, __FILE_NAME__, __LINE__)
static inline uint32_t
_read_u24(uint8_t **r, uint8_t *end, const char *file, int line) {
    _BUFFER_OVERRUN_CHECK(*r, 3, end, file, line, "read_u24");
    uint32_t out =
        *(uint8_t *)*r << 16 | *(uint8_t *)(*r + 1) << 8 | *(uint8_t *)(*r + 2);
    r += 3;
    return out;
}
#define read_u32(r, e) _read_u32(r, e, __FILE_NAME__, __LINE__)
static inline uint32_t
_read_u32(uint8_t **r, uint8_t *end, const char *file, int line) {
    _BUFFER_OVERRUN_CHECK(*r, 4, end, file, line, "read_u32");
    uint32_t out = ntohl(*(uint32_t *)*r);
    *r += 4;
    return out;
}

#define read_n(b, bs, r, l, e) _read_n(b, bs, r, l, e, __FILE_NAME__, __LINE__)
void
_read_n(
    uint8_t *buf,
    int buf_size,
    uint8_t **r,
    int len,
    uint8_t *end,
    const char *file,
    int line
) {
    _BUFFER_OVERRUN_CHECK(
        buf, buf_size, buf + buf_size, file, line, "read_n[dst buf]"
    );
    _BUFFER_OVERRUN_CHECK(*r, len, end, file, line, "read_n[src data]");
    if (buf_size > len) {
        memset(buf, 0, buf_size);
    }
    memcpy(buf, *r, len);
    *r += len;
}

int
bgpdump_resolve_afi(int afi) {
    switch (afi) {
    case BGP_AFI_IPV4:
        return AF_INET;
        break;
    case BGP_AFI_IPV6:
        return AF_INET6;
        break;
    default:
        return -1;
    }
}

uint16_t
bgpdump_process_mrt_header(struct mrt_header *h, struct mrt_info *info) {
    uint32_t newtime = ntohl(h->timestamp);

    if (log_enabled(INFO) && timestamp != newtime) {
        struct tm *tm;
        char timebuf[64];
        time_t clock;

        clock = (time_t)newtime;
        tm = localtime(&clock);
        strftime(timebuf, sizeof(timebuf), "%Y/%m/%d %H:%M:%S", tm);
        LOG(INFO,
            "new timestamp: %lu (\"%s\")\n",
            (unsigned long)ntohl(h->timestamp),
            timebuf);
    }

    timestamp = newtime;
    uint16_t mrt_type = ntohs(h->type);
    uint16_t mrt_subtype = ntohs(h->subtype);
    uint32_t mrt_length = ntohl(h->length);

    info->timestamp = newtime;
    info->type = ntohs(h->type);
    info->subtype = ntohs(h->subtype);
    info->length = ntohl(h->length);

    LOG(TRACE,
        "MRT Header: ts: %u type: %hu sub: %hu len: %u\n",
        timestamp,
        mrt_type,
        mrt_subtype,
        mrt_length);

    return mrt_type;
}

int
bgpdump_table_v2_peer_entry(int index, uint8_t *p, uint8_t *data_end) {
    int total = 0;

    uint8_t peer_type = read_u8(&p, data_end);
    total += 1;

    int af = peer_type & FLAG_PEER_ADDRESS_IPV6 ? AF_INET6 : AF_INET;
    int asn4byte = peer_type & FLAG_AS_NUMBER_SIZE ? 1 : 0;

    struct in_addr peer_bgp_id;
    int len = sizeof(struct in_addr);
    read_n((uint8_t *)&peer_bgp_id, len, &p, len, data_end);
    total += len;

    struct in6_addr addr;
    len = af == AF_INET6 ? 16 : 4;
    read_n((uint8_t *)&addr, len, &p, len, data_end);
    total += len;

    len = asn4byte ? 4 : 2;
    uint32_t asnumber =
        asn4byte ? read_u32(&p, data_end) : (uint32_t)read_u16(&p, data_end);
    total += len;

    if (log_enabled(INFO)) {
        char buf[64], buf2[64];
        inet_ntop(AF_INET, &peer_bgp_id, buf, sizeof(buf));
        inet_ntop(af, &addr, buf2, sizeof(buf2));
        LOG(INFO,
            "Peer[%d]: Type: %s%s%s(%#02x) "
            "BGP ID: %-15s AS: %-5u Address: %-15s\n",
            index,
            (peer_type & FLAG_PEER_ADDRESS_IPV6 ? "ipv6" : ""),
            ((peer_type & FLAG_PEER_ADDRESS_IPV6) &&
                     (peer_type & FLAG_AS_NUMBER_SIZE)
                 ? "|"
                 : ""),
            (peer_type & FLAG_AS_NUMBER_SIZE ? "4byte-as" : ""),
            peer_type,
            buf,
            asnumber,
            buf2);
    }

    if (index < PEER_MAX) {
        struct peer new;
        memset(&new, 0, sizeof(new));
        new.bgp_id = peer_bgp_id;
        new.ipv6_addr = (struct in6_addr)addr;
        new.ipv4_addr = *((struct in_addr *)&addr);
        new.asnumber = asnumber;
        new.ipv4_root = ptree_create();
        new.ipv6_root = ptree_create();
        new.path_root = ptree_create();

        if (log_enabled(DEBUG) && peer_table_only &&
            memcmp(&peer_table[index], &peer_null, sizeof(struct peer)) &&
            memcmp(&peer_table[index], &new, sizeof(struct peer))) {
            peer_print(index, &new);
        }

        peer_table[index] = new;
        peer_size = index + 1;
    } else
        LOG(ERROR, "peer_table overflow.\n");

    if (autsiz) {
        int i, local_peer_spec_size = peer_spec_size;
        for (i = 0; i < autsiz; i++) {
            if (peer_table[index].asnumber == autnums[i] &&
                local_peer_spec_size < PEER_INDEX_MAX) {
                printf(
                    "peer_spec_index[%d]: register peer %d, asn %d\n",
                    local_peer_spec_size,
                    index,
                    peer_table[index].asnumber
                );
                peer_spec_index[local_peer_spec_size] = index;
                peer_route_table[local_peer_spec_size] = route_table_create();
                peer_route_size[local_peer_spec_size] = 0;
                peer_ptree[local_peer_spec_size] = ptree_create();
                local_peer_spec_size++;
            }
        }
    }

    return total;
}

void
bgpdump_process_table_v2_peer_index_table(
    struct mrt_header *h, struct mrt_info *info, uint8_t *data_end
) {
    (void)info;

    uint8_t *p = (uint8_t *)h + sizeof(struct mrt_header);

    /* Collector BGP ID */
    struct in_addr collector_bgp_id;
    collector_bgp_id.s_addr = read_u32(&p, data_end);

    /* View Name Length */
    uint16_t view_name_length = read_u16(&p, data_end);

    /* View Name */
    BUFFER_OVERRUN_CHECK(p, view_name_length, data_end)
    uint8_t *view_name = p;
    p += view_name_length;

    /* Peer Count */
    uint16_t peer_count = read_u16(&p, data_end);

    if (peer_table_only || log_enabled(DEBUG)) {
        char buf[64];
        inet_ntop(AF_INET, &collector_bgp_id, buf, sizeof(buf));
        LOG(INFO, "Collector BGP ID: %s\n", buf);
        LOG(INFO, "View Name Length: %d\n", (int)view_name_length);
        LOG(INFO, "View Name: %s\n", view_name);
        LOG(INFO, "Peer Count: %d\n", (int)peer_count);
    }

    for (int i = 0; i < peer_count; i++) {
        p += bgpdump_table_v2_peer_entry(i, p, data_end);
    }
}

char *
bgpdump_print_extd_comm(struct bgp_extd_comm *comm) {
    static char buf[64];
#if 0
  char ipaddr_buf[64];
#endif

    switch (comm->type << 8 | comm->subtype) {
#if 0 /* BDS does not yet support this */

  case 0x0002:
    snprintf(buf, sizeof(buf), "target:%u:%u",
	     comm->value[0] << 8 |
	     comm->value[1],
	     comm->value[2] << 24 |
	     comm->value[3] << 16 |
	     comm->value[4] << 8 |
	     comm->value[5]);
    break;
  case 0x0102:
    inet_ntop(AF_INET, &comm->value[0], ipaddr_buf, sizeof(ipaddr_buf));
    snprintf(buf, sizeof(buf), "target:%s:%u",
	     ipaddr_buf, comm->value[4] << 8 | comm->value[5]);
    break;
  case 0x0202:
    snprintf(buf, sizeof(buf), "target:%u:%u",
	     comm->value[0] << 24 |
	     comm->value[1] << 16 |
	     comm->value[2] << 8 |
	     comm->value[3],
	     comm->value[4] << 8 |
	     comm->value[5]);
    break;
  case 0x0003:
    snprintf(buf, sizeof(buf), "origin:%u:%u",
	     comm->value[0] << 8 |
	     comm->value[1],
	     comm->value[2] << 24 |
	     comm->value[3] << 16 |
	     comm->value[4] << 8 |
	     comm->value[5]);
    break;
  case 0x0103:
    inet_ntop(AF_INET, &comm->value[0], ipaddr_buf, sizeof(ipaddr_buf));
    snprintf(buf, sizeof(buf), "origin:%s:%u",
	     ipaddr_buf, comm->value[4] << 8 | comm->value[5]);
    break;
  case 0x0203:
    snprintf(buf, sizeof(buf), "origin:%u:%u",
	     comm->value[0] << 24 |
	     comm->value[1] << 16 |
	     comm->value[2] << 8 |
	     comm->value[3],
	     comm->value[4] << 8 |
	     comm->value[5]);
    break;
#endif
    default:
        snprintf(
            buf,
            sizeof(buf),
            "raw:0x%02x%02x%02x%02x%02x%02x%02x%02x",
            comm->type,
            comm->subtype,
            comm->value[0],
            comm->value[1],
            comm->value[2],
            comm->value[3],
            comm->value[4],
            comm->value[5]
        );
        break;
    }

    return buf;
}

const char *
bgpdump_attr_name(uint8_t attr_type) {
    static char unknown_buf[16];
    switch (attr_type) {
    case ORIGIN:
        return "origin";
    case AS_PATH:
        return "as-path";
    case NEXT_HOP:
        return "next-hop";
    case MULTI_EXIT_DISC:
        return "multi-exit-disc";
    case LOCAL_PREF:
        return "local-pref";
    case ATOMIC_AGGREGATE:
        return "atomic-aggregate";
    case AGGREGATOR:
        return "aggregator";
    case COMMUNITY:
        return "community";
    case MP_REACH_NLRI:
        return "mp-reach-nlri";
    case MP_UNREACH_NLRI:
        return "mp-unreach-nlri";
    case EXTENDED_COMMUNITY:
        return "extended-community";
    case LARGE_COMMUNITY:
        return "large-community";
    default:
        snprintf(unknown_buf, sizeof(unknown_buf), "unknown (%d)", attr_type);
        return unknown_buf;
    }
}

void
bgpdump_print_attrs(uint8_t atype, uint8_t aflags, uint16_t alen) {
    const char *name = bgpdump_attr_name(atype);
    char flags[64];
    snprintf(
        flags,
        sizeof(flags),
        "%s, %s, %s%s",
        (aflags & OPTIONAL ? "optional" : "well-known"),
        (aflags & TRANSITIVE ? "transitive" : "non-transitive"),
        (aflags & PARTIAL ? "partial" : "complete"),
        (aflags & EXTENDED ? ", extended-length" : "")
    );
    printf("  attr: %s <%s> (%#04x) len: %d\n", name, flags, atype, alen);
}

void
bgpdump_process_bgp_attributes(
    struct bgp_route *route, uint8_t *start, uint8_t *end
) {
    uint8_t *p = (uint8_t *)start;

    while (p + 3 < end) {
        uint8_t attr_flags = read_u8(&p, end);
        uint8_t attr_type = read_u8(&p, end);

        uint16_t attr_len =
            attr_flags & EXTENDED ? read_u16(&p, end) : read_u8(&p, end);
        LOG(TRACE,
            "Attribute len=%d type=%s\n",
            attr_len,
            bgpdump_attr_name(attr_type));

        if (log_enabled(DEBUG)) {
            bgpdump_print_attrs(attr_type, attr_flags, attr_len);
        }

        BUFFER_OVERRUN_CHECK(p, attr_len, end)
        uint8_t *r = p;
        switch (attr_type) {
        case ORIGIN:
            if (log_enabled(DEBUG))
                printf("    origin: %d\n", *r);
            route->origin = read_u8(&r, end);
            break;

        case AS_PATH: {
            while (r < p + attr_len) {
                uint8_t stype = read_u8(&r, end);
                uint8_t path_size = read_u8(&r, end);

                if (log_enabled(DEBUG))
                    printf(
                        "    as_path[%s:%d]:",
                        (stype == 1 ? "set" : "seq"),
                        path_size
                    );

                route->path_size = path_size;
                for (int i = 0; i < path_size; i++) {
                    uint32_t as_path = read_u32(&r, end);

                    if (log_enabled(DEBUG))
                        printf(" %u", as_path);

                    if (i < ROUTE_PATH_LIMIT)
                        route->path_list[i] = as_path;
                    else {
                        if (log_enabled(DEBUG))
                            printf("\n");
                        LOG(ERROR, "path_list buffer overflow.\n");
                        route_print(route);
                    }

                    if (i == path_size - 1) {
                        route->origin_as = as_path;
                    }
                }

                if (log_enabled(DEBUG))
                    printf("\n");
            }
        } break;

        case NEXT_HOP: {
            if (attr_len != 4) {
                break;
            }
            memset(route->nexthop, 0, sizeof(route->nexthop));
            read_n(route->nexthop, 16, &r, attr_len, end);
            route->nexthop_af = AF_INET;
            if (log_enabled(DEBUG)) {
                char buf[64];
                inet_ntop(route->nexthop_af, route->nexthop, buf, sizeof(buf));
                LOG(DEBUG, "    nexthop: %s\n", buf);
            }
        } break;

        case AGGREGATOR:
            r += attr_len;
            break;
        case ATOMIC_AGGREGATE:
            if (log_enabled(DEBUG))
                printf("    atomic_aggregate: len: %d\n", attr_len);
            route->atomic_aggregate++;
            break;

        case LOCAL_PREF:
            route->localpref_set = 1;
            route->localpref = read_u32(&r, end);
            if (log_enabled(DEBUG))
                printf("    local-pref: %u\n", route->localpref);
            break;

        case MULTI_EXIT_DISC:
            route->med_set = 1;
            route->med = read_u32(&r, end);
            if (log_enabled(DEBUG))
                printf("    med: %u\n", route->med);
            break;

        case COMMUNITY: {
            route->community_size = attr_len >> 2;
            if (route->community_size > ROUTE_COMM_LIMIT) {
                route->community_size = ROUTE_COMM_LIMIT;
            }

            for (int idx = 0; idx < route->community_size; idx++) {
                route->community[idx] = read_u32(&r, end);

                if (log_enabled(DEBUG)) {
                    printf(
                        "%s %u:%u",
                        idx ? "," : "    community:",
                        route->community[idx] >> 16,
                        route->community[idx] & 0xffff
                    );
                }
            }

            if (log_enabled(DEBUG))
                printf("\n");
        } break;
        case EXTENDED_COMMUNITY: {
            route->extd_community_size = attr_len >> 3;
            if (route->extd_community_size > ROUTE_EXTD_COMM_LIMIT) {
                route->extd_community_size = ROUTE_EXTD_COMM_LIMIT;
            }

            for (int idx = 0; idx < route->extd_community_size; idx++) {
                read_n(
                    (uint8_t *)&route->extd_community[idx],
                    sizeof(struct bgp_extd_comm),
                    &r,
                    sizeof(struct bgp_extd_comm),
                    end
                );

                if (log_enabled(DEBUG)) {
                    printf(
                        "%s %s",
                        idx ? "," : "    extended-community:",
                        bgpdump_print_extd_comm(&route->extd_community[idx])
                    );
                }
            }

            if (log_enabled(DEBUG))
                printf("\n");
        } break;

        case LARGE_COMMUNITY: {
            route->large_community_size = attr_len / 12;
            if (route->large_community_size > ROUTE_LARGE_COMM_LIMIT) {
                route->large_community_size = ROUTE_LARGE_COMM_LIMIT;
            }

            for (int idx = 0; idx < route->large_community_size; idx++) {
                route->large_community[idx].global = read_u32(&r, end);
                route->large_community[idx].local1 = read_u32(&r, end);
                route->large_community[idx].local2 = read_u32(&r, end);

                if (log_enabled(DEBUG)) {
                    printf(
                        "%s %u:%u:%u",
                        idx ? "," : "    large-community:",
                        route->large_community[idx].global,
                        route->large_community[idx].local1,
                        route->large_community[idx].local2
                    );
                }
            }

            if (log_enabled(DEBUG))
                printf("\n");
        } break;

        case MP_REACH_NLRI: {
            // https://datatracker.ietf.org/doc/html/rfc4760#section-3
            uint16_t afi = read_u16(&r, end);
            int af = bgpdump_resolve_afi(afi);
            if (af == -1) {
                LOG(WARN, "failed to convert afi=%d to AF, ignore\n", afi);
                break;
            }
            uint8_t safi = read_u8(&r, end);
            uint8_t len = read_u8(&r, end);

            memset(route->nexthop, 0, sizeof(route->nexthop));
            read_n(
                route->nexthop,
                sizeof(route->nexthop),
                &r,
                MIN(len, sizeof(route->nexthop)),
                end
            );
            route->nexthop_af = af;

            if (len == 2 * sizeof(struct in6_addr)) {
                uint8_t nexthop2[16];
                read_n(nexthop2, 16, &r, 16, end);

                if (log_enabled(DEBUG)) {
                    char bufn1[64], bufn2[64];
                    inet_ntop(af, route->nexthop, bufn1, sizeof(bufn1));
                    inet_ntop(af, nexthop2, bufn2, sizeof(bufn2));
                    LOG(DEBUG, "link-local nexthop: %s:%s\n", bufn1, bufn2);
                }
            }
            if (r >= p + attr_len) { /* reserved present ? */
                break;
            }
            r++; /* reserved */

            uint8_t nlri_prefix[16];
            while (r < p + attr_len) {
                uint8_t nlri_plen = read_u8(&r, end);
                uint8_t byte_len = (nlri_plen + 7) / 8;
                if (byte_len == 0) {
                    continue;
                }
                memset(nlri_prefix, 0, sizeof(nlri_prefix));
                read_n(nlri_prefix, sizeof(nlri_prefix), &r, byte_len, end);
                // TODO: remove copypaste
                if (log_enabled(DEBUG)) {
                    char buf[64], buf2[64];
                    inet_ntop(af, route->nexthop, buf2, sizeof(buf2));
                    inet_ntop(af, nlri_prefix, buf, sizeof(buf));
                    LOG(DEBUG,
                        "    MP_REACH_NLRI: (afi/safi: %d/%d) %s(size:%d) "
                        "%s/%d\n",
                        afi,
                        safi,
                        buf2,
                        len,
                        buf,
                        nlri_plen);
                }
            }
        } break;
        case MP_UNREACH_NLRI: {
            // https://datatracker.ietf.org/doc/html/rfc4760#section-4
            uint16_t afi = read_u16(&r, end);
            int af = bgpdump_resolve_afi(afi);
            if (af == -1) {
                LOG(WARN, "failed to convert afi=%d to AF, ignore\n", afi);
                break;
            }
            uint8_t safi = read_u8(&r, end);

            uint8_t nlri_prefix[16];
            while (r < p + attr_len) {
                uint8_t nlri_plen = read_u8(&r, end);
                uint8_t byte_len = (nlri_plen + 7) / 8;
                if (byte_len == 0) {
                    continue;
                }
                memset(nlri_prefix, 0, sizeof(nlri_prefix));
                read_n(nlri_prefix, sizeof(nlri_prefix), &r, byte_len, end);
                // TODO: remove copypaste
                if (log_enabled(DEBUG)) {
                    char buf[64];
                    inet_ntop(af, nlri_prefix, buf, sizeof(buf));
                    LOG(DEBUG,
                        "    MP_UNREACH_NLRI: (afi/safi: %d/%d) %s/%d\n",
                        afi,
                        safi,
                        buf,
                        nlri_plen);
                }
            }
        } break;

        default:
            break;
        }

        if (r != p + attr_len) {
            LOG(DEBUG,
                "ERROR: failed to parse attribute, unparsed=%ld\n",
                (p + attr_len) - r);
        }
        p += attr_len;
    }
}

void
bgpdump_rewrite_nh(uint8_t *raw_path, uint16_t path_length) {
    uint8_t pa_flags, pa_type;
    uint16_t pa_length;
    uint8_t *pa;

    pa = raw_path;
    while (pa < (raw_path + path_length)) {
        pa_flags = *pa;
        pa_type = *(pa + 1);
        pa += 2;
        if (pa_flags & 0x10) { /* extended length ? */
            pa_length = *pa << 8 | *(pa + 1);
            pa += 2;
        } else {
            pa_length = *pa;
            pa++;
        }

        switch (pa_type) {
        case NEXT_HOP: /* ipv4 next hop */
            if (nhs == AF_INET) {
                memcpy(pa, &nhs_addr4.sin_addr, 4);
            }
            return;
        case MP_REACH_NLRI: {
            uint16_t afi;
            uint8_t safi, nh_len;

            afi = *pa << 8 | *(pa + 1);
            safi = *(pa + 2);
            nh_len = *(pa + 3);

            /* ipv6 unicast */
            if (nhs == AF_INET6 && afi == 2 && safi == 1 && nh_len == 16) {
                memcpy(pa + 4, &nhs_addr6.sin6_addr, 16);
            }

            /* ipv6 labeled unicast */
            if (nhs == AF_INET6 && afi == 2 && safi == 4 && nh_len == 16) {
                memcpy(pa + 4, &nhs_addr6.sin6_addr, 16);
            }

            /* ipv6 unicast, mapped ipv4 nexthop */
            if (nhs == AF_INET && afi == 2 && safi == 1 && nh_len == 16) {
                memcpy(pa + 4 + 12, &nhs_addr4.sin_addr, 4);
            }

            /* ipv6 labeled unicast, mapped ipv4 nexthop */
            if (nhs == AF_INET && afi == 2 && safi == 4 && nh_len == 16) {
                memcpy(pa + 4 + 12, &nhs_addr4.sin_addr, 4);
            }

            /* ipv4 labeled unicast */
            if (nhs == AF_INET && afi == 1 && safi == 4 && nh_len == 4) {
                memcpy(pa + 4, &nhs_addr4.sin_addr, 4);
            }
        }
            return;
        default:
            break;
        }
        pa += pa_length;
    }
}

/*
 * Mark a given PA type as found.
 */
void
bgpdump_set_pa_bit(struct bgpdump_pa_map_ *pa_map, uint8_t pa_type) {
    uint offset;

    offset = pa_type >> 3;
    pa_map->pa_bitmap[offset] |= (1L << (pa_type & 0x7));
}

/*
 * Mark a given PA type as processed.
 */
void
bgpdump_reset_pa_bit(struct bgpdump_pa_map_ *pa_map, uint8_t pa_type) {
    uint offset;

    offset = pa_type >> 3;
    pa_map->pa_bitmap[offset] ^= (1L << (pa_type & 0x7));
}

/*
 * Check if a given PA type was found.
 */
bool
bgpdump_get_pa_bit(struct bgpdump_pa_map_ *pa_map, uint8_t pa_type) {
    uint offset;

    offset = pa_type >> 3;
    return (pa_map->pa_bitmap[offset] & (1L << (pa_type & 0x7)));
}

/*
 * Index the PA block, such that we can have a quick handle for accessing
 * individual PAs.
 */
void
bgpdump_index_bgp_pa(
    struct bgpdump_pa_map_ *pa_map, uint8_t *buffer, uint16_t buffer_len
) {
    uint8_t pa_flags, pa_type;
    uint16_t pa_length;

    /*
     * Quick way of resetting the PA map index.
     */
    memset(&pa_map->pa_bitmap, 0, sizeof(pa_map->pa_bitmap));

    while (buffer_len > 3) {
        pa_flags = *buffer;
        pa_type = *(buffer + 1);

        /* record beginning of PA */
        pa_map->pa_start[pa_type] = buffer;

        buffer += 2;
        buffer_len -= 2;
        pa_map->pa_length[pa_type] = 2;

        if (pa_flags & 0x10) { /* Extended length ? */
            pa_length = *buffer << 8 | *(buffer + 1);
            buffer += 2;
            pa_map->pa_length[pa_type] += 2;
            buffer_len -= 2;
        } else {
            pa_length = *buffer;
            buffer++;
            pa_map->pa_length[pa_type] += 1;
            buffer_len--;
        }

        /* Check if pa_length overruns buffer */
        if (pa_length > buffer_len) {
            return;
        }

        /*
         * Update the index map, where we have found a particular PA.
         */
        pa_map->pa_length[pa_type] += pa_length;
        bgpdump_set_pa_bit(pa_map, pa_type);

        buffer += pa_length;
        buffer_len -= pa_length;
    }
}

void
bgpdump_copy_pa(
    struct bgpdump_pa_map_ *pa_map, uint8_t pa_type, uint8_t **fpap
) {
    if (!bgpdump_get_pa_bit(pa_map, pa_type)) {
        return;
    }

    memcpy(*fpap, pa_map->pa_start[pa_type], pa_map->pa_length[pa_type]);
    *fpap += pa_map->pa_length[pa_type];

    bgpdump_reset_pa_bit(pa_map, pa_type);
}

uint16_t
bgpdump_filter_bgp_pa_copy_nh(
    struct bgpdump_pa_map_ *pa_map, uint8_t *filtered_path, uint8_t *nexthop
) {
    uint8_t *fp = filtered_path;

    /* Copy the known PAs */
    bgpdump_copy_pa(pa_map, ORIGIN, &fp);
    bgpdump_copy_pa(pa_map, NEXT_HOP, &fp);
    bgpdump_copy_pa(pa_map, AS_PATH, &fp);
    bgpdump_copy_pa(pa_map, MULTI_EXIT_DISC, &fp);
    bgpdump_copy_pa(pa_map, LOCAL_PREF, &fp);
    bgpdump_copy_pa(pa_map, ATOMIC_AGGREGATE, &fp);
    bgpdump_copy_pa(pa_map, AGGREGATOR, &fp);
    bgpdump_copy_pa(pa_map, COMMUNITY, &fp);
    bgpdump_copy_pa(pa_map, EXTENDED_COMMUNITY, &fp);
    bgpdump_copy_pa(pa_map, LARGE_COMMUNITY, &fp);

    if (bgpdump_get_pa_bit(pa_map, MP_REACH_NLRI)) {

        uint8_t pa_flags, nh_len;
        uint8_t *buffer;

        /*
         * Extract the nexthop.
         */
        buffer = pa_map->pa_start[MP_REACH_NLRI];

        pa_flags = *buffer;
        if (pa_flags & 0x10) { /* extended length ? */
            buffer += 4;
        } else {
            buffer += 3;
        }

        nh_len = *(buffer + 3);
        buffer += 4;
        memcpy(nexthop, buffer, nh_len);
    }

    return fp - filtered_path;
}

uint16_t
bgpdump_filter_bgp_pa_trim_nh(
    struct bgpdump_pa_map_ *pa_map, uint8_t *filtered_path
) {
    uint8_t *fp;

    fp = filtered_path;

    /* Copy the known PAs */
    bgpdump_copy_pa(pa_map, ORIGIN, &fp);
    bgpdump_copy_pa(pa_map, NEXT_HOP, &fp);
    bgpdump_copy_pa(pa_map, AS_PATH, &fp);
    bgpdump_copy_pa(pa_map, MULTI_EXIT_DISC, &fp);
    bgpdump_copy_pa(pa_map, LOCAL_PREF, &fp);
    bgpdump_copy_pa(pa_map, ATOMIC_AGGREGATE, &fp);
    bgpdump_copy_pa(pa_map, AGGREGATOR, &fp);
    bgpdump_copy_pa(pa_map, COMMUNITY, &fp);
    bgpdump_copy_pa(pa_map, EXTENDED_COMMUNITY, &fp);
    bgpdump_copy_pa(pa_map, LARGE_COMMUNITY, &fp);

    if (bgpdump_get_pa_bit(pa_map, MP_REACH_NLRI)) {

        uint16_t afi;
        uint8_t safi, pa_flags, nh_len;
        uint8_t *buffer;

        /*
         * Truncate the NLRI by copying the nexthop.
         */
        buffer = pa_map->pa_start[MP_REACH_NLRI];

        pa_flags = *buffer;
        if (pa_flags & 0x10) { /* extended length ? */
            buffer += 4;
        } else {
            buffer += 3;
        }

        afi = *buffer << 8 | *(buffer + 1);
        safi = *(buffer + 2);
        nh_len = *(buffer + 3);
        buffer += 4;

        *fp++ = pa_flags | 0x10; /* extended length */
        *fp++ = MP_REACH_NLRI;
        *fp++ = 0;
        *fp++ = 4 + nh_len; /* PA length */
        *fp++ = 0;
        *fp++ = afi;
        *fp++ = safi;
        *fp++ = nh_len;
        memcpy(fp, buffer, nh_len);
        fp += nh_len;
    }

    return fp - filtered_path;
}

void
bgpdump_add_prefix(
    struct bgp_route *route, int index, uint8_t *raw_path, uint16_t path_length
) {
    struct bgp_path_ *bgp_path;
    struct ptree_node *bgp_path_node;
    struct bgp_prefix_ *bgp_prefix;
    struct bgpdump_pa_map_ pa_map;
    uint8_t filtered_path[4096];

    /*
     * First index the path attributes. We may need to filter the prefix
     * list in MP_REACH_NLRI PA.
     */
    bgpdump_index_bgp_pa(&pa_map, (uint8_t *)raw_path, path_length);
    uint16_t filtered_path_length =
        bgpdump_filter_bgp_pa_trim_nh(&pa_map, filtered_path);
    if (!filtered_path_length) {
        return;
    }

    /*
     * Check first if the path-attributes are known.
     */
    bgp_path_node = ptree_search(
        filtered_path, filtered_path_length * 8, peer_table[index].path_root
    );

    if (!bgp_path_node) {

        if (!filtered_path_length) {
            return;
        }

        bgp_path = calloc(1, sizeof(struct bgp_path_));
        if (!bgp_path) {
            return;
        }

        /*
         * Add fresh BGP path to the tree.
         */
        if (route->label) {
            bgp_path->safi = 4; /* labeled-unicast */
        } else {
            bgp_path->safi = 1; /* unicast */
        }
        bgp_path->af = route->af;
        bgp_path->pnode = ptree_add(
            filtered_path,
            filtered_path_length * 8,
            bgp_path,
            peer_table[index].path_root
        );
        if (bgp_path->pnode) {
            peer_table[index].path_count++;
        }
        bgp_path->path_length = filtered_path_length;
        CIRCLEQ_INIT(&bgp_path->path_qhead);
    } else {
        bgp_path = bgp_path_node->data;
    }

    bgp_prefix = calloc(1, sizeof(struct bgp_prefix_));
    memcpy(&bgp_prefix->prefix, &route->prefix, (route->prefix_length + 7) / 8);
    bgp_prefix->prefix_length = route->prefix_length;
    bgp_prefix->label = route->label;
    bgp_prefix->index = index;

    if (bgp_path->af == AF_INET) {
        bgp_prefix->pnode = ptree_add(
            route->prefix,
            route->prefix_length,
            bgp_prefix,
            peer_table[index].ipv4_root
        );
        if (bgp_prefix->pnode) {
            peer_table[index].ipv4_count++;
        }
    } else if (bgp_path->af == AF_INET6) {
        bgp_prefix->pnode = ptree_add(
            route->prefix,
            route->prefix_length,
            bgp_prefix,
            peer_table[index].ipv6_root
        );
        if (bgp_prefix->pnode) {
            peer_table[index].ipv6_count++;
        }
    }

    CIRCLEQ_INSERT_TAIL(
        &bgp_path->path_qhead, bgp_prefix, prefix_qnode
    ); // NOLINT
    bgp_prefix->path = bgp_path;
    bgp_path->refcount++;
}

void
bgpdump_process_table_v2_rib_entry(
    int index,
    int af,
    uint32_t sequence_number,
    uint32_t label,
    uint8_t *prefix,
    uint8_t prefix_length,

    uint8_t **q,
    uint8_t *data_end
) {

    uint8_t *p = *q;

    peer_index = read_u16(&p, data_end);
    uint32_t originated_time = read_u32(&p, data_end);
    uint16_t attribute_length = read_u16(&p, data_end);

    int peer_spec_i = 0;
    int peer_match = 0;
    for (int i = 0; i < peer_spec_size; i++) {
        if (peer_index == peer_spec_index[i]) {
            peer_spec_i = i;
            peer_match++;
        }
    }

    if (peer_spec_size)
        LOG(TRACE, "peer_index: %d, peer_match: %d\n", peer_index, peer_match);

    if (!peer_spec_size || peer_match) {
        LOG(TRACE,
            "rib[%d]: peer[%d] originated_time: %u attribute_length: %d\n",
            index,
            peer_index,
            originated_time,
            attribute_length);

        if (peer_index < PEER_MAX) {
            if (route_count)
                peer_table[peer_index].route_count++;

            if (plen_dist)
                peer_table[peer_index].route_count_by_plen[prefix_length]++;
        }

        struct bgp_route route;

        memset(&route, 0, sizeof(route));
        memcpy(route.prefix, prefix, (prefix_length + 7) / 8);
        route.prefix_length = prefix_length;
        route.label = label;
        route.af = af;

        if ((brief || lookup || udiff || stats || compat_mode || autsiz ||
             heatmap) &&
            (!blaster || !blaster_dump)) {
            bgpdump_process_bgp_attributes(&route, p, p + attribute_length);
        }

        /*
         * For the blaster add the prefix and the path attributes to the
         * peer-RIB.
         */
        if (blaster || blaster_dump) {
            /* next hop rewrite ? */
            if (nhs) {
                bgpdump_rewrite_nh((uint8_t *)p, attribute_length);
            }

            uint32_t count =
                MAX(peer_table[peer_index].ipv4_count,
                    peer_table[peer_index].ipv6_count);
            if (!prefix_limit || count < prefix_limit) {
                bgpdump_add_prefix(&route, peer_index, p, attribute_length);
            }
        }

        /* Now all the BGP attributes for this rib_entry are processed. */

        if (stats) {
            int i, peer_match = 0;

            if (peer_spec_size == 0)
                peer_match++;
            else {
                for (i = 0; i < peer_spec_size; i++)
                    if (peer_index == peer_spec_index[i])
                        peer_match++;
            }

            if (peer_match) {
                // printf ("peer_stat_save: peer: %d\n", peer_index);
                peer_stat_save(peer_index, &route, prefix_length);
            }
        }

        if (peer_spec_size && (!blaster && !blaster_dump)) {
            struct bgp_route *rp;
            uint64_t *route_size = &peer_route_size[peer_spec_i];
            if (*route_size >= nroutes) {
                LOG(ERROR, "route table overflow.\n");
                *route_size = nroutes - 1;
            }

            struct bgp_route *rpp = peer_route_table[peer_spec_i];
            rp = &rpp[sequence_number];
            // rp = &peer_route_table[peer_index][sequence_number];
            *route_size = *route_size + 1;
            //(*route_size)++;

            // route_print (&route);
            memcpy(rp, &route, sizeof(struct bgp_route));

            ptree_add(
                rp->prefix,
                rp->prefix_length,
                (void *)rp,
                peer_ptree[peer_spec_i]
            );
        }

        if (udiff) {
            for (int i = 0; i < MIN(peer_spec_size, 2); i++) {
                if (peer_spec_index[i] == peer_index) {
                    diff_table[i][sequence_number] = route;
                    if (udiff_lookup)
                        ptree_add(
                            route.prefix,
                            route.prefix_length,
                            (void *)&diff_table[i][sequence_number],
                            diff_ptree[i]
                        );
                }
            }
        }

        if (brief)
            route_print_brief(&route);
        else if (compat_mode)
            route_print_compat(&route);
        else if (log_enabled(TRACE))
            route_print(&route);
    }

    BUFFER_OVERRUN_CHECK(p, attribute_length, data_end)
    p += attribute_length;

    *q = p;
}

void
bgpdump_process_table_v2_rib_unicast(
    int af, struct mrt_header *h, struct mrt_info *info, uint8_t *data_end
) {
    (void)info;
    uint8_t *p = (uint8_t *)h + sizeof(struct mrt_header);

    uint32_t sequence_number = read_u32(&p, data_end);
    uint8_t prefix_length = read_u8(&p, data_end);

    uint32_t prefix_size = ((prefix_length + 7) / 8);
    uint8_t prefix[16];
    read_n(prefix, sizeof(prefix), &p, prefix_size, data_end);
    uint16_t entry_count = read_u16(&p, data_end);

    if (log_enabled(TRACE)) {
        char pbuf[64];
        inet_ntop(af, prefix, pbuf, sizeof(pbuf));
        LOG(TRACE,
            "Sequence Number: %u Prefix %s/%d Entry Count: %d\n",
            sequence_number,
            pbuf,
            prefix_length,
            entry_count);
    }

    for (int i = 0; i < entry_count && p < data_end; i++) {
        bgpdump_process_table_v2_rib_entry(
            i, af, sequence_number, 0, prefix, prefix_length, &p, data_end
        );
    }

    if (udiff) {
        bgpdump_udiff_compare(af, sequence_number);

#if 0
      struct bgp_route *route;

      if (udiff_verbose)
        {
          printf ("seq: %lu\n", (unsigned long) sequence_number);
          if (! IS_ROUTE_NULL (&diff_table[0][sequence_number]))
            {
              route = &diff_table[0][sequence_number];
              printf ("{");
              route_print (route);
            }
          if (! IS_ROUTE_NULL (&diff_table[1][sequence_number]))
            {
              route = &diff_table[1][sequence_number];
              printf ("}");
              route_print (route);
            }
        }

      /* only in left */
      if (! IS_ROUTE_NULL (&diff_table[0][sequence_number]) &&
          IS_ROUTE_NULL (&diff_table[1][sequence_number]))
        {
          route = &diff_table[0][sequence_number];
          if (! udiff_lookup)
            {
              printf ("-");
              route_print (route);
            }
          else
            {
              struct ptree_node *x;
              int plen = (af == AF_INET ? 32 : 128);
              x = ptree_search ((char *)&route->prefix, plen, diff_ptree[1]);
              if (x)
                {
                  /* only in left but also entirely reachable in right */
                  struct bgp_route *other = x->data;
                  if (other->flag == '>')
                    {
                      route->flag = '(';
                      printf ("(");
                    }
                  else
                    {
                      route->flag = '-';
                      printf ("-");
                    }
                  route_print (route);
                }
              else
                {
                  /* only in left and unreachable in right (maybe partially) */
                  route->flag = '<';
                  printf ("<");
                  route_print (route);
                }
            }
        }

      /* only in right */
      if (IS_ROUTE_NULL (&diff_table[0][sequence_number]) &&
          ! IS_ROUTE_NULL (&diff_table[1][sequence_number]))
        {
          route = &diff_table[1][sequence_number];
          if (! udiff_lookup)
            {
              printf ("+");
              route_print (route);
            }
          else
            {
              struct ptree_node *x;
              int plen = (af == AF_INET ? 32 : 128);
              x = ptree_search ((char *)&route->prefix, plen, diff_ptree[0]);
              if (x)
                {
                  /* only in right but also entirely reachable in left */
                  struct bgp_route *other = x->data;
                  if (other->flag == '<')
                    {
                      route->flag = ')';
                      printf (")");
                    }
                  else
                    {
                      route->flag = '+';
                      printf ("+");
                    }
                  route_print (route);
                }
              else
                {
                  /* only in right and unreachable in left (maybe partially) */
                  route->flag = '>';
                  printf (">");
                  route_print (route);
                }
            }
        }

      /* exist in both */
      if (! IS_ROUTE_NULL (&diff_table[0][sequence_number]) &&
          ! IS_ROUTE_NULL (&diff_table[1][sequence_number]) &&
          diff_table[0][sequence_number].prefix_length > 0)
        {
          int plen = diff_table[0][sequence_number].prefix_length - 1;

          if (udiff_lookup)
            {
              struct ptree_node *x;

              route = &diff_table[0][sequence_number];
              x = ptree_search ((char *)&route->prefix, plen, diff_ptree[1]);
              if (x)
                {
                  /* the shorter in right was '>' */
                  struct bgp_route *other = x->data;
                  if (other->flag == '>')
                    {
                      route->flag = '(';
                      printf ("(");
                      route_print (route);
                    }
                }

              route = &diff_table[1][sequence_number];
              x = ptree_search ((char *)&route->prefix, plen, diff_ptree[0]);
              if (x)
                {
                  /* the shorter in left was '<' */
                  struct bgp_route *other = x->data;
                  if (other->flag == '<')
                    {
                      route->flag = ')';
                      printf (")");
                      route_print (route);
                    }
                }

            }
        }
#endif /*0*/
    }
}

void
bgpdump_process_table_v2_rib_generic(
    struct mrt_header *h, struct mrt_info *info, uint8_t *data_end
) {
    (void)info;

    uint8_t *p = (uint8_t *)h + sizeof(struct mrt_header);

    uint32_t sequence_number = read_u32(&p, data_end);
    uint16_t afi = read_u16(&p, data_end);
    uint8_t safi = read_u8(&p, data_end);

    int af = bgpdump_resolve_afi(afi);
    if (af == -1) {
        LOG(ERROR, "Unknown GENERIC Entry, afi=%d, safi=%d skip\n", afi, safi);
        return;
    }

    uint8_t prefix_length = read_u8(&p, data_end);
    uint32_t label = 0;
    if (safi == BGP_SAFI_MPLS) {
        // https://datatracker.ietf.org/doc/html/rfc3107
        prefix_length -= 24;
        label = read_u24(&p, data_end);
        label = label >> 4;
    }

    uint32_t prefix_size = ((prefix_length + 7) / 8);
    uint8_t prefix[16];
    read_n(prefix, sizeof(prefix), &p, prefix_size, data_end);

    uint16_t entry_count = read_u16(&p, data_end);

    if (log_enabled(INFO)) {
        char pbuf[64];
        inet_ntop(af, prefix, pbuf, sizeof(pbuf));
        LOG(INFO,
            "Sequence Number: %u Prefix %s/%d Entry Count: %d\n",
            sequence_number,
            pbuf,
            prefix_length,
            entry_count);
    }

    for (int i = 0; i < entry_count && p < data_end; i++) {
        bgpdump_process_table_v2_rib_entry(
            i, af, sequence_number, label, prefix, prefix_length, &p, data_end
        );
    }
}

void
bgpdump_process_table_dump_v2(
    struct mrt_header *h, struct mrt_info *info, uint8_t *data_end
) {
    switch (info->subtype) {
    case BGPDUMP_TABLE_V2_PEER_INDEX_TABLE:
        bgpdump_process_table_v2_peer_index_table(h, info, data_end);
        break;
    case BGPDUMP_TABLE_V2_RIB_IPV4_UNICAST:
        if (!peer_table_only) {
            bgpdump_process_table_v2_rib_unicast(AF_INET, h, info, data_end);
        }
        break;
    case BGPDUMP_TABLE_V2_RIB_IPV6_UNICAST:
        if (!peer_table_only) {
            bgpdump_process_table_v2_rib_unicast(AF_INET6, h, info, data_end);
        }
        break;
    case BGPDUMP_TABLE_V2_RIB_GENERIC:
        if (!peer_table_only) {
            bgpdump_process_table_v2_rib_generic(h, info, data_end);
        }
        break;
    default:
        LOG(WARN, "unsupported subtype: %d\n", info->subtype);
        break;
    }
}

/*
 * Local Variables:
 * c-basic-offset: 2
 * End:
 */
