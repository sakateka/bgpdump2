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
#define LOG_IMPLEMENTATION

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "benchmark.h"
#include "ptree.h"

#include "bgpdump.h"
#include "bgpdump_data.h"
#include "bgpdump_file.h"
#include "bgpdump_log.h"
#include "bgpdump_option.h"
#include "bgpdump_parse.h"
#include "bgpdump_route.h"

#include "bgpdump_blaster.h"
#include "bgpdump_peer.h"
#include "bgpdump_peerstat.h"
#include "bgpdump_ptree.h"
#include "bgpdump_query.h"
#include "bgpdump_savefile.h"

extern int optind;

char *progname = NULL;

struct mrt_info info;
struct ptree *ptree[2];

int qaf = AF_INET6;
unsigned long autnums[AUTLIM];
int autsiz = 0;

struct bgp_route *diff_table[2];
struct ptree *diff_ptree[2];

void
bgpdump_process(uint8_t *buf, size_t *data_len) {
    struct mrt_header *h;
    int hsize = sizeof(struct mrt_header);
    uint8_t *data_end = buf + *data_len;
    unsigned long len;
    int rest;

    LOG(DEBUG, "process %lu bytes.\n", *data_len);

    uint8_t *p = buf;
    h = (struct mrt_header *)p;
    len = ntohl(h->length);

    LOG(DEBUG, "mrt message: length: %lu bytes.\n", len);

    /* Process as long as entire MRT message is in the buffer */
    while (len && p + hsize + len <= data_end) {
        uint16_t mrt_type = bgpdump_process_mrt_header(h, &info);

        switch (mrt_type) {
        case BGPDUMP_TYPE_TABLE_DUMP_V2:
            bgpdump_process_table_dump_v2(h, &info, p + hsize + len);
            break;
        default:
            LOG(WARN, "Not supported: mrt type: %d\n", mrt_type);
            LOG(WARN, "discarding %lu bytes data.\n", hsize + len);
            break;
        }

        p += hsize + len;

        len = 0;
        if (p + hsize < data_end) {
            h = (struct mrt_header *)p;
            len = ntohl(h->length);
            LOG(TRACE, "next mrt message: length: %lu bytes.\n", len);
            LOG(TRACE,
                "p: %p hsize: %d len: %lu mrt-end: %p data_end: %p\n",
                p,
                hsize,
                len,
                p + hsize + len,
                data_end);
        }
    }

    /* move the partial, last-part data
       to the beginning of the buffer. */
    rest = data_end - p;
    if (rest)
        memmove(buf, p, rest);
    *data_len = rest;
}

void
rot(uint64_t n, uint32_t *x, uint32_t *y, uint32_t rx, uint32_t ry) {
    int t;
    if (ry == 0) {
        if (rx == 1) {
            *x = n - 1 - *x;
            *y = n - 1 - *y;
        }

        t = *x;
        *x = *y;
        *y = t;
    }
}

void
d2xy(uint64_t n, uint64_t d, uint32_t *x, uint32_t *y) {
    uint64_t s, t = d;
    uint32_t rx, ry;
    *x = *y = 0;
    for (s = 1; s < n; s *= 2) {
        rx = 1 & (t / 2);
        ry = 1 & (t ^ rx);

        rot(s, x, y, rx, ry);

        *x += s * rx;
        *y += s * ry;
        t /= 4;
    }
}

void
heatmap_image_hilbert_gplot(int peer_spec_i) {
    int peer_index = peer_spec_index[peer_spec_i];

    unsigned int a0;
    unsigned long val = 0;

    uint32_t x1, y1, x2, y2;
    uint32_t xs, ys, xe, ye;

    unsigned int index;

    int textxmargin = 1;
    int textymargin = 5;

    char filename[256];
    snprintf(
        filename, sizeof(filename), "%s-p%d.gp", heatmap_prefix, peer_index
    );
    FILE *fp = fopen(filename, "w+");
    if (!fp) {
        LOG(ERROR, "can't open file %s: %s\n", filename, strerror(errno));
        return;
    }

    fprintf(fp, "set xlabel \"\"\n");
    fprintf(fp, "set ylabel \"\"\n");
    fprintf(fp, "\n");
    fprintf(fp, "unset tics\n");
    fprintf(fp, "\n");
    fprintf(fp, "set cbrange [0:256]\n");
    fprintf(fp, "set cbtics 32\n");
    fprintf(fp, "\n");
    fprintf(fp, "set xrange [-1:256]\n");
    fprintf(fp, "set yrange [256:-1]\n");
    fprintf(fp, "\n");
    fprintf(fp, "set pm3d map\n");
    fprintf(
        fp,
        "set palette defined (0 \"black\", 1 \"red\", "
        "128 \"yellow\", 192 \"green\", 255 \"blue\")\n"
    );
    fprintf(fp, "\n");
    fprintf(fp, "set style rect back fs empty border lc rgb \"white\"\n");
    fprintf(fp, "\n");

    for (a0 = 0; a0 < 256; a0++) {
        val = (a0 << 8);
        d2xy(1ULL << 16, val, &x1, &y1);
        val = (a0 << 8) + 255;
        d2xy(1ULL << 16, val, &x2, &y2);

        index = a0 + 1;
        // printf ("%u: start (%u,%u) end (%u,%u).\n",
        //         a0, x1, y1, x2, y2);

        xs = (MIN(x1, x2)) / 16 * 16;
        ys = (MIN(y1, y2)) / 16 * 16;
        xe = xs + 16;
        ye = ys + 16;

        fprintf(
            fp,
            "set label  %u \"%u\" at first %u,%u left "
            "font \",8\" front textcolor rgb \"white\"\n",
            index,
            a0,
            xs + textxmargin,
            ys + textymargin
        );
        fprintf(
            fp,
            "set object %u rect from %u,%u to %u,%u front\n",
            index,
            xs,
            ys,
            xe,
            ye
        );
    }

    int asnum;
    char bgpid[32], bgpaddr[32];
    asnum = peer_table[peer_index].asnumber;
    inet_ntop(AF_INET, &peer_table[peer_index].bgp_id, bgpid, sizeof(bgpid));
    inet_ntop(
        AF_INET, &peer_table[peer_index].ipv4_addr, bgpaddr, sizeof(bgpaddr)
    );

    char *p, titlename[64];
    p = rindex(heatmap_prefix, '/');
    if (p)
        snprintf(titlename, sizeof(titlename), "%s", ++p);
    else
        snprintf(titlename, sizeof(titlename), "%s", heatmap_prefix);

    fprintf(fp, "\n");
    fprintf(
        fp,
        "set title \"%s p%d bgpid:%s addr:%s AS%d\"\n",
        titlename,
        peer_index,
        bgpid,
        bgpaddr,
        asnum
    );
    fprintf(fp, "set term postscript eps enhanced color\n");
    fprintf(fp, "set output '%s-p%d.eps'\n", heatmap_prefix, peer_index);
    fprintf(
        fp,
        "splot '%s-p%d.dat' u 1:2:3 with image notitle\n",
        heatmap_prefix,
        peer_index
    );
    fprintf(fp, "\n");
    fprintf(fp, "set term png\n");
    fprintf(fp, "set output '%s-p%d.png'\n", heatmap_prefix, peer_index);
    fprintf(fp, "replot\n");
    fprintf(fp, "\n");

    fclose(fp);

    LOG(INFO, "%s is written.\n", filename);
}

void
heatmap_image_hilbert_data(int peer_spec_i) {
    int peer_index = peer_spec_index[peer_spec_i];
    struct ptree *ptree = peer_ptree[peer_spec_i];

    uint32_t a0, a1, a2;
    struct in_addr addr = {0};
    uint64_t val = 0;
    uint8_t *p = (uint8_t *)&addr;
    struct ptree_node *node;
    uint64_t count = 0;

    uint32_t array[256][256];

    uint32_t x, y;
    x = y = 0;

    for (a0 = 0; a0 < 256; a0++) {
        p[0] = (unsigned char)a0;
        for (a1 = 0; a1 < 256; a1++) {
            p[1] = (unsigned char)a1;

            count = 0;
            for (a2 = 0; a2 < 256; a2++) {
                p[2] = (unsigned char)a2;
                // printf ("heat: addr: %s\n", inet_ntoa (addr));

                node = ptree_search((uint8_t *)&addr, 24, ptree);
                if (node) {
                    // struct bgp_route *route = node->data;
                    // route_print (route);
                    count++;
                } else {
                    // printf ("no route.\n");
                }
            }

            p[2] = 0;
            val = (a0 << 8) + a1;
            d2xy(1ULL << 16, val, &x, &y);
#if 0
          printf ("val: %lu, x: %lu, y: %lu, count: %lu\n",
                  val, (unsigned long) x, (unsigned long) y,
                  (unsigned long) count);
#endif

            array[x][y] = count;
        }
    }

    // printf ("\n");

    char filename[256];
    snprintf(
        filename, sizeof(filename), "%s-p%d.dat", heatmap_prefix, peer_index
    );

    FILE *fp = fopen(filename, "w+");
    if (!fp) {
        LOG(ERROR, "can't open file %s: %s\n", filename, strerror(errno));
        return;
    }

    for (a0 = 0; a0 < 256; a0++)
        for (a1 = 0; a1 < 256; a1++)
            fprintf(fp, "%u %u %u\n", a0, a1, array[a0][a1]);

    fclose(fp);
    LOG(INFO, "%s is written.\n", filename);
}

void
heatmap_image_hilbert_data_aspath_max_distance(int peer_spec_i) {
    int peer_index = peer_spec_index[peer_spec_i];
    struct ptree *ptree = peer_ptree[peer_spec_i];

    unsigned int a0, a1, a2;
    struct in_addr addr = {0};
    unsigned long val = 0;
    unsigned char *p = (unsigned char *)&addr;
    struct ptree_node *node;
    // unsigned long count = 0;
    unsigned long max = 0;

    unsigned int array[256][256];

    uint32_t x, y;
    x = y = 0;

    for (a0 = 0; a0 < 256; a0++) {
        p[0] = (unsigned char)a0;
        for (a1 = 0; a1 < 256; a1++) {
            p[1] = (unsigned char)a1;

            // count = 0;
            max = 0;

            for (a2 = 0; a2 < 256; a2++) {
                p[2] = (unsigned char)a2;
                // printf ("heat: addr: %s\n", inet_ntoa (addr));

                node = ptree_search((uint8_t *)&addr, 24, ptree);
                if (node) {
                    struct bgp_route *route = node->data;
                    // route_print (route);
                    // count++;
                    if (max < route->path_size)
                        max = route->path_size;
                } else {
                    // printf ("no route.\n");
                }
            }

            p[2] = 0;
            val = (a0 << 8) + a1;
            d2xy(1ULL << 16, val, &x, &y);
#if 0
          printf ("val: %lu, x: %lu, y: %lu, count: %lu\n",
                  val, (unsigned long) x, (unsigned long) y,
                  (unsigned long) count);
#endif
#if 1
            printf(
                "val: %lu, x: %lu, y: %lu, max: %lu\n",
                val,
                (unsigned long)x,
                (unsigned long)y,
                (unsigned long)max
            );
#endif

            // array[x][y] = count;
            int adjust = 16;
            if (max * adjust > 255)
                array[x][y] = 255;
            else
                array[x][y] = max * adjust;
        }
    }

    // printf ("\n");

    char filename[256];
    snprintf(
        filename, sizeof(filename), "%s-p%d.dat", heatmap_prefix, peer_index
    );

    FILE *fp = fopen(filename, "w+");
    if (!fp) {
        LOG(ERROR, "can't open file %s: %s\n", filename, strerror(errno));
        return;
    }

    for (a0 = 0; a0 < 256; a0++)
        for (a1 = 0; a1 < 256; a1++)
            fprintf(fp, "%u %u %u\n", a0, a1, array[a0][a1]);

    fclose(fp);
    LOG(INFO, "%s is written.\n", filename);
}

int
main(int argc, char **argv) {
    progname = strdup(argv[0]);

    bufsiz = resolv_number(BGPDUMP_BUFSIZ_DEFAULT, NULL);
    nroutes = resolv_number(ROUTE_LIMIT_DEFAULT, NULL);

    int status = bgpdump_getopt(argc, argv);
    if (status)
        return status;

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        LOG(INFO, "Read MRT data from stdin\n");
        argc += 1;
        argv -= 1;
        argv[0] = "-";
    }

    if (log_enabled(INFO)) {
        LOG(INFO, "bufsiz = %llu\n", bufsiz);
        LOG(INFO, "nroutes = %llu\n", nroutes);
        char buf[1024];
        fmt_peer_spec_index(buf, sizeof(buf));
        LOG(INFO, "peer_indices = [%s]\n", buf);

        LOG(INFO, "asn nums = ");
        for (int i = 0; i < autsiz; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%ld", autnums[i]);
        }
        fprintf(stderr, "\n");
    }

    if (stats)
        peer_stat_init();

    uint8_t *buf = malloc(bufsiz);
    if (!buf) {
        LOG(ERROR, "can't malloc %lluB-size buf: %s\n", bufsiz, strerror(errno)
        );
        exit(-1);
    }

    peer_table_init();

    if (peer_spec_size && !blaster) {
        for (int i = 0; i < peer_spec_size; i++) {
            peer_route_table[i] = route_table_create();
            peer_route_size[i] = 0;
            peer_ptree[i] = ptree_create();
        }
    }

    if (lookup) {
        route_init();
        ptree[AF_INET >> 3] = ptree_create();
        ptree[AF_INET6 >> 3] = ptree_create();
    }

    if (udiff) {
        diff_table[0] = malloc(nroutes * sizeof(struct bgp_route));
        diff_table[1] = malloc(nroutes * sizeof(struct bgp_route));
        assert(diff_table[0] && diff_table[1]);
        memset(diff_table[0], 0, nroutes * sizeof(struct bgp_route));
        memset(diff_table[1], 0, nroutes * sizeof(struct bgp_route));

        if (udiff_lookup) {
            diff_ptree[0] = ptree_create();
            diff_ptree[1] = ptree_create();
        }
    }

    /* for each rib files. */
    for (int i = 0; i < argc; i++) {
        char *filename = argv[i];
        file_format_t format = get_file_format(filename);
        struct access_method *method = get_access_method(format);
        void *file = method->fopen(filename, "r");
        if (!file) {
            LOG(ERROR, "# could not open file: %s\n", filename);
            continue;
        }

        size_t datalen = 0;

        while (1) {
            size_t ret =
                method->fread(buf + datalen, 1, bufsiz - datalen, file);
            LOG(DEBUG,
                "read: %lu bytes to buf[%lu]. total %lu bytes\n",
                ret,
                datalen,
                ret + datalen);
            datalen += ret;

            /* end of file. */
            if (ret == 0 && method->feof(file)) {
                LOG(DEBUG, "read: end-of-file.\n");
                break;
            }

            bgpdump_process(buf, &datalen);

            LOG(DEBUG, "process rest: %lu bytes\n", datalen);
        }

        if (datalen) {
            LOG(WARN,
                "warning: %lu bytes unprocessed data remains: %s\n",
                datalen,
                filename);
        }
        method->fclose(file);

        /* For each end of the processing of files. */
        if (route_count) {
            peer_route_count_show();
            peer_route_count_clear();
        }

        if (plen_dist) {
            peer_route_count_by_plen_show();
            peer_route_count_by_plen_clear();
        }
    }

    /* query_table construction. */
    if (lookup) {
        query_limit = 0;

        if (lookup_file)
            query_limit = query_file_count(lookup_file);

        if (lookup_addr)
            query_limit++;

        query_init();

        if (lookup_addr)
            query_addr(lookup_addr);

        if (lookup_file)
            query_file(lookup_file);

        if (log_enabled(DEBUG))
            query_list();
    }

    /* query to route_table (ptree). */
    if (lookup) {
        if (benchmark)
            benchmark_start();

        if (lookup) {
            for (int i = 0; i < peer_spec_size; i++) {
                LOG(INFO, "peer %d:\n", peer_spec_index[i]);
                if (log_enabled(DEBUG))
                    ptree_list(peer_ptree[i]);
                ptree_query(peer_ptree[i], query_table, query_size);
            }
        }

        if (benchmark) {
            benchmark_stop();
            benchmark_print(query_size);
        }
    }

    if (heatmap) {
        for (int i = 0; i < peer_spec_size; i++) {
            heatmap_image_hilbert_gplot(i);
            heatmap_image_hilbert_data(i);
            // heatmap_image_hilbert_data_aspath_max_distance (i);
        }
    }

    if (lookup) {
        free(query_table);
        ptree_delete(ptree[AF_INET >> 3]);
        ptree_delete(ptree[AF_INET6 >> 3]);
        route_finish();
    }

    if (udiff) {
        free(diff_table[0]);
        free(diff_table[1]);

        if (lookup) {
            ptree_delete(diff_ptree[0]);
            ptree_delete(diff_ptree[1]);
        }
    }

    if (stats) {
        peer_stat_show();
        // peer_stat_finish ();
    }

    if (blaster || blaster_dump) {
        bgpdump_blaster();
    }

    free(buf);

    return status;
}
