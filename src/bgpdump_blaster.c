/*
 * bgpdump2 BGP blaster module.
 *
 * Hannes Gredler, May 2020
 *
 * Copyright (C) 2015-2020, RtBrick, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <time.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "netdb.h"

#include "ptree.h"
#include "bgpdump_option.h"
#include "bgpdump_route.h"
#include "bgpdump_data.h"
#include "bgpdump_peer.h"
#include "bgpdump_blaster.h"

void
bgpdump_blaster (void)
{
    int index, peer_index;
    struct ptree *t;
    struct ptree_node *n;
    struct bgp_path_ *bgp_path;
    struct bgp_prefix_ *bgp_prefix;
    struct bgp_route route;
    int prefixes;

    for (index = 0; index < peer_spec_size; index++) {
	peer_index = peer_spec_index[index];
	t = peer_table[peer_index].path_root;
	if (!t) {
	    continue;
	}

	if (!peer_table[peer_index].path_count) {
	    continue;
	}

	printf("\nRIB for peer-index %d\n", peer_index);
	printf("%u ipv4 prefixes, %u ipv6 prefixes, %u paths",
	       peer_table[peer_index].ipv4_count,
	       peer_table[peer_index].ipv6_count,
	       peer_table[peer_index].path_count);

	for (n = ptree_head(t); n; n = ptree_next(n)) {
	    bgp_path = n->data;
	    if (!bgp_path) {
		continue;
	    }

	    printf("\n path %p, length %u, refcount %u\n",
		   bgp_path,
		   bgp_path->path_length,
		   bgp_path->refcount);

	    memset (&route, 0, sizeof(route));
	    bgpdump_process_bgp_attributes(&route, n->key, n->key + bgp_path->path_length);

	    prefixes = 0;
	    CIRCLEQ_FOREACH(bgp_prefix, &bgp_path->path_qhead, prefix_qnode) {
		char pbuf[64];
		inet_ntop (bgp_prefix->afi, bgp_prefix->prefix, pbuf, sizeof(pbuf));
		if (prefixes == 0) {
		    printf ("%s%s/%d", (prefixes % 8) ? ", " : "  ",
			    pbuf, bgp_prefix->prefix_length);
		} else {
		    printf ("%s%s/%d", (prefixes % 8) ? ", " : "\n  ",
			    pbuf, bgp_prefix->prefix_length);
		}
		prefixes++;
	    }
	}
    }
}
