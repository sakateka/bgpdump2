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
    int index;
    struct ptree *t;
    struct ptree_node *n;
    struct bgp_path_ *bgp_path;

    for (index = 0; index < PEER_INDEX_MAX; index++) {
	t = peer_table[index].path_root;
	if (!t) {
	    continue;
	}

	for (n = ptree_head(t); n; n = ptree_next (n)) {
	    bgp_path = n->data;
	    if (!bgp_path) {
		continue;
	    }
	    printf("path %p, refcount %u\n", bgp_path, bgp_path->refcount);
	}
    }
}
