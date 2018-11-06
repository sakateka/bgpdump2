/*
 * bgpdump2 JSON export module.
 *
 * Hannes Gredler, November 2018
 *
 * Copyright (C) 2015-2018, RtBrick, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "bgpdump_route.h"
#include "bgpdump_json.h"

/* json ctx */
struct json_ctx_ *json_ctx[JSON_MAX_FILES] = { NULL };

/*
 * Flush the write buffer.
 */
ssize_t
json_fflush (struct json_ctx_ *ctx)
{
    int res = 0;

#if 0
    struct timespec {
	time_t tv_sec;        /* seconds */
	long   tv_nsec;       /* nanoseconds */
    };
#endif

    if (!ctx || !ctx->write_idx) {
        return 0;
    }

    res = write(ctx->output_fd, ctx->write_buf, ctx->write_idx);

    /*
     * Blocked ?
     */
    if (res == -1) {

	switch (errno) {
	case EAGAIN:

	    /* nanosleep() */
	    return -1;
	    break;

	case EPIPE:

	    /*
	     * reset the buffer for unresponsive callers.
	     */
	    ctx->write_idx = 0;
	    return -1;
	    break;

	default:
	    ctx->write_idx = 0;
	    /*
	     * Unhandled failure in flushing
	     */
	    break;
	}
	return -1;
    }

    /*
     * Full write ?
     */
    if (res == (int)ctx->write_idx) {
	ctx->write_idx = 0;
	return res;
    }

    /*
     * Partial write ?
     */
    if (res && res < (int)ctx->write_idx) {

	/*
	 * Rebase the buffer.
	 */
	memcpy(ctx->write_buf, ctx->write_buf+res, ctx->write_idx - res);
	ctx->write_idx -= res;
	return res;
    }

    /*
     * Must not happen.
     */
    return res;
}


void
route_print_json (struct bgp_route *route, uint16_t peer_index)
{
  int i;
  char prefix[64];
  char nexthop[64];
  int plen;

  char *origin;
  struct json_ctx_ *ctx;

  /*
   * Locate the context.
   */
  if (peer_index >= JSON_MAX_FILES) {
      return;
  }
  ctx = json_ctx[peer_index];

  /*
   * First context init ?
   */
  if (!ctx) {
      char filename[128];

      ctx = calloc(1, sizeof(struct json_ctx_));
      if (!ctx) {
	  return;
      }

      ctx->write_buf = malloc(JSON_WRITEBUFSIZE);
      if (!ctx->write_buf) {
	  free(ctx);
	  return;
      }

      /*
       * Open file for writing.
       */
      snprintf(filename, sizeof(filename), "peer-%u.json", peer_index);
      ctx->output_fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC,
			    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); /* chmod 644 */
      if (!ctx->output_fd) {
	  free(ctx->write_buf);
	  ctx->write_buf = NULL;
	  free(ctx);
	  return;
      }

      /*
       * Everything has been set up properly. Store the context.
       */
      json_ctx[peer_index] = ctx;

      /*
       * Write the file header.
       */
      JSONWRITE("{\n  \"table\": ");
      JSONWRITE("{ \"table_name\": \"default.bgp.peer-group.mrt-peer-%u.ipvX.unicast\" }", peer_index);
      JSONWRITE(",\n  \"objects\": [\n");
  }

  /*
   * open rib-entry object.
   */
  JSONWRITE("%s{\n      \"attribute\": {\n", ctx->comma_obj ? ",\n    " : "    ");
  ctx->comma_obj = 1;

  /*
   * Prefix
   */
  inet_ntop(qaf, route->prefix, prefix, sizeof(prefix));
  plen = route->prefix_length;
  JSONWRITE("\t\"prefix4\": \"%s/%d\"", prefix, plen);

  /*
   * nexthop
   */
  inet_ntop(qaf, route->nexthop, nexthop, sizeof (nexthop));
  JSONWRITE(",\n\t\"bgp_nh%s\": \"%s\"", qaf == AF_INET ? "4": "6", nexthop);

  /*
   * Peer IP & ASN
   */
#if 0
  {
      char peer_addr[64];

      inet_ntop (AF_INET, &peer_table[peer_index].ipv4_addr,
		 peer_addr, sizeof (peer_addr));
      peer_asn = peer_table[peer_index].asnumber;
  }
#endif

  /*
   * AS Path
   */
  JSONWRITE(",\n\t\"as_path\": [ ");
  for (i = 0; i < MIN (route->path_size, ROUTE_PATH_LIMIT); i++) {
      if (i == 0) {
	  JSONWRITE("\"%u\"", route->path_list[i]);
      } else {
	  JSONWRITE(", \"%u\"", route->path_list[i]);
      }
  }
  JSONWRITE(" ]");

  /*
   * Origin
   */
  switch (route->origin)
    {
    case '0':
      origin = "IGP";
      break;
    case '1':
      origin = "EGP";
      break;
    case '2':
    default:
      origin = "Incomplete";
      break;
    }
  JSONWRITE(",\n\t\"origin\": \"%s\"", origin);

  /*
   * Local Preference
   */
  if (route->localpref_set) {
      JSONWRITE(",\n\t\"local_preference\": %u", route->localpref);
  }

  /*
   * MED
   */
  if (route->med_set) {
      JSONWRITE(",\n\t\"med\": %u", route->med);
  }

  /*
   * Community
   */
  if (route->community_size) {
      uint asn;
      uint local;

      JSONWRITE(",\n\t\"community\": [ ");
      for (i = 0; i < MIN (route->community_size, ROUTE_COMM_LIMIT); i++) {
	  asn = route->community[i] >> 16;
	  local = route->community[i] & 0xffff;
	  if (i == 0) {
	      JSONWRITE("\"%u:%u\"", asn, local);
	  } else {
	      JSONWRITE(", \"%u:%u\"", asn, local);
	  }
      }
      JSONWRITE(" ]");
  }

  /*
   * Atomic aggregate.
   */
#if 0
  char *atomicaggr;
  char *atomicaggr_asn_addr;
  atomicaggr = (route->atomic_aggregate > 0 ? "AG" : "NAG");
  atomicaggr_asn_addr = "";
#endif

  /*
   * close rib-entry.
   */
  JSONWRITE("\n      }\n    }");
  ctx->prefixes++;
}

void
json_close_all (void)
{
    struct json_ctx_ *ctx;
    int idx;

    for (idx = 0; idx < JSON_MAX_FILES; idx++) {

	ctx = json_ctx[idx];

	if (!ctx) {
	    continue;
	}

	/*
	 * Write the file trailer.
	 */
	JSONWRITE("\n  ]");
	JSONWRITE(",\n  \"statistics\": { \"prefixes\": %u }", ctx->prefixes);
	JSONWRITE("\n}\n");

	/*
	 * Flush the buffer.
	 */
	json_fflush(ctx);


	/*
	 * close file.
	 */
	close(ctx->output_fd);

	/*
	 * Free the write-buffer.
	 */
	free(ctx->write_buf);
	ctx->write_buf = NULL;

	/*
	 * Destroy context.
	 */
	free(ctx);
	json_ctx[idx] = NULL;
    }
}
