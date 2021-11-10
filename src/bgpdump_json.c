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
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <time.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "netdb.h"

#include "bgpdump_option.h"
#include "bgpdump_route.h"
#include "bgpdump_data.h"
#include "bgpdump_peer.h"
#include "bgpdump_json.h"

/* json ctx */
struct json_ctx_ *json_ctx[JSON_MAX_FILES] = { NULL };
int sockfd = -1;


/*
 * Flush the write buffer.
 */
ssize_t
json_fflush (struct json_ctx_ *ctx)
{
    char buffer[BUFSIZ];
    int res = 0;
    struct iovec io[2];
    struct timespec sleeptime, rem;

    if (!ctx || !ctx->write_idx) {
        return 0;
    }

    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = 10 * 1000 * 1000; /* 10ms */

    /*
     * Write the HTTP header.
     */
    io[0].iov_base = &ctx->header_buf;
    io[0].iov_len = snprintf((char *)&ctx->header_buf, sizeof(ctx->header_buf),
	"POST /%s HTTP/1.1\r\n"
	"User-Agent: bgpdump2\r\n"
	"Host: ctrld\r\n"
	"Content-Type: application/json\r\n"
	"Content-Length: %d"
	"\r\n\r\n", json_page, ctx->write_idx);

    /*
     * Add payload to the IO Vector.
     */
    io[1].iov_base = ctx->write_buf;
    io[1].iov_len = ctx->write_idx;

    /*
     * Log to file.
     */
    res = writev(ctx->output_fd, io, 2);

    /*
     * Write to socket.
     */
    if (sockfd != -1) {
	res = writev(sockfd, io, 2);

	if (res == -1) {
	    printf("## errno %u\n", errno);
	    return -1;
	}

	printf("## wrote %u prefixes, %u bytes, %u prefixes total",
	       ctx->chunk_prefixes,
	       (unsigned int)io[0].iov_len + (unsigned int)io[1].iov_len,
	       ctx->prefixes);
    }

    ctx->chunk = 0;
    ctx->chunk_prefixes = 0;


    /*
     * Full write ?
     */
    if (res == io[0].iov_len + io[1].iov_len) {
	ctx->write_idx = 0;
    }

    /*
     * Read the response.
     */
    while (1) {
	int len = 0;
	char version[32];
	char reason[32];
	uint result = 0;

	ioctl(sockfd, FIONREAD, &len);
	if (len > 0) {
	    len = read(sockfd, buffer, len);

	    /*
	     * Log.
	     */
	    res = write(ctx->output_fd, buffer, len);

	    sscanf(buffer, "%s %u %s\n", version, &result, reason);
	    if (result) {
		printf(", got %s", buffer);
		break; /* exit read loop */
	    }
	}

	nanosleep(&sleeptime, &rem);
    } 

    /*
     * All done.
     */
    ctx->fflush = 0;
    
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
  }

  if (ctx->chunk == 0) {

      /*
       * Write the table header.
       */
      JSONWRITE("{\n  \"table\": ");
      JSONWRITE("{ \"table_name\": \"default.bgp.1.peer-group.iBGP_100_%u.ipv%s.unicast\" }",
		peer_index, qaf == AF_INET ? "4": "6");
      JSONWRITE(",\n  \"objects\": [\n");
      ctx->root_obj_open = 1;
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
  JSONWRITE("\t\"prefix%s\": \"%s/%d\"", qaf == AF_INET ? "4": "6", prefix, plen);

  /*
   * nexthop
   */
  inet_ntop(qaf, route->nexthop, nexthop, sizeof (nexthop));
  JSONWRITE(",\n\t\"bgp_nh%s\": \"%s\"", qaf == AF_INET ? "4": "6", nexthop);

  /*
   * Peer BGP-ID
   */
  {
      char peer_addr[64];

      inet_ntop(AF_INET, &peer_table[peer_index].bgp_id, peer_addr, sizeof(peer_addr));
      JSONWRITE(",\n\t\"originator_id\": \"%s\"", peer_addr);
  }

  /*
   * Peer ASN
   */
#if 0
  peer_asn = peer_table[peer_index].asnumber;
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
      JSONWRITE(",\n\t\"local_preference\": \"%u\"", route->localpref);
  } else if (localpref != -1) {
      JSONWRITE(",\n\t\"local_preference\": \"%d\"", localpref);
  }

  /*
   * Peer Group Type.
   */
  if (localpref != -1) {
      JSONWRITE(",\n\t\"pg_type\": \"ibgp\"");
  } else {
      JSONWRITE(",\n\t\"pg_type\": \"ebgp\"");
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
   * Extended Community
   */
  if (route->extd_community_size) {
      JSONWRITE(",\n\t\"extended_community\": [ ");
      for (i = 0; i < MIN (route->extd_community_size, ROUTE_EXTD_COMM_LIMIT); i++) {
	  if (i == 0) {
	      JSONWRITE("\"%s\"", bgpdump_print_extd_comm(&route->extd_community[i]));
	  } else {
	      JSONWRITE(", \"%s\"", bgpdump_print_extd_comm(&route->extd_community[i]));
	  }
      }
      JSONWRITE(" ]");
  }

  /*
   * Large Community
   */
  if (route->large_community_size) {
      JSONWRITE(",\n\t\"large_community\": [ ");
      for (i = 0; i < MIN (route->large_community_size, ROUTE_LARGE_COMM_LIMIT); i++) {
	  if (i == 0) {
	      JSONWRITE("\"%u:%u:%u\"", route->large_community[i].global,
			route->large_community[i].local1,
			route->large_community[i].local2);
	  } else {
	      JSONWRITE(", \"%u:%u:%u\"", route->large_community[i].global,
			route->large_community[i].local1,
			route->large_community[i].local2);
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
  ctx->chunk_prefixes++;
  ctx->chunk++;

  if (ctx->fflush) {
      json_fflush(ctx);
  }

  /*
   * Close the object if this is the end of a chunk
   */
  if (ctx->chunk >= JSON_CHUNK) {
      JSONWRITE("\n  ]");
      JSONWRITE("\n}\n");
      ctx->comma_obj = 0;
      ctx->root_obj_open = 0;
      ctx->chunk = 0;
      json_fflush(ctx);
  }
}

void
json_open_socket (void) {

    char       protoname[] = "tcp";
    in_addr_t  in_addr;

    struct protoent *protoent;
    struct hostent *hostent;
    struct sockaddr_in sockaddr_in;

    /* Get socket. */
    protoent = getprotobyname(protoname);
    if (!protoent) {
        return;
    }
    sockfd = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
    if (sockfd == -1) {
        return;
    }

    /* Prepare sockaddr_in. */
    hostent = gethostbyname(json_ip);
    if (!hostent) {
        return;
    }

    in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
    if (in_addr == (in_addr_t)-1) {
        return;
    }

    sockaddr_in.sin_addr.s_addr = in_addr;
    sockaddr_in.sin_family = AF_INET;
    sockaddr_in.sin_port = htons(json_port);

    /* Do the actual connection. */
    if (connect(sockfd, (struct sockaddr*)&sockaddr_in, sizeof(sockaddr_in)) == -1) {
        return;
    }

    {
	/* Now lets try to set the send buffer size to 4194304 bytes */
	int size = 4096*1024;
	int err;
	err = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,  &size, sizeof(int));
	if (err != 0) {
	    printf("Unable to set send buffer size, continuing with default size\n");
	}
    }
}

void
json_close_all (void)
{
    struct timespec sleeptime, rem;
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
	if (ctx->root_obj_open) {
	    JSONWRITE("\n  ]");
	    JSONWRITE("\n}\n");
	    ctx->root_obj_open = 0;
	}

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

    sleeptime.tv_sec = 5;
    sleeptime.tv_nsec = 0;
    nanosleep(&sleeptime, &rem);

    /*
     * Close the socket.
     */
    if (sockfd != -1) {
	close(sockfd);
    }
}
