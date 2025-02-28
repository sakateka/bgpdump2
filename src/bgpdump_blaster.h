/*
 * bgpdump2 BGP blaster module.
 *
 * Hannes Gredler, May 2020
 *
 * Copyright (C) 2015-2020, RtBrick, Inc.
 */

#ifndef __BGPDUMP_BLASTER_H__
#define __BGPDUMP_BLASTER_H__

#include <netinet/in.h>
#include <stdio.h>

void
bgpdump_blaster(void);

#define BGP_TCP_PORT 179
#define BGP_READBUFSIZE 1024 * 256
#define BGP_WRITEBUFSIZE 1024 * 256
#define BGP_MAX_MESSAGE_SIZE 4096

#define BGP_MSG_OPEN 1
#define BGP_MSG_UPDATE 2
#define BGP_MSG_NOTIFICATION 3
#define BGP_MSG_KEEPALIVE 4

#define MSEC 1000 * 1000 /* 1 million nanoseconds */

typedef enum {
    IDLE,
    CONNECT,
    ACTIVE,
    OPENSENT,
    OPENCONFIRM,
    ESTABLISHED
} state_t;

struct bgp_session_ {
    FILE *file;
    int sockfd;
    state_t state;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    struct timer_ *connect_timer;
    struct timer_ *send_open_timer;
    struct timer_ *open_sent_timer;
    struct timer_ *keepalive_timer;
    struct timer_ *hold_timer;
    struct timer_ *close_timer;

    uint peer_holdtime;
    uint peer_as;

    /* write buffer */
    struct timer_ *write_job;
    u_char *write_buf;
    uint write_idx;

    /* read buffer */
    struct timer_ *read_job;
    u_char *read_buf;
    u_char *read_buf_start;
    u_char *read_buf_end;

    /*
     * Cursor for the async ribwalk.
     */
    struct ptree_node *ribwalk_pnode;
    int ribwalk_peer_index;
    uint ribwalk_prefix_index;
    struct bgp_prefix_ *ribwalk_prefix;
    uint ribwalk_complete : 1, ribwalk_withdraw : 1;
    struct timespec ribwalk_start; /* Timestamp when RIB walk was started */
    struct timespec ribwalk_eor;   /* Timestamp when end of RIB was sent */

    /*
     * Statistics.
     */
    struct {
        uint updates_sent;
        uint prefixes_sent;
        uint prefixes_withdrawn;
        uint octets_sent;
    } stats;
};

#endif /* __BGPDUMP_BLASTER_H__ */
