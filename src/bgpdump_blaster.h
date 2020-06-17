/*
 * bgpdump2 BGP blaster module.
 *
 * Hannes Gredler, May 2020
 *
 * Copyright (C) 2015-2020, RtBrick, Inc.
 */

#ifndef __BGPDUMP_BLASTER_H__
#define __BGPDUMP_BLASTER_H__

void bgpdump_blaster(void);

#define BGP_TCP_PORT 179
#define BGP_READBUFSIZE  65536
#define BGP_WRITEBUFSIZE 1024*4096
#define BGP_MAX_MESSAGE_SIZE 4096

#define BGP_MSG_OPEN         1
#define BGP_MSG_UPDATE       2
#define BGP_MSG_NOTIFICATION 3
#define BGP_MSG_KEEPALIVE    4

#define MSEC 1000*1000 /* 1 million nanoseconds */

typedef enum
{
    IDLE,
    CONNECT,
    ACTIVE,
    OPENSENT,
    OPENCONFIRM,
    ESTABLISHED
} state_t;

struct __attribute__((__packed__)) timer_
{
    CIRCLEQ_ENTRY(timer_) timer_qnode;
    char name[16];
    void *data; /* Misc. data */
    void (*cb)(struct timer_ *); /* Callback function. */
    struct timespec expire; /* Expiration interval */
};

struct __attribute__((__packed__)) bgp_session_
{
    int sockfd;
    state_t state;
    struct sockaddr_in sockaddr_in; /* XXX v6 */

    struct timer_ *connect_timer;
    struct timer_ *open_sent_timer;
    struct timer_ *keepalive_timer;
    struct timer_ *hold_timer;
    struct timer_ *close_timer;

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
    int ribwalk_prefix_index;
    uint ribwalk_complete:1;
};

#endif /* __BGPDUMP_BLASTER_H__ */
