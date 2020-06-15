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
#define BGP_WRITEBUFSIZE 65536

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
    //    struct ptree_node *pnode;
    struct sockaddr_in sockaddr_in; /* XXX v6 */
    struct timer_ *open_sent_timer;

    struct timespec last_connect_attempt;
    struct timespec last_keepalive_sent;
    struct timespec last_keepalive_received;

    /* write buffer */
    u_char *write_buf;
    uint write_idx;
};

#endif /* __BGPDUMP_BLASTER_H__ */
