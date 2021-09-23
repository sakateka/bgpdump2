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
#define BGP_WRITEBUFSIZE 1024*256
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
    struct timer_ **ptimer;
    void (*cb)(struct timer_ *); /* Callback function. */
    struct timespec expire; /* Expiration interval */
    uint delete:1,
	expired:1;
};

struct __attribute__((__packed__)) bgp_session_
{
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
    int ribwalk_prefix_index;
    uint ribwalk_complete:1, ribwalk_withdraw:1;
    struct timespec eor_ts; /* Timestamp when end of RIB was sent */

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

/*
 * List of log-ids.
 */
enum {
    LOG_ID_MIN,
    TIMER,
    TIMER_DETAIL,
    UPDATE,
    UPDATE_DETAIL,
    KEEPALIVE,
    FSM,
    IO,
    NORMAL,
    ERROR,
    LOG_ID_MAX
};

struct keyval_ {
    u_int val;       /* value */
    const char *key; /* key */
};

struct __attribute__((__packed__)) log_id_
{
    uint8_t enable;
    void (*filter_cb)(struct log_id_ *, void *); /* Callback function for filtering */
    void *filter_arg;
};

#define LOG(log_id_, fmt_, ...)					\
    do { if (log_id[log_id_].enable) {fprintf(stdout, "%s "fmt_, fmt_timestamp(), ##__VA_ARGS__);} } while (0)

extern struct log_id_ log_id[];
extern void log_enable(char *);

#endif /* __BGPDUMP_BLASTER_H__ */
