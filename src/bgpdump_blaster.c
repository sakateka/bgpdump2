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

/* Globals */
CIRCLEQ_HEAD(timer_head_, timer_ ) timer_qhead; /* Timer root */

/* Prototypes */
void bgpdump_connect_session_cb(struct timer_ *);

/*
 * Flush the write buffer.
 */
void
bgpdump_fflush (struct bgp_session_ *session)
{
    int res;

    if (!session->write_idx) {
        return;
    }

    res = write(session->sockfd, session->write_buf, session->write_idx);

    /*
     * Blocked ?
     */
    if (res == -1) {

        switch (errno) {

        case EAGAIN:
	    break;

        default:
	    break;
        }
        return;
    }

    /*
     * Full write ?
     */
    if (res == (int)session->write_idx) {

	fprintf(stderr, "fully drained %u bytes buffer to %s\n",
		res, blaster_addr);

	session->write_idx = 0;
        return;
    }

    /*
     * Partial write ?
     */
    if (res && res < (int)session->write_idx) {

	fprintf(stderr, "partial drained %u bytes buffer to %s\n",
		res, blaster_addr);

        /*
         * Rebase the buffer.
         */
        memcpy(session->write_buf, session->write_buf+res, session->write_idx - res);
        session->write_idx -= res;
    }
}

/*
 * Quick'n dirty big endian writer.
 */
void
write_be_uint (u_char *data, uint length, unsigned long long value)
{
    uint idx;

    if (!length || length > 8) {
	return;
    }

    for (idx = 0; idx < length; idx++) {
	data[length - idx -1] =  value & 0xff;
	value >>= 8;
    }
}

/*
 * Push data to the write buffer and update the cursor.
 */
void
push_be_uint (struct bgp_session_ *session, uint length, unsigned long long value)
{
    /*
     * Buffer overrun protection.
     */
    if ((session->write_idx + length) >= BGP_WRITEBUFSIZE) {
	return;
    }

    /*
     * Write the data.
     */
    write_be_uint(session->write_buf + session->write_idx, length, value);

    /*
     * Adjust the cursor.
     */
    session->write_idx += length;
}


void
push_as4_capability (struct bgp_session_ *session)
{
    uint cap_idx, length;


    /* Capability */
    push_be_uint(session, 1, 2); /* Cap code */
    push_be_uint(session, 1, 0); /* Cap length. To be updated later */
    cap_idx = session->write_idx;

    /*
     * AS4 capability.
     */
    push_be_uint(session, 1, 65);
    push_be_uint(session, 1, 4); /* length to encode my AS4 */
    push_be_uint(session, 4, 65200); /* my AS */

    /*
     * Calculate Capability length field.
     */
    length = session->write_idx - cap_idx;
    write_be_uint(session->write_buf+cap_idx-1, 1, length); /* overwrite Cap length */
}


/*
 * Write a BGP open message.
 */
void
push_open_message (struct bgp_session_ *session)
{
    uint open_start_idx, length, opt_parms_idx, opt_parms_length;

    open_start_idx = session->write_idx;

    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */

    push_be_uint(session, 2, 0); /* length */
    push_be_uint(session, 1, 1); /* open message type */

    push_be_uint(session, 1, 4); /* version 4 */
    push_be_uint(session, 2, 23456); /* my AS */
    push_be_uint(session, 2, 90); /* holdtime */
    push_be_uint(session, 4, 0x01020304); /* BGP ID 1.2.3.4 */

    /* Optional parameters */
    push_be_uint(session, 1, 0); /* Optional Parameter length */
    opt_parms_idx = session->write_idx;

    /*
     * AS4 capability.
     */
    push_as4_capability(session);

    /*
     * Calculate Optional parameters length field.
     */
    opt_parms_length = session->write_idx - opt_parms_idx;
    write_be_uint(session->write_buf+opt_parms_idx-1, 1, opt_parms_length); /* overwrite parameters length */

    /*
     * Calculate Message length field.
     */
    length = session->write_idx - open_start_idx;
    write_be_uint(session->write_buf+open_start_idx+16, 2, length); /* overwrite message length */
}

/*
 * Enqueue a callback function onto the timer list.
 */
struct timer_ *
timer_add (char *name, time_t sec, long nsec, void *data, void (*cb))
{
    struct timer_ *timer;

    timer = calloc(1, sizeof(struct timer_));
    if (!timer) {
	return NULL;
    }

    /*
     * Store name, data and callback.
     */
    snprintf(timer->name, sizeof(timer->name), "%s", name);
    timer->data = data;
    timer->cb = cb;

    /*
     * Set expiration interval.
     */
    clock_gettime(CLOCK_MONOTONIC, &timer->expire);
    timer->expire.tv_sec += sec;
    timer->expire.tv_nsec += nsec;

    /*
     * Handle nsec overflow.
     */
    if (timer->expire.tv_nsec >= 10000000000) {
	timer->expire.tv_nsec -= 10000000000;
	timer->expire.tv_sec++;
    }

    CIRCLEQ_INSERT_TAIL(&timer_qhead, timer, timer_qnode);
    printf("Add %s timer, expire in %lu.%lu\n", timer->name, sec, nsec);

    return timer;
}

/*
 * Compare two timespecs.
 *
 * return -1 if ts1 is older than ts2
 * return +1 if ts1 is newer than ts2
 * return  0 if ts1 is equal to ts2
 */
int
timer_compare (struct timespec *ts1, struct timespec *ts2)
{
    if (ts1->tv_sec < ts2->tv_sec) {
	return -1;
    }

    if (ts1->tv_sec > ts2->tv_sec) {
	return +1;
    }

    if (ts1->tv_nsec < ts2->tv_nsec) {
	return -1;
    }

    if (ts1->tv_nsec > ts2->tv_nsec) {
	return +1;
    }

    return 0;
}

/*
 * Process the timer queue.
 */
void
timer_walk (void)
{
    struct timer_ *timer, *next_timer;
    struct timespec now, min, sleep, rem;

    while (!CIRCLEQ_EMPTY(&timer_qhead)) {

	/*
	 * First pass. Call into expired nodes.
	 * Figure out our min sleep time.
	 */
	clock_gettime(CLOCK_MONOTONIC, &now);
	min.tv_sec = now.tv_sec + 3600;
	min.tv_nsec = 0;

	CIRCLEQ_FOREACH(timer, &timer_qhead, timer_qnode) {

	    /*
	     * Expired ?
	     */
	    if ((timer_compare(&timer->expire, &now) == -1) && timer->cb) {

		printf("Firing %s timer\n", timer->name);

		/*
		 * We may destroy our walking point. Prefetch the next node.
		 */
		next_timer = CIRCLEQ_NEXT(timer, timer_qnode);

		(*timer->cb)(timer); /* Callback */

		CIRCLEQ_REMOVE(&timer_qhead, timer, timer_qnode);
		free(timer);

		/*
		 * End of queue ?
		 */
		if (next_timer != (struct timer_ *)&timer_qhead) {
		    timer = next_timer;
		} else {
		    break;
		}
	    }

	    if ((timer_compare(&timer->expire, &now) >= 0)) {

		/*
		 * Find the min timer.
		 */
		if (timer_compare(&timer->expire, &min) == -1) {
		    min.tv_sec = timer->expire.tv_sec;
		    min.tv_nsec = timer->expire.tv_nsec;
		}
	    }
	}

	/*
	 * Calculate the sleep timer.
	 */
	sleep.tv_sec = min.tv_sec - now.tv_sec;
	sleep.tv_nsec = min.tv_nsec - now.tv_nsec;

	if (sleep.tv_sec < 0) {
	    return;
	}

	/*
	 * Handle nsec overflow.
	 */
	if (sleep.tv_nsec < 0) {
	    sleep.tv_nsec += 10000000000;
	    sleep.tv_sec--;
	}

	nanosleep(&sleep, &rem);
    }
}

void
bgpdump_test1_cb (struct timer_ *timer)
{
    printf("Test 1 CB, timer %p\n", timer);
}

void
bgpdump_test2_cb (struct timer_ *timer)
{
    printf("Test 2 CB, timer %p\n", timer);
}

void
bgpdump_test3_cb (struct timer_ *timer)
{
    printf("Test 3 CB, timer %p\n", timer);
}

void
bgpdump_close_session_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;
    session->state = IDLE;

    close(session->sockfd);
    session->sockfd = -1;

    /*
     * Try to re-establish in 5s.
     */
    timer_add("connect_retry", 5, 0, session, &bgpdump_connect_session_cb);
}

/*
 * Socket is writable. Lets send an open message.
 */
void
bgpdump_send_open_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;
    session->state = OPENSENT;

    push_open_message(session);
    bgpdump_fflush(session);

    /*
     * Kill the session after 10s.
     * Once an open message is received this timer needs to be stopped.
     */
    session->open_sent_timer = timer_add("open_sent", 10, 0, session, &bgpdump_close_session_cb);
}

void
bgpdump_connect_session_cb (struct timer_ *timer)
{

    struct bgp_session_ *session;
    char       protoname[] = "tcp";
    in_addr_t  in_addr;

    struct protoent *protoent;
    struct hostent *hostent;

    session = (struct bgp_session_ *)timer->data;
    session->state = CONNECT;

    /* Get socket. */
    protoent = getprotobyname(protoname);
    if (!protoent) {
        return;
    }
    session->sockfd = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
    if (session->sockfd == -1) {
        return;
    }

    /* Set socket to non blocking */
    fcntl(session->sockfd, F_SETFL, fcntl(session->sockfd, F_GETFL, 0) | O_NONBLOCK);

    /* Prepare sockaddr_in. */
    hostent = gethostbyname(blaster_addr);
    if (!hostent) {
        return;
    }

    in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
    if (in_addr == (in_addr_t)-1) {
        return;
    }

    session->sockaddr_in.sin_addr.s_addr = in_addr;
    session->sockaddr_in.sin_family = AF_INET;
    session->sockaddr_in.sin_port = htons(BGP_TCP_PORT);

    /*
     * Record last connect attempt timestamp.
     */
    clock_gettime(CLOCK_MONOTONIC, &session->last_connect_attempt);

    /* Do the actual connection. */
    if (connect(session->sockfd, (struct sockaddr*)&session->sockaddr_in, sizeof(session->sockaddr_in)) < 0) {

	int res;
	fd_set myset;
	struct timeval tv;
	int valopt;
	socklen_t lon;

	if (errno == EINPROGRESS) {

	    fprintf(stderr, "Connecting to %s\n", blaster_addr);

	    do {
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(session->sockfd, &myset);
		res = select(session->sockfd+1, NULL, &myset, NULL, &tv);
		if (res < 0 && errno != EINTR) {
		    fprintf(stderr, "Error connecting to %s %d - %s\n", blaster_addr, errno, strerror(errno));
		    exit(0);
		}
		else if (res > 0) {

		    /*
		     * Socket selected for write.
		     */
		    lon = sizeof(int);
		    if (getsockopt(session->sockfd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
			fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
			exit(0);
		    }
		    // Check the value returned...
		    if (valopt) {
			fprintf(stderr, "Error in delayed connection() %d - %s\n", valopt, strerror(valopt));
			exit(0);
		    }

		    fprintf(stderr, "Socket ready !\n");

		    #if 0
		    {
			/* Now lets try to set the send buffer size to 4194304 bytes */
			int size = 4096*1024;
			int err;
			err = setsockopt(session->sockfd, SOL_SOCKET, SO_SNDBUF,  &size, sizeof(int));
			if (err != 0) {
			    printf("Unable to set send buffer size, continuing with default size\n");
			}
		    }
		    #endif

		    timer_add("send_open", 0, 0, session, &bgpdump_send_open_cb);
		    break;
		} else {

		    fprintf(stderr, "Connect timeout\n");
		    close(session->sockfd);
		    session->sockfd = -1;

		    /* did not work, retry in 5s */
		    timer_add("connect_retry", 5, 0, session, &bgpdump_connect_session_cb);
		    return;
		}
	    } while (1);
	}
    }
}

void
bgpdump_blaster (void)
{
    int index, peer_index;
    struct ptree *t;
    struct ptree_node *n;
    struct bgp_path_ *bgp_path;
    struct bgp_prefix_ *bgp_prefix;
    struct bgp_route route;
    struct bgp_session_ *session;
    int prefixes;

    session = calloc(1, sizeof(struct bgp_session_));
    if (!session) {
	return;
    }

    session->write_buf = calloc(1, BGP_WRITEBUFSIZE);
    if (!session->write_buf) {
	return;
    }

    CIRCLEQ_INIT(&timer_qhead); /* Init timer queue */

    /*
     * Enqueue a connect event immediatly.
     */
    timer_add("connect_retry", 0, 0, session, &bgpdump_connect_session_cb);

#if 0
    timer_add(10, 0, session, &bgpdump_test1_cb);
    timer_add(20, 0, session, &bgpdump_test2_cb);
    timer_add(50, 0, session, &bgpdump_test3_cb);
#endif

    /*
     * Process the timer queue.
     */
    timer_walk();

# if 0
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

	    memset(&route, 0, sizeof(route));
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
#endif
}
