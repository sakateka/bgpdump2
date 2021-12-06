/*
 * bgpdump2 BGP blaster module.
 *
 * Hannes Gredler, May 2020
 *
 * Copyright (C) 2015-2020, RtBrick, Inc.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "netdb.h"

#include "ptree.h"
#include "timer.h"
#include "bgpdump_option.h"
#include "bgpdump_route.h"
#include "bgpdump_data.h"
#include "bgpdump_peer.h"
#include "bgpdump_blaster.h"

/* Globals */
struct timer_root_ timer_root; /* Timer root */
struct log_id_ log_id[LOG_ID_MAX];

struct keyval_ log_names[] = {
    { TIMER,         "timer" },
    { TIMER_DETAIL,  "timer-detail" },
    { UPDATE,        "update" },
    { UPDATE_DETAIL, "update-detail" },
    { KEEPALIVE,     "keepalive" },
    { FSM,           "fsm" },
    { IO,            "io" },
    { NORMAL,        "normal" },
    { ERROR,         "error" },
    { 0, NULL}
};

struct keyval_ bgp_msg_names[] = {
    { BGP_MSG_OPEN,         "open" },
    { BGP_MSG_UPDATE,       "update" },
    { BGP_MSG_NOTIFICATION, "notification" },
    { BGP_MSG_KEEPALIVE,    "keepalive" },
    { 0, NULL}
};

struct keyval_ bgp_fsm_state_names[] = {
    { IDLE,         "idle" },
    { CONNECT,      "connect" },
    { ACTIVE,       "active" },
    { OPENSENT,     "opensent" },
    { OPENCONFIRM,  "openconfirm" },
    { ESTABLISHED,  "established" },
    { 0, NULL}
};

struct keyval_ bgp_notification_error_values[] = {
    { 1, "Message Header Error" },
    { 2, "OPEN Message Error" },
    { 3, "UPDATE Message Error" },
    { 4, "Hold Timer Expired" },
    { 5, "FSM Error" },
    { 6, "Cease" },
    { 0, NULL}
};

struct keyval_ bgp_notification_msg_hdr_error_values[] = {
    { 1, "Connection Not Synchronized" },
    { 2, "Bad Message Length" },
    { 3, "Bad Message Type" },
    { 0, NULL}
};

struct keyval_ bgp_notification_open_error_values[] = {
    { 1, "Unsupported Version Number" },
    { 2, "Bad Peer AS" },
    { 3, "Bad BGP Identifier" },
    { 4, "Unsupported Optional Parameter" },
    { 6, "Unacceptable Hold Time" },
    { 0, NULL}
};

struct keyval_ bgp_notification_update_error_values[] = {
    { 1, "Malformed Attribute List" },
    { 2, "Unrecognized Well-known Attribute" },
    { 3, "Missing Well-known Attribute" },
    { 4, "Attribute Flags Error" },
    { 5, "Attribute Length Error" },
    { 6, "Invalid ORIGIN Attribute" },
    { 8, "Invalid NEXT_HOP Attribute" },
    { 9, "Optional Attribute Error" },
    { 10, "Invalid Network Field" },
    { 11, "Malformed AS_PATH" },
    { 0, NULL}
};

struct keyval_ bgp_notification_cease_error_values[] = {
    { 1, "Maximum Number of Prefixes Reached" },
    { 2, "Administrative Shutdown" },
    { 3, "Peer De-configured" },
    { 4, "Administrative Reset" },
    { 5, "Connection Rejected" },
    { 6, "Other Configuration Change" },
    { 7, "Connection Collision Resolution" },
    { 8, "Out of Resources" },
    { 0, NULL}
};

/* Prototypes */
void bgpdump_connect_session_cb(struct timer_ *);
void bgpdump_read_cb(struct timer_ *);
void bgpdump_ribwalk_cb(struct timer_ *);
void bgpdump_rebase_read_buffer(struct bgp_session_ *);
void push_be_uint(struct bgp_session_ *, uint, unsigned long long);
void write_be_uint(u_char *, uint, unsigned long long);

/*
 * Format the logging timestamp.
 */
char *
fmt_timestamp (void)
{
    static char ts_str[sizeof("Jun 19 08:07:13.711541")];
    struct timespec now;
    struct tm tm;
    int len;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm);

    len = strftime(ts_str, sizeof(ts_str), "%b %d %H:%M:%S", &tm);
    snprintf(ts_str+len, sizeof(ts_str) - len, ".%06lu", now.tv_nsec / 1000);

    return ts_str;
}

/*
 * Check if logging is enabled.
 */
void
log_enable (char *log_name)
{
    int idx;

    idx = 0;
    while (log_names[idx].key) {
	if (strcmp(log_names[idx].key, log_name) == 0) {
	    log_id[log_names[idx].val].enable = 1;
	}
	idx++;
    }
}

const char *
keyval_get_key (struct keyval_ *keyval, int val)
{
    struct keyval_ *ptr;

    ptr = keyval;
    while (ptr->key) {
	if (ptr->val == val) {
	    return ptr->key;
	}
	ptr++;
    }
    return "unknown";
}

/*
 * LOG changes in the FSM.
 */
void
bgpdump_fsm_change (struct bgp_session_ *session, state_t new_state)
{
    if (session->state == new_state) {
	return;
    }

    LOG(FSM, "Neighbor %s state change from %s -> %s\n", blaster_addr,
	keyval_get_key(bgp_fsm_state_names, session->state),
	keyval_get_key(bgp_fsm_state_names, new_state));

    session->state = new_state;
}

/*
 * Flush the write buffer.
 * return 0 if buffer is empty and if the buffer has been fully drained.
 * return 1 if there is still some data lurking in the buffer.
 */
int
bgpdump_fflush (struct bgp_session_ *session)
{
    int res;

    if (!session->write_idx) {
        return 0;
    }

    res = write(session->sockfd, session->write_buf, session->write_idx);

    /*
     * Blocked ?
     */
    if (res == -1) {
        switch (errno) {
        case EAGAIN:
	    break;

	case EPIPE:
	    return 0;

        default:
	    LOG(ERROR, "write(): error %s (%d)\n", strerror(errno), errno);
	    break;
        }
	return 1;
    }

    /*
     * Full write ?
     */
    if (res == (int)session->write_idx) {
	LOG(IO, "Full write %u bytes buffer to %s\n", res, blaster_addr);
	session->write_idx = 0;
	session->stats.octets_sent += res;
	return 0;
    }

    /*
     * Partial write ?
     */
    if (res && res < (int)session->write_idx) {
	LOG(IO, "Partial write %u bytes buffer to %s\n", res, blaster_addr);
	session->stats.octets_sent += res;

	/*
	 * Rebase the buffer.
	 */
	memmove(session->write_buf, session->write_buf+res, session->write_idx - res);
	session->write_idx -= res;
	return 1;
    }

    return 0;
}

void
bgpdump_push_prefix(struct bgp_session_ *session, struct bgp_prefix_ *prefix)
{
    int idx, length;

    *(session->write_buf + session->write_idx) = prefix->prefix_length;
    session->write_idx++;
    length = (prefix->prefix_length + 7) / 8;
    for (idx = 0; idx < length; idx++) {
	*(session->write_buf + session->write_idx) = prefix->prefix[idx];
	session->write_idx++;
    }

    if (session->ribwalk_withdraw) {
	session->stats.prefixes_withdrawn++;
    } else {
	session->stats.prefixes_sent++;
    }
}

/*
 * Drain the write buffer. Kill once the buffer is empty
 */
void
bgpdump_drain_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;

    if (!bgpdump_fflush(session)) {
	timer_del(session->write_job);
    }
}

void
bgpdump_send_eor (struct bgp_session_ *session, uint16_t af, uint8_t safi)
{
    uint16_t afi;

    if (af == AF_INET && safi == 1) {

	/* ipv4-unicast */
	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(session, 2, 23); /* length */
	push_be_uint(session, 1, BGP_MSG_UPDATE); /* message type */
	push_be_uint(session, 2, 0); /* withdrawn routes length  */
	push_be_uint(session, 2, 0); /* total path attributes length */

    } else {

	/* all-other afi/safi pairs */
	afi = 0;
	if (af == AF_INET6) {
	    afi = 2;
	}

	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(session, 2, 29); /* length */
	push_be_uint(session, 1, BGP_MSG_UPDATE); /* message type */
	push_be_uint(session, 2, 0); /* withdrawn routes length  */
	push_be_uint(session, 2, 6); /* total path attributes length */

	push_be_uint(session, 1, 0x80); /* pa_flags */
	push_be_uint(session, 1, 15); /* MP_UNREACH_NLRI */
	push_be_uint(session, 1, 3); /* pa_length */
	push_be_uint(session, 2, afi); /* AFI */
	push_be_uint(session, 1, safi); /* SAFI */

    }
    session->stats.updates_sent++;
}

void
bgpdump_ribwalk_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;
    struct bgp_path_ *bgp_path;
    struct bgp_prefix_ *prefix;
    struct bgp_route route;
    struct ptree *t;
    int peer_index, prefix_index;
    uint update_start_idx, tpa_length_idx, length;
    uint updates_encoded;

    session = (struct bgp_session_ *)timer->data;

    if (session->ribwalk_complete) {
	return;
    }

    if (withdraw_delay && session->ribwalk_withdraw) {
	struct timespec now, diff;

	clock_gettime(CLOCK_MONOTONIC, &now);
	timespec_sub(&diff, &now, &session->eor_ts);

	/* backoff if withdraw delay has not yet been reached */
	if (diff.tv_sec < withdraw_delay) {
	    LOG(NORMAL, "Delay withdraw generation for %lu secs\n", withdraw_delay - diff.tv_sec);
	    timer_add(&timer_root, &session->write_job, "write_job",
		      withdraw_delay, 0, session, bgpdump_ribwalk_cb);
	    return;
	}
    }

    if (!session->ribwalk_pnode) {
	peer_index = peer_spec_index[session->ribwalk_peer_index];

	t = peer_table[peer_index].path_root;
	if (!t || !peer_table[peer_index].path_count) {

	    /* Next RIB */
	    if (session->ribwalk_peer_index < peer_spec_size) {
		session->ribwalk_peer_index++;
	    } else {
		session->ribwalk_complete = true;
		return;
	    }
	    session->ribwalk_pnode = NULL;
	    session->ribwalk_prefix_index = 0;

	    return;
	}

	LOG(NORMAL, "RIB for peer-index %d: AS %u, ipv4 prefixes %u, ipv6 prefixes %u, %u paths\n",
	    peer_index,
	    peer_table[peer_index].asnumber,
	    peer_table[peer_index].ipv4_count,
	    peer_table[peer_index].ipv6_count,
	    peer_table[peer_index].path_count);

	session->ribwalk_pnode = ptree_head(t);

	/*
	 * When we dump to a file it's time to open it.
	 */
	if (blaster_dump) {
	    char filename[128];
	    char bgp_id[sizeof("255.255.255.255")];
	    char ip_addr[sizeof("255.255.255.255")];
	    struct peer *my_peer;

	    my_peer = &peer_table[peer_index];
	    inet_ntop(AF_INET, &my_peer->bgp_id, bgp_id, sizeof(bgp_id));
	    inet_ntop(AF_INET, &my_peer->ipv4_addr, ip_addr, sizeof(ip_addr));
	    snprintf(filename, sizeof(filename), "peer%u-asn%u-bgpid%s-ip%s.bgp",
		     peer_index, my_peer->asnumber, bgp_id, ip_addr);
	    session->file = fopen(filename, "w");
	    if (!session->file) {
		LOG(ERROR, "Could not open blaster dump file %s", filename);
		return;
	    }
	    session->sockfd = fileno(session->file);
	    if (session->sockfd == -1) {
		LOG(ERROR, "Could not set FD for blaster dump file %s", filename);
		return;
	    }
	}
    }

    if (session->write_idx > (BGP_WRITEBUFSIZE - BGP_MAX_MESSAGE_SIZE)) {
	LOG(IO, "Write buffer full\n");
    }

    /*
     * Encode up until there is at least space for one full message.
     */
    updates_encoded = 0;
    while (session->write_idx < (BGP_WRITEBUFSIZE - BGP_MAX_MESSAGE_SIZE)) {

	bgp_path = session->ribwalk_pnode->data;
	if (!bgp_path) {

	    /* internal node */
	    session->ribwalk_pnode = ptree_next(session->ribwalk_pnode);
	    continue;
	}

	if (session->ribwalk_prefix_index == bgp_path->refcount) {

	    /* All routes for this path have been encoded, progress to next path. */
	    session->ribwalk_pnode = ptree_next(session->ribwalk_pnode);
	    session->ribwalk_prefix_index = 0;

	    /*
	     * Is this the end of this RIB ?
	     */
	    if (!session->ribwalk_pnode) {

		/*
		 * Progress to next RIB
		 * if no withdraws should be send or
		 * withdraw sending of this RIB is complete.
		 */
		if (!withdraw_delay || (withdraw_delay && session->ribwalk_withdraw)) {
		    if (session->ribwalk_peer_index < peer_spec_size-1) {
			session->ribwalk_peer_index++;
		    } else {
			session->ribwalk_complete = true;
			LOG(NORMAL, "RIB walk complete\n");
		    }
		}

		/*
		 * Toggle update/withdraw state
		 */
		if (withdraw_delay) {
		    session->ribwalk_withdraw = ~session->ribwalk_withdraw;
		}

		/*
		 * We're done. Send End of RIB marker which is an empty BGP update.
		 */
		bgpdump_send_eor(session, bgp_path->af, 1);

		bgpdump_fflush(session);
		LOG(NORMAL, "Sent %u updates, %u prefixes sent, %u prefixes withdrawn, %u octets\n",
		    session->stats.updates_sent,
		    session->stats.prefixes_sent,
		    session->stats.prefixes_withdrawn,
		    session->stats.octets_sent);

		clock_gettime(CLOCK_MONOTONIC, &session->eor_ts);
		LOG(NORMAL, "End-of-RIB\n");

		/*
		 * Re-schedule.
		 */
		if (session->ribwalk_complete) {
		    timer_add(&timer_root, &session->write_job, "write_job",
			      0, 20 * MSEC, session, bgpdump_drain_cb);
		} else {
		    timer_add(&timer_root, &session->write_job, "write_job",
			      0, 20 * MSEC, session, bgpdump_ribwalk_cb);
		}
		return;
	    }
	    continue;
	}

	if (session->ribwalk_prefix_index &&
	    (session->ribwalk_prefix_index < bgp_path->refcount)) {
	    LOG(IO, "Resuming encoding %u/%u prefixes\n",
		bgp_path->refcount - session->ribwalk_prefix_index,
		bgp_path->refcount);
	}

	/*
	 * Encode an Update.
	 */
	update_start_idx = session->write_idx;

	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(session, 8, 0xffffffffffffffff); /* marker */

	push_be_uint(session, 2, 0); /* length, will be overwritten later */
	push_be_uint(session, 1, BGP_MSG_UPDATE); /* message type */

	if (!session->ribwalk_withdraw) {

	    /*
	     * Encode update.
	     */
	    push_be_uint(session, 2, 0); /* withdrawn routes length  */
	    tpa_length_idx = session->write_idx;
	    push_be_uint(session, 2, bgp_path->path_length); /* total path attributes length */

	    /* path attributes */
	    memcpy(session->write_buf+session->write_idx,
		   session->ribwalk_pnode->key,
		   bgp_path->path_length);
	    session->write_idx += bgp_path->path_length;

	    if (log_id[UPDATE].enable) {
		int old_show, old_detail;

		memset(&route, 0, sizeof(route));
		LOG(UPDATE, "Encode path %p, length %u, refcount %u\n",
		    bgp_path, bgp_path->path_length, bgp_path->refcount);

		old_show = show;
		old_detail = detail;
		show = 1;
		detail = 1;
		bgpdump_process_bgp_attributes(&route, session->ribwalk_pnode->key,
					       session->ribwalk_pnode->key + bgp_path->path_length);
		show = old_show;
		detail = old_detail;
	    }
	} else {

	    /*
	     * Encode withdraw.
	     */
	    push_be_uint(session, 2, 0); /* withdrawn routes length. Will be overwritten later */
	}

	/* Encode prefixes */
	prefix_index = 0;

	if (bgp_path->af == AF_INET) {

	    /* ipv4 */
	    CIRCLEQ_FOREACH(prefix, &bgp_path->path_qhead, prefix_qnode) {
		if (session->ribwalk_prefix_index &&
		    (prefix_index < session->ribwalk_prefix_index)) {
		    prefix_index++;
		    continue;
		}
		bgpdump_push_prefix(session, prefix);
		prefix_index++;

		/*
		 * If there is not enough space for at least one full ipv4 prefix then bail.
		 */
		if (session->write_idx - update_start_idx >= (BGP_MAX_MESSAGE_SIZE - 5)) {
		    LOG(IO, "Update full, encoded %u ipv4 prefixes\n", prefix_index);
		    break;
		}
	    }
	} else if (bgp_path->af == AF_INET6) {

	    /* ipv6 */

	    uint pa_start_idx;

	    /* first write a MP_REACH attribute header */

	    push_be_uint(session, 1, 0x90); /* pa_flags: extended length */
	    push_be_uint(session, 1, 14); /* MP_REACH_NLRI */
	    push_be_uint(session, 2, 0); /* length, will be overwritten later */
	    pa_start_idx = session->write_idx;
	    push_be_uint(session, 2, 2); /* AFI ipv6 */
	    push_be_uint(session, 1, 1); /* SAFI unicast */

	    /* nexthop */
	    push_be_uint(session, 1, 16); /* nexthop length */
	    memcpy(session->write_buf+session->write_idx, bgp_path->nexthop, 16);
	    session->write_idx += 16;

	    push_be_uint(session, 1, 0); /* SNPA / reserved */

	    CIRCLEQ_FOREACH(prefix, &bgp_path->path_qhead, prefix_qnode) {
		if (session->ribwalk_prefix_index &&
		    (prefix_index < session->ribwalk_prefix_index)) {
		    prefix_index++;
		    continue;
		}
		bgpdump_push_prefix(session, prefix);
		prefix_index++;

		/*
		 * If there is not enough space for at least one full ipv6 prefix then bail.
		 */
		if (session->write_idx - update_start_idx >= (BGP_MAX_MESSAGE_SIZE - 17)) {
		    LOG(IO, "Update full, encoded %u ipv6 prefixes\n", prefix_index);
		    break;
		}
	    }

	    /* overwrite pa length */
	    length = session->write_idx - pa_start_idx;
	    write_be_uint(session->write_buf+pa_start_idx-2, 2, length);

	    /* overwrite total pa length */
	    write_be_uint(session->write_buf+tpa_length_idx, 2, bgp_path->path_length + length + 4);
	}
	session->ribwalk_prefix_index = prefix_index; /* Update cursor */

	if (session->ribwalk_withdraw)  {
	    length = session->write_idx - (update_start_idx+16+3+2);
	    write_be_uint(session->write_buf+update_start_idx+19, 2, length); /* overwrite withdrawn routes length */
	    push_be_uint(session, 2, 0); /* total path attributes length */
	}

	/*
	 * Calculate Message length field.
	 */
	length = session->write_idx - update_start_idx;
	write_be_uint(session->write_buf+update_start_idx+16, 2, length); /* overwrite message length */

	session->stats.updates_sent++;
	updates_encoded++;
    }

    if (updates_encoded) {
	LOG(NORMAL, "Sent %u updates, %u prefixes sent, %u prefixes withdrawn, %u octets\n",
	    session->stats.updates_sent,
	    session->stats.prefixes_sent,
	    session->stats.prefixes_withdrawn,
	    session->stats.octets_sent);
    }

    /*
     * Start the write loop.
     */
    bgpdump_fflush(session);
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
 * Quick'n dirty big endian reader.
 */
unsigned long long
read_be_uint (u_char *data, uint length)
{
    uint idx;
    unsigned long long value;

    if (!length || length > 8) {
	return 0;
    }

    value = 0;
    for (idx = 0; idx < length; idx++) {
	value <<= 8;
	value = value | *(data+idx);
    }

    return value;
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
push_mp_capability (struct bgp_session_ *session, uint afi, uint safi)
{
    uint cap_idx, length;


    /* Capability */
    push_be_uint(session, 1, 2); /* Cap code */
    push_be_uint(session, 1, 0); /* Cap length. To be updated later */
    cap_idx = session->write_idx;

    /*
     * MP capability.
     */
    push_be_uint(session, 1, 1); /* MP extension CAp*/
    push_be_uint(session, 1, 4); /* Length */
    push_be_uint(session, 2, afi);
    push_be_uint(session, 1, 0); /* Reserved */
    push_be_uint(session, 1, safi);

    /*
     * Calculate Capability length field.
     */
    length = session->write_idx - cap_idx;
    write_be_uint(session->write_buf+cap_idx-1, 1, length); /* overwrite Cap length */
}

uint32_t
get_my_as (void)
{
    if (autsiz) {
	return autnums[0];
    } else {
	return 65535;
    }
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

    push_be_uint(session, 4, get_my_as()); /* my AS */

    /*
     * Calculate Capability length field.
     */
    length = session->write_idx - cap_idx;
    write_be_uint(session->write_buf+cap_idx-1, 1, length); /* overwrite Cap length */
}

/*
 * Write a BGP keepalive message.
 */
void
push_keepalive_message (struct bgp_session_ *session)
{
    uint keepalive_start_idx, length;

    /*
     * Enough space for keepalive ?
     */
    if (session->write_idx > (BGP_WRITEBUFSIZE - 19)) {
	return;
    }

    keepalive_start_idx = session->write_idx;

    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */

    push_be_uint(session, 2, 0); /* length */
    push_be_uint(session, 1, BGP_MSG_KEEPALIVE); /* message type */

    /*
     * Calculate Message length field.
     */
    length = session->write_idx - keepalive_start_idx;
    write_be_uint(session->write_buf+keepalive_start_idx+16, 2, length); /* overwrite message length */
}

/*
 * Write a BGP open message.
 */
void
push_open_message (struct bgp_session_ *session)
{
    uint open_start_idx, length, opt_parms_idx, opt_parms_length, my_as;

    open_start_idx = session->write_idx;

    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(session, 8, 0xffffffffffffffff); /* marker */

    push_be_uint(session, 2, 0); /* length */
    push_be_uint(session, 1, BGP_MSG_OPEN); /* message type */

    push_be_uint(session, 1, 4); /* version 4 */

    my_as = get_my_as();
    if (my_as > 65535) {
	push_be_uint(session, 2, 23456); /* my AS */
    } else {
	push_be_uint(session, 2, my_as); /* my AS */
    }
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
     * MP capability for ipv4 and ipv6
     */
    push_mp_capability(session, 1, 1); /* ipv4 unicast */
    push_mp_capability(session, 2, 1); /* ipv6 unicast */
    push_mp_capability(session, 1, 4); /* ipv4 labeled unicast */
    push_mp_capability(session, 2, 4); /* ipv6 labeled unicast */

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

void
bgpdump_close_session_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;
    bgpdump_fsm_change(session, IDLE);

    close(session->sockfd);
    session->sockfd = -1;

    /*
     * Kill our timers and jobs.
     */
    timer_del(session->connect_timer);
    timer_del(session->send_open_timer);
    timer_del(session->open_sent_timer);
    timer_del(session->keepalive_timer);
    timer_del(session->hold_timer);

    timer_del(session->read_job);
    timer_del(session->write_job);
    timer_del(session->close_timer);

    /*
     * Reset buffers.
     */
    session->write_idx = 0;
    session->read_buf_start = session->read_buf;
    session->read_buf_end = session->read_buf;

    /*
     * Try to re-establish in 5s.
     */
    timer_add(&timer_root, &session->connect_timer, "connect_retry",
	      5, 0, session, &bgpdump_connect_session_cb);
}

/*
 * Send an keepalive message.
 */
void
bgpdump_send_keepalive_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;

    push_keepalive_message(session);
    bgpdump_fflush(session);
}


/*
 * Socket is writable. Lets send an open message.
 */
void
bgpdump_send_open_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;

    session = (struct bgp_session_ *)timer->data;

    push_open_message(session);
    bgpdump_fflush(session);

    /*
     * Kill the session after 10s.
     * Once an open message is received this timer needs to be stopped.
     */
    timer_add(&timer_root, &session->open_sent_timer, "open_sent",
	      10, 0, session, &bgpdump_close_session_cb);
    bgpdump_fsm_change(session, OPENSENT);

    /*
     * Start the read job.
     */
    timer_add_periodic(&timer_root, &session->read_job, "read_job",
		       1, 0, session, bgpdump_read_cb);
}

void
bgpdump_connect_session_cb (struct timer_ *timer)
{
    struct protoent *protoent;
    struct bgp_session_ *session;
    char protoname[] = "tcp";
    int af, res;

    session = (struct bgp_session_ *)timer->data;

    memset(&session->addr4, 0, sizeof(session->addr4));
    memset(&session->addr6, 0, sizeof(session->addr6));
    memset(&session->stats, 0, sizeof(session->stats));

    /* First figure out what addr family the socket shall be */
    af = 0;
    if (inet_pton(AF_INET, blaster_addr, &session->addr4.sin_addr)) {
	af = AF_INET;
    } else if (inet_pton(AF_INET6, blaster_addr, &session->addr6.sin6_addr)) {
	af = AF_INET6;
    }

    /* Get socket. */
    protoent = getprotobyname(protoname);
    if (!protoent) {
        return;
    }
    session->sockfd = socket(af, SOCK_STREAM, protoent->p_proto);
    if (session->sockfd == -1) {
        return;
    }

    /* Set socket to non blocking */
    fcntl(session->sockfd, F_SETFL, fcntl(session->sockfd, F_GETFL, 0) | O_NONBLOCK);

    bgpdump_fsm_change(session, CONNECT);

    res = 0;
    switch (af) {
    case AF_INET:
	session->addr4.sin_family = AF_INET;
	session->addr4.sin_port = htons(BGP_TCP_PORT);

	res = connect(session->sockfd, (struct sockaddr*)&session->addr4, sizeof(session->addr4));
	break;
    case AF_INET6:
	session->addr6.sin6_family = AF_INET6;
	session->addr6.sin6_port = htons(BGP_TCP_PORT);

	res = connect(session->sockfd, (struct sockaddr*)&session->addr6, sizeof(session->addr6));
	break;
    }

    /* Do the actual connection. */
    if (res < 0) {

	int res;
	fd_set myset;
	struct timeval tv;
	int valopt;
	socklen_t lon;

	if (errno == EINPROGRESS) {

	    LOG(NORMAL, "Connecting to %s\n", blaster_addr);

	    do {
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(session->sockfd, &myset);
		res = select(session->sockfd+1, NULL, &myset, NULL, &tv);
		if (res < 0 && errno != EINTR) {
		    LOG(ERROR, "Error connecting to %s %d - %s\n", blaster_addr, errno, strerror(errno));
		    exit(0);
		}
		else if (res > 0) {

		    /*
		     * Socket selected for write.
		     */
		    lon = sizeof(int);
		    if (getsockopt(session->sockfd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
			LOG(ERROR, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
			exit(0);
		    }
		    /* Check the return value */
		    if (valopt) {
			LOG(ERROR, "Error in delayed connection() %d - %s\n", valopt, strerror(valopt));
			exit(0);
		    }

		    LOG(NORMAL, "Socket to %s is writeable\n", blaster_addr);

		    #if 1
		    {
			/* Now lets try to set the send buffer size to 4194304 bytes */
			int size = 4096*1024;
			int err;
			err = setsockopt(session->sockfd, SOL_SOCKET, SO_SNDBUF,  &size, sizeof(int));
			if (err != 0) {
			    LOG(ERROR, "Unable to set send buffer size, continuing with default size\n");
			}
		    }
		    #endif

		    timer_add(&timer_root, &session->send_open_timer, "send_open",
			      0, 0, session, &bgpdump_send_open_cb);
		    break;
		} else {

		    LOG(NORMAL, "Connect timeout\n");
		    close(session->sockfd);
		    session->sockfd = -1;

		    /* did not work, retry in 5s */
		    timer_add(&timer_root, &session->connect_timer, "connect",
			      5, 0, session, &bgpdump_connect_session_cb);
		    return;
		}
	    } while (1);
	}
    }
}

/*
 * Read and process the BGP message stream until no full BGP message can get consumed.
 */
void
bgpdump_read (struct bgp_session_ *session)
{
    uint size, length, type;

    while (1) {
	size = session->read_buf_end - session->read_buf_start;

	/* Minimum message size */
	if (size < 19) {
	    break;
	}

	/* Full message on the wire to consume ? */
	length = read_be_uint(session->read_buf_start+16, 2);
	type = *(session->read_buf_start+18);
	if (length > size) {
	    break;
	}

	LOG(NORMAL, "Read %s message (%u), length %u from %s\n",
	    keyval_get_key(bgp_msg_names, type), type, length, blaster_addr);

	switch (type) {
	case BGP_MSG_OPEN:
	    /* stop timer */
	    timer_del(session->open_sent_timer);
	    bgpdump_fsm_change(session, OPENCONFIRM);

	    push_keepalive_message(session);
	    bgpdump_fflush(session);

	    session->peer_as = read_be_uint(session->read_buf_start+20, 2);
	    session->peer_holdtime = read_be_uint(session->read_buf_start+22, 2);
	    LOG(NORMAL, "  Peer AS %u, holdtime %us\n", session->peer_as, session->peer_holdtime);
	    timer_add_periodic(&timer_root, &session->keepalive_timer, "keepalive",
			       30, 0, session, bgpdump_send_keepalive_cb);
	    break;

	case BGP_MSG_NOTIFICATION:
	    {
		uint8_t error_code, error_subcode;

		error_code = *(session->read_buf_start+19);
		error_subcode = *(session->read_buf_start+20);

		switch (error_code) {
		case 1: /* Message Header Error */
		    LOG(NORMAL, "Notification Error: %s (%u), %s (%u)\n",
			keyval_get_key(bgp_notification_error_values, error_code), error_code,
			keyval_get_key(bgp_notification_msg_hdr_error_values, error_subcode), error_subcode);
		    break;
		case 2: /* OPEN Message Error */
		    LOG(NORMAL, "Notification Error: %s (%u), %s (%u)\n",
			keyval_get_key(bgp_notification_error_values, error_code), error_code,
			keyval_get_key(bgp_notification_open_error_values, error_subcode), error_subcode);
		    break;
		case 3: /* Update Message Error */
		    LOG(NORMAL, "Notification Error: %s (%u), %s (%u)\n",
			keyval_get_key(bgp_notification_error_values, error_code), error_code,
			keyval_get_key(bgp_notification_update_error_values, error_subcode), error_subcode);
		    break;
		case 6: /* Cease */
		    LOG(NORMAL, "Notification Error: %s (%u), %s (%u)\n",
			keyval_get_key(bgp_notification_error_values, error_code), error_code,
			keyval_get_key(bgp_notification_cease_error_values, error_subcode), error_subcode);
		    break;
		default:
		    LOG(NORMAL, "Notification Error: %s (%u), subcode %u\n",
			keyval_get_key(bgp_notification_error_values, error_code), error_code, error_subcode);
		    break;
		}
	    }

	    /* restart session */
	    timer_add(&timer_root, &session->close_timer, "restart_session",
		      0, 0, session, &bgpdump_close_session_cb);
	    return;

	case BGP_MSG_KEEPALIVE:
	    bgpdump_fsm_change(session, ESTABLISHED);

	    /* reset hold timer */
	    if (session->peer_holdtime) {
		timer_add(&timer_root, &session->hold_timer, "holdtime",
			  session->peer_holdtime, 0, session, &bgpdump_close_session_cb);
	    }

	    /*
	     * Start the walk job.
	     */
	    timer_add_periodic(&timer_root, &session->write_job, "write_job",
			       0, 20 * MSEC, session, bgpdump_ribwalk_cb);
	    break;

	case BGP_MSG_UPDATE:
	    /* ignore */

	    /* reset hold timer */
	    if (session->peer_holdtime) {
		timer_add(&timer_root, &session->hold_timer, "holdtime",
			  session->peer_holdtime, 0, session, &bgpdump_close_session_cb);
	    }
	    break;

	default:
	    break;
	}

	/*
	 * Progress pointer to next BGP message.
	 */
	session->read_buf_start += length;
    }

    bgpdump_rebase_read_buffer(session);
}

void
bgpdump_read_cb (struct timer_ *timer)
{
    struct bgp_session_ *session;
    uint space_left, res;

    session = (struct bgp_session_ *)timer->data;

    /*
     * Start the read loop.
     */
    for (space_left = BGP_READBUFSIZE; space_left; ) {

        space_left = (session->read_buf + BGP_READBUFSIZE) - session->read_buf_end;
	res = read(session->sockfd, session->read_buf_end, space_left);

	/*
	 * Blocked ?
	 */
	if (res == -1) {

	    switch (errno) {
	    case EAGAIN:
		break;

	    default:
		LOG(ERROR, "  read() error %s\n", strerror(errno));
		break;
	    }
	    break;
	}

	session->read_buf_end += res;
	bgpdump_read(session);

	/*
	 * close timer is set, if something went wrong during reading. Bail.
	 */
	if (session->close_timer) {
	    timer_del(session->read_job);
	    return;
	}
    }
}

/*
 * When there is only little data left and
 * the buffer start is close to buffer end,
 * then 'rebase' the buffer by copying
 * the tail data to the buffer head.
 */
void
bgpdump_rebase_read_buffer (struct bgp_session_ *session)
{
    int size;

    /*
     * As per the comparison below a buffersize
     * of 64K and a divisor of 16 ensures that we
     * always can read a full BGP message of 4K.
     */
    if ((session->read_buf_start - session->read_buf) > (BGP_READBUFSIZE / 16)) {

        /*
         * Copy what is left to the buffer start.
         */
        size = session->read_buf_end - session->read_buf_start;
        memcpy(session->read_buf, session->read_buf_start, size);
        session->read_buf_start = session->read_buf;
        session->read_buf_end = session->read_buf + size;
    }
}

void
bgpdump_blaster (void)
{
    struct bgp_session_ *session;

    session = calloc(1, sizeof(struct bgp_session_));
    if (!session) {
	return;
    }

    /*
     * Init read buffer.
     */
    session->read_buf = calloc(1, BGP_READBUFSIZE);
    if (!session->read_buf) {
	return;
    }
    session->read_buf_start = session->read_buf;
    session->read_buf_end = session->read_buf;

    /*
     * Init write buffer.
     */
    session->write_buf = calloc(1, BGP_WRITEBUFSIZE);
    if (!session->write_buf) {
	return;
    }
    session->write_idx = 0;

    timer_init_root(&timer_root); /* Init timer queue */

    /* Logging */
    log_id[NORMAL].enable = true;
    log_id[ERROR].enable = true;
    log_id[FSM].enable = true;

    if (blaster_dump) {

	/*
	 * In case of blaster_dump option we'll just dump the BGP stream into a file.
	 */
	timer_add_periodic(&timer_root, &session->write_job, "write_job",
			   0, 20 * MSEC, session, bgpdump_ribwalk_cb);

    } else {

	/*
	 * Enqueue a connect event immediatly.
	 */
	timer_add(&timer_root, &session->connect_timer,
		  "connect", 0, 0, session, &bgpdump_connect_session_cb);
    }

    /*
     * Block SIGPIPE. This happens when a session disconnects.
     * We handle EPIPE when writing the buffer.
     */
    signal(SIGPIPE, SIG_IGN);

    /*
     * Process the timer queue.
     */
    timer_walk(&timer_root);
}
