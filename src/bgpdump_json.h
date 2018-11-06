/*
 * bgpdump2 JSON export module.
 *
 * Hannes Gredler, November 2018
 *
 * Copyright (C) 2015-2018, RtBrick, Inc.
 */

#ifndef __BGPDUMP_JSON_H__
#define __BGPDUMP_JSON_H__

void route_print_json (struct bgp_route *, uint16_t);
void json_close_all(void);

#define JSON_MAX_FILES 1000
#define JSON_WRITEBUFSIZE 65536

/*
 * Handy macro to write into a buffer.
 * Buffer gets auto-flushed if buffer watermark reaches 90%.
 */
#define JSONWRITE(...) do {                                                     \
    if (ctx->write_idx > ((JSON_WRITEBUFSIZE/10)*9)) {                          \
        json_fflush(ctx);                                                       \
    }                                                                           \
    ctx->write_idx += snprintf(((char *)ctx->write_buf + ctx->write_idx),       \
                        (JSON_WRITEBUFSIZE - ctx->write_idx - 1),               \
                        __VA_ARGS__);                                           \
} while (/*CONSTCOND*/0)

struct json_ctx_ {

    /* write buffer */
    u_char *write_buf;
    uint write_idx;

    /* I/O */
    int output_fd;

    /* JSON formatting stuff */
    int comma_obj;

    uint prefixes;
};

#endif /* __BGPDUMP_JSON_H__ */
