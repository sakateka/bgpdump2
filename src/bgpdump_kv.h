#pragma once

#include <sys/types.h>

struct keyval_ {
    u_int val;       /* value */
    const char *key; /* key */
};
