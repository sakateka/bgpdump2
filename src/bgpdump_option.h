/*
 * Bgpdump2: A Tool to Read and Compare the BGP RIB Dump Files.
 * Copyright (C) 2015.  Yasuhiro Ohara <yasu@nttv6.jp>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BGPDUMP_OPTION_H__
#define __BGPDUMP_OPTION_H__

#define BGPDUMP_VERSION "v2.0.1"
#define BGPDUMP_BUFSIZ_DEFAULT "16MiB"

extern int quiet;
extern int debug;
extern int detail;
extern int verbose;
extern int show;
extern int brief;
extern int compat_mode;
extern int udiff;
extern int udiff_verbose;
extern int udiff_lookup;
extern int route_count;
extern int plen_dist;
extern int stats;
extern int benchmark;
extern int lookup;
extern char *lookup_addr;
extern char *lookup_file;
extern int peer_table_only;
extern int heatmap;
extern char *heatmap_prefix;
extern int json_dump;
extern char json_page[];
extern char json_ip[];
extern int json_port;
extern char *json_peergroup;
extern int localpref;
extern int blaster;
extern char *blaster_addr;

extern unsigned long long bufsiz;
extern unsigned long long nroutes;

void usage ();
void version ();

int
bgpdump_getopt (int argc, char **argv);

#endif /* __BGPDUMP_OPTION_H__ */
