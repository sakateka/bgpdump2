srcs = [
  'bgpdump_file.c',
  'bgpdump_peer.c',
  'bgpdump_data.c',
  'bgpdump_route.c',
  'benchmark.c',
  'ptree.c',
  'queue.c',
  'timer.c',
  'bgpdump_savefile.c',
  'bgpdump_query.c',
  'bgpdump_ptree.c',
  'bgpdump_peerstat.c',
  'bgpdump_option.c',
  'bgpdump_parse.c',
  'bgpdump_udiff.c',
  'bgpdump_blaster.c',
  'bgpdump.c',
]

executable(
  'bgpdump2',
  srcs,
  include_directories: [
    include_directories('.'),
    configuration_inc,
  ],
  dependencies: deps,
)
