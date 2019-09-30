set(bio_src
  b_addr.c
  b_dump.c
  b_print.c
  b_sock.c
  b_sock2.c
  bf_buff.c
  bf_lbuf.c
  bf_nbio.c
  bf_null.c
  bio_cb.c
  bio_err.c
  bio_lib.c
  bio_local.h
  bio_meth.c
  bss_acpt.c
  bss_bio.c
  bss_conn.c
  bss_dgram.c
  bss_fd.c
  bss_file.c
  bss_log.c
  bss_mem.c
  bss_null.c
  bss_sock.c
)

add_library(bio ${bio_src})
