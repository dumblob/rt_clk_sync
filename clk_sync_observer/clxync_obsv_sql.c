#ifdef SQL

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

#include <sqlite3.h>
#include "clxync_obsv.h"

static sqlite3 *db;
static sqlite3_stmt *ins_log_exe, *ins_ntp_tx_exe, *ins_ntp_rx_exe;

int sql_rc(int rc) {
  switch (rc) {
  case SQLITE_OK:
  case SQLITE_ROW:
  case SQLITE_DONE:
  case SQLITE_BUSY:
    return rc;
  default:
    fprintf(stderr, "sqlite error (%d): %s\n", rc, sqlite3_errmsg(db));
    exit(rc);
  }
}

void sql_log(char *msg) {
  struct timespec ts;
  int i;
  clock_gettime(LOG_CLK_ID, &ts);
  if (msg[(i = strlen(msg)-1)] == '\n')
    msg[i] = '\0';
  sql_rc(sqlite3_bind_int64(ins_log_exe, 1, ts.tv_sec));
  sql_rc(sqlite3_bind_int64(ins_log_exe, 2, ts.tv_nsec));
  sql_rc(sqlite3_bind_text(ins_log_exe,  3, msg, -1, SQLITE_STATIC));
  while (sql_rc(sqlite3_step(ins_log_exe)) == SQLITE_BUSY) {
    fprintf(stderr, "db busy: wait & retry\n");
    usleep(1000);
  }
  sql_rc(sqlite3_reset(ins_log_exe));
}

/* * */

typedef struct {
  uint16_t src_port, dst_port;
  char src_addr_s[INET6_ADDRSTRLEN+1], dst_addr_s[INET6_ADDRSTRLEN+1];
  uint64_t tx_tstamp;
  int64_t db_id;
} ntp_info_t;

#define PKT_BUF_LEN 256 /* must be 2^n */
static ntp_info_t pkt_buf[PKT_BUF_LEN];
static unsigned pkt_buf_idx = 0;

static inline unsigned next_idx(unsigned idx) {
  ++idx;
  idx &= PKT_BUF_LEN-1;
  return idx;
}

static inline unsigned prev_idx(unsigned idx) {
  --idx;
  idx &= PKT_BUF_LEN-1;
  return idx;
}

int find_rx_packet(ntp_info_t *ntp_tx) {
  int i, idx = pkt_buf_idx;
  ntp_info_t *nfo;
  for (i = 0; i < PKT_BUF_LEN; i++) {
    nfo = pkt_buf + idx;
    if ((nfo->src_port == NTP_PORT) &&
	(strcmp(nfo->src_addr_s, ntp_tx->dst_addr_s) == 0) &&
	(strcmp(nfo->dst_addr_s, ntp_tx->src_addr_s) == 0) &&
	(nfo->tx_tstamp == ntp_tx->tx_tstamp))
      return idx;
    idx = prev_idx(idx);
  }
  return -1;
}

int find_tx_packet(ntp_info_t *ntp_rx) {
  int i, idx = pkt_buf_idx;
  ntp_info_t *nfo;
  for (i = 0; i < PKT_BUF_LEN; i++) {
    nfo = pkt_buf + idx;
    if ((nfo->dst_port == NTP_PORT) &&
	(strcmp(nfo->src_addr_s, ntp_rx->dst_addr_s) == 0) &&
	(strcmp(nfo->dst_addr_s, ntp_rx->src_addr_s) == 0) &&
	(nfo->tx_tstamp == ntp_rx->tx_tstamp))
      return idx;
    idx = prev_idx(idx);
  }
  return -1;
}

void put_packet(ntp_info_t *ntp) {
  int idx = next_idx(pkt_buf_idx);
  memcpy(pkt_buf + idx, ntp, sizeof(ntp_info_t));
}

static inline uint32_t hi32(uint64_t w) {
  w >>= 32;
  return (uint32_t)w;
}

static inline uint32_t lo32(uint64_t w) {
  return (uint32_t)w;
}

void sql_output_ntp_packet(bool ipv6,
			   const uint8_t *src_ip, uint16_t src_port,
			   const uint8_t *dst_ip, uint16_t dst_port,
			   const struct timeval *tstamp, /* actually in nsec */
			   ntp_pkt_t *ntp) {
  sqlite3_stmt *ins_exe;
  ntp_info_t nfo;
  int pair_idx;
  int (*find_packet)(ntp_info_t *ntp_rx);
  /* determine, whether we have got tx or rx packet;
     simply assume, that client's local port will never be equal to 123;
     in case of error, file it under rx
  */
  if (dst_port == NTP_PORT) {
    /* tx pkt */
    ins_exe = ins_ntp_tx_exe;
    find_packet = find_rx_packet;
    nfo.tx_tstamp = ntp->xmt_tstamp;
  }
  else {
    /* rx pkt */
    ins_exe = ins_ntp_rx_exe;
    find_packet = find_tx_packet;
    nfo.tx_tstamp = ntp->org_tstamp;
  }
  nfo.src_port = src_port;
  nfo.dst_port = dst_port;
  ipaddr2str(nfo.src_addr_s, src_ip, ipv6);
  ipaddr2str(nfo.dst_addr_s, dst_ip, ipv6);
  /* find counterpart from other direction, if already in the buffer */
  pair_idx = find_packet(&nfo);
  /* insert into db */  
  int i = 0;
  if (pair_idx != -1) {
    sql_rc(sqlite3_bind_int64(ins_exe, ++i, pkt_buf[pair_idx].db_id));
  }
  else {
    sql_rc(sqlite3_bind_null(ins_exe, ++i));
  }
  /* INSERT packet */
  /* IP src/dst */
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, ipv6));
  sql_rc(sqlite3_bind_text (ins_exe, ++i, nfo.src_addr_s, -1, SQLITE_STATIC));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, src_port));
  sql_rc(sqlite3_bind_text (ins_exe, ++i, nfo.dst_addr_s, -1, SQLITE_STATIC));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, dst_port));
  /* our (pcap) timestamp */
  sql_rc(sqlite3_bind_int64(ins_exe, ++i, tstamp->tv_sec));
  sql_rc(sqlite3_bind_int64(ins_exe, ++i, tstamp->tv_usec /*act.nsec*/));
  /* NTP payload */
  uint8_t
    li = ntp->li_vn_mode >> 6,
    vn = (ntp->li_vn_mode >> 3) & 0x7,
    mode = (ntp->li_vn_mode >> 0) & 0x7;
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, li));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, vn));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, mode));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, ntp->poll));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, ntp->precision));
  sql_rc(sqlite3_bind_int64(ins_exe, ++i, ntp->root_delay));
  sql_rc(sqlite3_bind_int64(ins_exe, ++i, ntp->root_disp));
  sql_rc(sqlite3_bind_int64(ins_exe, ++i, ntp->ref_id));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, hi32(ntp->ref_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, lo32(ntp->ref_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, hi32(ntp->org_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, lo32(ntp->org_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, hi32(ntp->rec_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, lo32(ntp->rec_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, hi32(ntp->xmt_tstamp)));
  sql_rc(sqlite3_bind_int  (ins_exe, ++i, lo32(ntp->xmt_tstamp)));
  /* go fight for a lock! */
  while (sql_rc(sqlite3_step(ins_exe)) == SQLITE_BUSY) {
    fprintf(stderr, "db busy: wait & retry\n");
    usleep(1000);
  }
  nfo.db_id = sqlite3_last_insert_rowid(db);
  sql_rc(sqlite3_reset(ins_exe));
  /* if not paired, put into the buffer */
  if (pair_idx == -1) {
    put_packet(&nfo);
  }
}

void sql_init(char *db_fname) {
  const char
    ins_log_cmd[] =
    "INSERT INTO log VALUES (?,?,'clxync_obsv',?)",
    ins_ntp_tx_cmd[] =
    "INSERT INTO ntp_tx "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ins_ntp_rx_cmd[] =
    "INSERT INTO ntp_rx "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
  sql_rc(sqlite3_open(db_fname, &db));
  sql_rc(sqlite3_prepare(db, ins_log_cmd, -1, &ins_log_exe, NULL));
  sql_rc(sqlite3_prepare(db, ins_ntp_tx_cmd, -1, &ins_ntp_tx_exe, NULL));
  sql_rc(sqlite3_prepare(db, ins_ntp_rx_cmd, -1, &ins_ntp_rx_exe, NULL));
}

void sql_close() {
  sql_rc(sqlite3_finalize(ins_log_exe));
  sql_rc(sqlite3_finalize(ins_ntp_tx_exe));
  sql_rc(sqlite3_finalize(ins_ntp_rx_exe));
  sql_rc(sqlite3_close(db));
}

#endif /*SQL*/
