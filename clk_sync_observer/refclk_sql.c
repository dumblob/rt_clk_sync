#ifdef SQL

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <sqlite3.h>
#include "refclk.h"

static sqlite3 *db;
static sqlite3_stmt *ins_log_exe, *ins_os_clk_exe, *ins_ref_clk_exe;

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

void sql_output_os_clk(uint32_t *ts_sec, uint32_t *ts_tick,
		       struct timespec *t_raw, struct timespec *t_adj) {
  /* table os_clk (
     cnt_sec0 integer,
     cnt_tick0 integer, cnt_tick1 integer, cnt_tick2 integer, cnt_tick3 integer,
     raw_sec0 integer, raw_nsec1 integer, raw_nsec2 integer, raw_nsec3 integer,
     adj_sec0 integer, adj_nsec1 integer, adj_nsec2 integer, adj_nsec3 integer)
  */
  int i = 0;
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, ts_sec[0]));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, ts_tick[0]));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, ts_tick[1]));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, ts_tick[2]));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, ts_tick[3]));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_raw[0].tv_sec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_raw[0].tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_raw[1].tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_raw[2].tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_adj[0].tv_sec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_adj[0].tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_adj[1].tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_os_clk_exe, ++i, t_adj[2].tv_nsec));
  while (sql_rc(sqlite3_step(ins_os_clk_exe)) == SQLITE_BUSY) {
    fprintf(stderr, "db busy: wait & retry\n");
    usleep(1000);
  }
  sql_rc(sqlite3_reset(ins_os_clk_exe));
}

void sql_output_ref_clk(uint32_t sec, uint32_t tick) {
  /* table ref_clk (
     raw_sec integer, raw_nsec integer,
     cnt_sec integer, cnt_tick integer)
  */
  int i = 0;
  /* get approximate raw clk time to be used in indexing */
  struct timespec ts;
  clock_gettime(CLK_RAW, &ts);
  sql_rc(sqlite3_bind_int64(ins_ref_clk_exe, ++i, ts.tv_sec));
  sql_rc(sqlite3_bind_int64(ins_ref_clk_exe, ++i, ts.tv_nsec));
  sql_rc(sqlite3_bind_int64(ins_ref_clk_exe, ++i, sec));
  sql_rc(sqlite3_bind_int64(ins_ref_clk_exe, ++i, tick));
  while (sql_rc(sqlite3_step(ins_ref_clk_exe)) == SQLITE_BUSY) {
    fprintf(stderr, "db busy: wait & retry\n");
    usleep(1000);
  }
  sql_rc(sqlite3_reset(ins_ref_clk_exe));
}

void sql_init(char *db_fname) {
  const char
    ins_log_cmd[] =
    "INSERT INTO log VALUES (?,?,'refclk',?)",
    ins_os_clk_cmd[] =
    "INSERT INTO os_clk VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ins_ref_clk_cmd[] =
    "INSERT INTO ref_clk VALUES (?,?,?,?)";
  sql_rc(sqlite3_open(db_fname, &db));
  sql_rc(sqlite3_prepare(db, ins_log_cmd, -1, &ins_log_exe, NULL));
  sql_rc(sqlite3_prepare(db, ins_os_clk_cmd, -1, &ins_os_clk_exe, NULL));
  sql_rc(sqlite3_prepare(db, ins_ref_clk_cmd, -1, &ins_ref_clk_exe, NULL));
}

void sql_close() {
  sql_rc(sqlite3_finalize(ins_log_exe));
  sql_rc(sqlite3_finalize(ins_os_clk_exe));
  sql_rc(sqlite3_finalize(ins_ref_clk_exe));
  sql_rc(sqlite3_close(db));
}

#endif /*SQL*/
