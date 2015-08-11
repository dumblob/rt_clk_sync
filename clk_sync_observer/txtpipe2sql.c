#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>

#include <sqlite3.h>

#define CLK_ID CLOCK_MONOTONIC_RAW
#define MAX_STR_LEN 1023

typedef struct record_t {
  struct timespec tstamp;
  char *head, *tail;
} record_t;

static sqlite3 *db;
static int max_head_len = 16;
static char *tail_separators = " \f\n\r\t\v";

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

int get_data(record_t *rec) {
  static char s[MAX_STR_LEN+1], head[MAX_STR_LEN+1];
  int i;
  if (fgets(s, sizeof(s), stdin) == NULL)
    return -1;
  clock_gettime(CLK_ID, &rec->tstamp);
  /* remove trailing newline */
  i = strlen(s);
  s[i-1] = '\0';
  /* split log msg into indexing head and the rest of msg */
  for (i = 0; s[i] && (i < max_head_len); i++) {
    if (strchr(tail_separators, s[i]))
      break;
    head[i] = s[i];
  }
  head[i] = '\0';  
  rec->head = head;
  rec->tail = s + i;
  return 0;
}

void usage(char *self_name) {
  printf(
"txtpipe2sql -- redirects plain text stdin into timestamped SQLite table\n"
"usage: %s [-t table_name] [-m max_head_chars] [-d head_delim] sqlite_db_file\n"
" -t        table name, default: \"log\"\n"
" -m        maximum number of characters going into \"head\" field\n"
" -d        possible delimiter chars between \"head\" and \"tail\"\n\n",
    self_name);
}

int main(int argc, char *argv[]) {
  const char insert_cmd_proto[] =
    "INSERT INTO %s VALUES (?,?,?,?)";
  char *insert_cmd;
  sqlite3_stmt *insert_exe;
  record_t rec;
  char *db_fname = NULL, *table_name = "log";

  //-t tab_name -m max_head_chars -d head_delimiters db_name
  int opt, n;
  optind = opterr = 0;
  while ((opt = getopt(argc, argv, ":ht:m:d:")) != -1)
    switch (opt) {
    case 'h':
      usage(argv[0]);
      return 0;
      break;
    case 't':
      table_name = optarg;
      break;
    case 'm':
      n = atoi(optarg);
      if (n < 1) {
	fprintf(stderr, "WARN: invalid max_head_chars=%d, leaving default %d\n",
		n, max_head_len);
      }
      else if (n > MAX_STR_LEN) {
	max_head_len = MAX_STR_LEN;
	fprintf(stderr, "WARN: max_head_chars too large, setting to %d\n",
		max_head_len);
      }
      else {
	max_head_len = n;
      }
      break;
    case 'd':
      tail_separators = optarg;
      break;
    case ':':
      fprintf(stderr, "command line option -%c requires an argument\n"
              "use -h for help\n",
              optopt);
      return -1;
      break;
    case '?':
      fprintf(stderr, "unrecognized command line option -%c\n"
              "use -h for help\n",
              optopt);
      return -1;
      break;
    default:
      break;
    }
  if (optind < argc) {
    if (optind > argc) {
      fprintf(stderr, "more than one non-option argument: %s...\n"
              "use -h for help\n",            
              argv[optind+1]);
      return -1;
    }
    db_fname = argv[optind];
  }
  else {
    fprintf(stderr, "database file name must be given\n"
	    "use -h for help\n");
    return -1;
  }

  insert_cmd = (char*)malloc(1 + strlen(insert_cmd_proto) + strlen(table_name));
  if (!insert_cmd) {
    fprintf(stderr, "fatal: can not malloc\n");
    return -1;
  }
  sprintf(insert_cmd, insert_cmd_proto, table_name);
  
  sql_rc(sqlite3_open(db_fname, &db));
  sql_rc(sqlite3_prepare(db, insert_cmd, -1, &insert_exe, NULL));
  for (;;) {
    if (get_data(&rec))
      break;
    sql_rc(sqlite3_bind_int64(insert_exe, 1, rec.tstamp.tv_sec));
    sql_rc(sqlite3_bind_int64(insert_exe, 2, rec.tstamp.tv_nsec));
    sql_rc(sqlite3_bind_text(insert_exe,  3, rec.head, -1, SQLITE_STATIC));
    sql_rc(sqlite3_bind_text(insert_exe,  4, rec.tail, -1, SQLITE_STATIC));
    while (sql_rc(sqlite3_step(insert_exe)) == SQLITE_BUSY) {
      fprintf(stderr, "db busy: wait & retry\n");
      usleep(1000);
    }
    sql_rc(sqlite3_reset(insert_exe));
  }
  sql_rc(sqlite3_finalize(insert_exe));
  sql_rc(sqlite3_close(db));
  return 0;
}
