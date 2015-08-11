#define PERIOD_NSEC 62500000 /*16Hz*/

#define CLK_RAW CLOCK_MONOTONIC_RAW
#define CLK_ADJ CLOCK_REALTIME /* slower, more accurate */
//#define CLK_ADJ CLOCK_REALTIME_COARSE /* faster, less accurate */

#ifdef SQL
#ifndef DEFAULT_SQL_DB
#define DEFAULT_SQL_DB "/buben/cas/orloj.db"
#endif
#define LOG_CLK_ID CLK_RAW
void sql_log(char *msg);
void sql_output_os_clk(uint32_t *ts_sec, uint32_t *ts_tick,
		       struct timespec *t_raw, struct timespec *t_adj);
void sql_output_ref_clk(uint32_t sec, uint32_t tick);
void sql_init(char *db_fname);
void sql_close();  
#endif
