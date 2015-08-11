#define length(a) (sizeof(a)/sizeof((a)[0]))
#define __packed __attribute__((packed))

#define NTP_PORT 123

#define NTP_PACKET 							\
  uint8_t li_vn_mode;   /* 2b Leap Indicator, 3b Version Number, 3b Association Mode */\
  uint8_t stratum;\
  uint8_t poll;         /* msg interval in log2 sec */\
  uint8_t precision;    /* precision of the system clock in log2 sec */\
  uint32_t root_delay;  /* total round-trip delay to the ref clock */\
  uint32_t root_disp;   /* root dispersion (total disp. to the ref clk) */\
  uint32_t ref_id;      /* reference ID (usually ASCII printable) */\
  uint64_t ref_tstamp;  /* reference timestamp (time when sys clk was last set/corrected) */\
  uint64_t org_tstamp;  /* origin timestamp */\
  uint64_t rec_tstamp;  /* receive timestamp */\
  uint64_t xmt_tstamp;  /* transmit timestamp */

typedef struct {
  NTP_PACKET
} __packed ntp_pkt_pkd_t;

typedef struct {
  NTP_PACKET
} /* not packed */ ntp_pkt_t;

char *ipaddr2str(char *s, const uint8_t *addr, const bool is_ipv6);

#ifdef SQL
#ifndef DEFAULT_SQL_DB
#define DEFAULT_SQL_DB "/buben/cas/orloj.db"
#endif
#define LOG_CLK_ID CLOCK_MONOTONIC_RAW
void sql_log(char *msg);
void sql_output_ntp_packet(bool ipv6,
			   const uint8_t *src_ip, uint16_t src_port,
			   const uint8_t *dst_ip, uint16_t dst_port,
			   const struct timeval *tstamp, /* actually in nsec */
			   ntp_pkt_t *ntp);
void sql_init(char *db_fname);
void sql_close();
#endif
