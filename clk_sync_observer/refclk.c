#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "refclk.h"

uint32_t *mm_ctrl, *tmem_cpu, *tmem_refclk;

#define TSTAMP_CTRL_ADDR 0x43c00000
#define TSTAMP_CTRL_LEN       (4*4)
#define TSTAMP_MEM0_ADDR 0x40000000
#define TSTAMP_MEM1_ADDR 0x40010000
#define TSTAMP_MEM_LEN   (256)
#define TSTAMP_MEM_BLEN  (8*TSTAMP_MEM_LEN)

#define F_CCLK     200000000 /*Hz*/
#define TTAG_MASK 0xff000000

#define __mb() \
 __asm__ __volatile__("dmb": : : "memory")

#define __mb_smp() \
 __asm__ __volatile__("dmb ish": : : "memory")

static char *memdev = "/dev/mem";
static int mem_fd = -1;

static int mem_open() {
  mem_fd = open(memdev, O_RDWR|O_SYNC);
  if (mem_fd < 0) {
    perror("open memory device");
    return -1;
  }
  return 0;
}

void *mem_map(unsigned long mem_start, unsigned long mem_length) {
  unsigned long pagesize, mem_window_size;
  void *mm, *mem;
  //pagesize = getpagesize();
  pagesize = sysconf(_SC_PAGESIZE);

  mem_window_size =
    ((mem_start & (pagesize-1)) + mem_length + pagesize-1) & ~(pagesize-1);
  mm = mmap(NULL, mem_window_size, PROT_WRITE|PROT_READ,
            MAP_SHARED, mem_fd, mem_start & ~(pagesize-1));
  mem = mm + (mem_start & (pagesize-1));
  if (mm == MAP_FAILED) {
    perror("mmap");
    return NULL;
  }
  fprintf(stderr, "mmap 0x%lx -> %p\n", mem_start, mem);
  return mem;
}

static inline void tstamp_cpu(uint32_t tag) {
  mm_ctrl[0] = tag;
  __mb();
}

static inline uint32_t tstamp_read(uint32_t *tmem, int offset, uint32_t *tag) {
  unsigned idx = offset & (TSTAMP_MEM_LEN-1); /* len must be 2^n */
  /* 1 record = 2 32-bit words */
  idx <<= 1;
  if (tag)
    *tag = tmem[idx+1];
  return tmem[idx+0];
}

static inline int tstamp_next_idx(int idx) {
  ++idx;
  idx &= TSTAMP_MEM_LEN-1;
  return idx;
}

int tstamp_init() {
  mem_open();
  uint32_t *mm_sysctl = mem_map(0xf8000000, 0xb78);
  /* override FCLK1 freq. to periph clk (1GHz) / 5 = 200MHz */
  mm_sysctl[0x180/4] = 0x00100500;
  munmap(mm_sysctl, 0xb78);
  /* map timestamp ring-buffers */
  tmem_cpu = mem_map(TSTAMP_MEM0_ADDR, TSTAMP_MEM_LEN);
  tmem_refclk = mem_map(TSTAMP_MEM1_ADDR, TSTAMP_MEM_LEN);
  /* set up timestamping */
  mm_ctrl = mem_map(TSTAMP_CTRL_ADDR, TSTAMP_CTRL_LEN);
  mm_ctrl[2] = F_CCLK-1;
  mm_ctrl[1] = TTAG_MASK;
  return 0;
}

void tstamp_close() {
  munmap(mm_ctrl, TSTAMP_CTRL_LEN);
  munmap(tmem_cpu, TSTAMP_MEM_LEN);
  munmap(tmem_refclk, TSTAMP_MEM_LEN);
}

/* * */

uint32_t old_sec[TSTAMP_MEM_LEN];

void ref_pps_init() {
  int i;
  for (i = 0; i < TSTAMP_MEM_LEN; i++)
    tstamp_read(tmem_refclk, i, old_sec + i);
}

int ref_pps_detect() {
  uint32_t sec;
  int i;
  for (i = 0; i < TSTAMP_MEM_LEN; i++) {
    tstamp_read(tmem_refclk, i, &sec);
    if (sec != old_sec[i])
      return i;
  }
  return -1;
}

int ref_pps_get(int *idx, uint32_t *sec, uint32_t *tick) {
  *tick = tstamp_read(tmem_refclk, *idx, sec);
  if (*sec != old_sec[*idx]) {
    old_sec[*idx] = *sec;
    *idx = tstamp_next_idx(*idx);
    return 1;
  }
  return 0;
}

void output_os_clk(uint32_t *ts_sec, uint32_t *ts_tick,
		   struct timespec *t_raw, struct timespec *t_adj) {
  printf("C(0)=%u.%09u C(1)=%u.%09u C(2)=%u.%09u C(3)=%u.%09u\n"
	 "R(0)=%lu.%09lu R(1)=%lu.%09lu R(2)=%lu.%09lu\n"
	 "A(0)=%lu.%09lu A(1)=%lu.%09lu A(2)=%lu.%09lu\n\n",
	 ts_sec[0],ts_tick[0], ts_sec[1],ts_tick[1],
	 ts_sec[2],ts_tick[2], ts_sec[3],ts_tick[3],
	 t_raw[0].tv_sec, t_raw[0].tv_nsec,
	 t_raw[1].tv_sec, t_raw[1].tv_nsec,
	 t_raw[2].tv_sec, t_raw[2].tv_nsec,
	 t_adj[0].tv_sec, t_adj[0].tv_nsec,
	 t_adj[1].tv_sec, t_adj[1].tv_nsec,
	 t_adj[2].tv_sec, t_adj[2].tv_nsec);
}

void output_ref_clk(uint32_t sec, uint32_t tick) {
  printf("ext1pps C=%u.%09u\n", sec, tick);
}

int sample_os_clocks(int *ts_idx) {
  struct timespec t_raw[3], t_adj[3];
  uint32_t ts_sec[4], ts_tick[4];
  int i;
  /* sample clocks */
  tstamp_cpu(1U << 24);
  clock_gettime(CLK_RAW, t_raw + 0);
  clock_gettime(CLK_ADJ, t_adj + 0);
  tstamp_cpu(2U << 24);
  clock_gettime(CLK_RAW, t_raw + 1);
  clock_gettime(CLK_ADJ, t_adj + 1);
  tstamp_cpu(3U << 24);
  clock_gettime(CLK_RAW, t_raw + 2);
  clock_gettime(CLK_ADJ, t_adj + 2);
  tstamp_cpu(4U << 24);
  /* gather HW timestamps */
  __mb();
  for (i = 0; i < 4; i++) {
    ts_tick[i] = tstamp_read(tmem_cpu, *ts_idx, ts_sec + i);
    /* check tag */
    if ((ts_sec[i] & TTAG_MASK) != ((i+1) << 24)) {
      fprintf(stderr, "ERR: tstamp memory tag mismatch (expect:%x, read:%x)!\n",
	      ((i+1) << 24), ts_sec[i] & TTAG_MASK);
      return -1;
    }
    ts_sec[i] &= ~TTAG_MASK;
    *ts_idx = tstamp_next_idx(*ts_idx);
  }
  output_os_clk(ts_sec, ts_tick, t_raw, t_adj);
#ifdef SQL
  sql_output_os_clk(ts_sec, ts_tick, t_raw, t_adj);
#endif
  return 0;
}

int cpu_tstamp_init(int *idx) {
  uint32_t tag;
  int i;
  /* clear buffer */
  for (i = 0; i < TSTAMP_MEM_LEN; i++)
    tstamp_cpu(0);
  /* mark & find this last record */
  tstamp_cpu(1U << 24);
  for (i = 0; i < TSTAMP_MEM_LEN; i++) {
    tstamp_read(tmem_cpu, i, &tag);
    if (tag & TTAG_MASK) {
      *idx = tstamp_next_idx(i);
      return 0;
    }
  }
  fprintf(stderr, "ERR: unable to initialize cpu tstamp memory!\n");
  return -1;
}

void main_loop() {
  int cpu_idx, refclk_idx = -1;
  uint32_t sec, tick;
  struct timespec ts;
  /* init */
  if (cpu_tstamp_init(&cpu_idx))
    return;
  fprintf(stderr, "cpu timestamp pointer found @offset=%u\n", cpu_idx);
  __mb();
  ref_pps_init();
  /* loop */
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* take internal clocks measurement */
    sample_os_clocks(&cpu_idx);
    /* check ext 1pps */
    if (refclk_idx == -1) {
      /* 1pps not yet encountered */
      refclk_idx = ref_pps_detect();
      if (refclk_idx != -1) {
	fprintf(stderr, "1pps detected @offset=%d\n", refclk_idx);
      }
    }
    else {
      while (ref_pps_get(&refclk_idx, &sec, &tick)) {
	sec &= ~TTAG_MASK;
	output_ref_clk(sec, tick);
#ifdef SQL
	sql_output_ref_clk(sec, tick);
#endif
      }
    }
    /* wait for next sample */
    if ((ts.tv_nsec += PERIOD_NSEC) >= 1000000000) {
      ++ts.tv_sec;
      ts.tv_nsec -= 1000000000;
    }
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
  }
}

int main(int argc, char *argv[]) {
  fprintf(stderr, "init\n");
#ifdef SQL
  sql_init((argc == 2) ? argv[1] : DEFAULT_SQL_DB);
  sql_log("init");
#endif
  tstamp_init();
  main_loop();
  /* never shall get here: severe OS/HW error */
  fprintf(stderr, "fatal error: closing\n");
#ifdef SQL
  sql_close();
#endif
  tstamp_close();
  return -1;
}
