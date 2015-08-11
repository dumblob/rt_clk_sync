create table log (
  t_sec integer, t_nsec integer, head varchar, tail varchar
);
create table gps_nmea (
  t_sec integer, t_nsec integer, head varchar, tail varchar
);
create table ntimed_trace (
  t_sec integer, t_nsec integer, head varchar, tail varchar
);

create table os_clk (
  cnt_sec0 integer,
  cnt_tick0 integer, cnt_tick1 integer, cnt_tick2 integer, cnt_tick3 integer,
  raw_sec1 integer, raw_nsec1 integer, raw_nsec2 integer, raw_nsec3 integer,
  adj_sec1 integer, adj_nsec1 integer, adj_nsec2 integer, adj_nsec3 integer  
);
create table ref_clk (
  raw_sec integer, raw_nsec integer,
  cnt_sec integer, cnt_tick integer
);

create table ntp_rx (
  ntp_tx_id integer,
  ipv6 boolean,
  src_addr varchar,
  src_port integer,
  dst_addr varchar,
  dst_port integer,
  raw_sec integer,
  raw_nsec intefer,
  pkt_tstamp_sec integer,
  pkt_tstamp_nsec integer,
  li integer,
  vn integer,
  mode integer,
  poll integer,
  prec integer,
  root_delay integer,
  root_disp integer,
  ref_id integer,
  ref_ts_hi integer,
  ref_ts_lo integer,
  org_ts_hi integer,
  org_ts_lo integer,
  rec_ts_hi integer,
  rec_ts_lo integer,
  xmt_ts_hi integer,
  xmt_ts_lo integer
);

create table ntp_tx (
  ntp_rx_id integer,
  ipv6 boolean,
  src_addr varchar,
  src_port integer,
  dst_addr varchar,
  dst_port integer,
  raw_sec integer,
  raw_nsec intefer,
  pkt_tstamp_sec integer,
  pkt_tstamp_nsec integer,
  li integer,
  vn integer,
  mode integer,
  poll integer,
  prec integer,
  root_delay integer,
  root_disp integer,
  ref_id integer,
  ref_ts_hi integer,
  ref_ts_lo integer,
  org_ts_hi integer,
  org_ts_lo integer,
  rec_ts_hi integer,
  rec_ts_lo integer,
  xmt_ts_hi integer,
  xmt_ts_lo integer
);

create index ix_log1 on log(t_sec,t_nsec);
create index ix_log2 on log(head,t_sec,t_nsec);

create index ix_gps_nmea1 on gps_nmea(t_sec,t_nsec);
create index ix_gps_nmea2 on gps_nmea(head,t_sec,t_nsec);

create index ix_ntimed1 on ntimed_trace(t_sec,t_nsec);
create index ix_ntimed2 on ntimed_trace(head,t_sec,t_nsec);

create index ix_ref_clk1 on ref_clk(raw_sec,raw_nsec);

create index ix_os_clk1 on os_clk(raw_sec1,raw_nsec1);

create index ix_ntp_rx1 on ntp_rx(raw_sec,raw_nsec);
create index ix_ntp_rx2 on ntp_rx(src_addr,raw_sec,raw_nsec);

create index ix_ntp_tx1 on ntp_rx(raw_sec,raw_nsec);
create index ix_ntp_tx2 on ntp_rx(dst_addr,raw_sec,raw_nsec);
