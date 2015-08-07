compile (needs libpcap installed):

`gcc -o clk_sync_observer -pedantic -lpcap ./clk_sync_observer.c`

run:

`./clk_sync_observer`

_________________________________________________________________
Comments on timestamping, pcap, Linux & Zynq (Marek Peca, pecam1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- capture (pcap) chosen to compare our algs against ntp, ntimed,...; reason:
  do not require patching of other's SW
- suitable reference HW to compare with absolute time (Rb clock, GPS Rx): Zynq;
  reason: easy addition of simple timestamping HW counter, untouched by OS

Observations:

- Linux (3.14.2 for firsts tests) supports 2 APIs for net timestamping:
  a) ioctl SIOGCSTAMP(NS) (probably a legacy way)
  b) cmsg SCM_TIMESTAMP(NS)

- HW timestamps are theoretically supported; fortunately, a concept of
  disciplined NIC oscillator by NIC driver has been deprecated, and moved to
  userspace. Therefore, only host SW timestamps, or raw (non-disciplined)
  HW timestamps are supported, HW clock *shall* be exposed as a clock source,
  and this may be disciplined from userspace (the good side is, it need not);

  However:
-- whether there are NICs which support HW timestamping of generic UDP packet,
   is unknown to me; Zynq does not, its Gigabit Eth supports stamping of PTP
   stuff only; *and*, the NIC driver as of xlnx linux 4.1.x does some weird
   action to discipline NIC time (yes, silly control attempts...);

- libpcap (1.7.3) seems to use ioctl SIOCGSTAMP(NS) only, HW tstamps supported;

- both (a) ioctl & (b) cmsg resort to ktime_get_real() in case of SW timestamp;
  it seems it is not possible to choose other clock source in Linux:

  (a) inet_ioctl() calls:
  int sock_get_timestampns(...):
      (..)
      if (ts.tv_sec == 0) {
                 sk->sk_stamp = ktime_get_real();
                 ts = ktime_to_timespec(sk->sk_stamp);
      }

  (b) __sock_recv_timestamp() calls:
  static inline void __net_timestamp(struct sk_buff *skb)
  {
         skb->tstamp = ktime_get_real();
  }

- Ntimed (Aug 2015 development client) in contrary uses only SCM_* cmsg API;

- by an experiment, it has been confirmed, at least on reference Zynq, that
  nanosecond timestamps are equal among libpcap (using ioctl, SW tstamps), and
  Ntimed, using cmsgs

Experiment

./clk_sync_observer -d eth0 -t host
has been run on Zynq in parallel with Ntimed;
"host" timestamps select the only working stamping, i.e. SW.
(2015-08-07 pecam1)
