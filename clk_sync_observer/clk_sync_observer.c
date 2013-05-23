/**
 * capture NTP packets and extract contained timestamps
 * Author: Jan Pacner xpacne00@stud.fit.vutbr.cz
 * Date: 2013-05-23 14:48:07 CEST
 * License:
 *   "THE BEER-WARE LICENSE" (Revision 42):
 *   Jan Pacner wrote this file. As long as you retain this notice you
 *   can do whatever you want with this stuff. If we meet some day and
 *   you think this stuff is worth it, you can buy me a beer in return.
 */

// useful links
//   fxr.watson.org
// not implemented
//   support for any L3+ tunneling (including IPSec etc.)
//   support for fragmented packets (neither IPv4 nor IPv6)
//   NTP control digests checking
//   NTP message authentication code support
//   NTP port choice

#include <stdint.h>  // HACK for pcap missing u_* types (needed under Linux)
#define __USE_BSD    // ...see the preceeding line
#include <pcap/pcap.h>

#include <stdint.h>  // u_* types
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>  // open()
#include <fcntl.h>  // open()
#include <errno.h>
#include <netinet/in.h>  // in_addr in6_addr
#include <signal.h>  // sigaction()
#include <getopt.h>
#include <string.h>  // strerror()

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

#define IP_VERSION_4 4  /* content of the version field in IP header */
#define IP_VERSION_6 6  /* - || - */

/* ethernet frame */
typedef struct {
  /* preamble and frame delimiter are not part of pcap frame */
  uint8_t mac_addr_dst[6];
  uint8_t mac_addr_src[6];
  /* 802.1Q tag is removed by libpcap */
  uint16_t len_or_ethertype;  /* <1500 payload len
                                 >=1536 EtherType values
                                 rest is undefined */
  /* checksum is removed by libpcap */
} eth_hdr_t;

/* IPv4 header (according to RFC 791), partially adopted from tutorial
   http://www.tcpdump.org/pcap.html and
   http://systhread.net/texts/200805lpcap1.php) */
typedef struct {
  uint8_t        ver_hdrlen;      /* 4b version; 4b header length (in multiples of 4B) */
    #define IPv4_version(x) ((x) >> 4)  /* should be IPPROTO_IP */
    #define IPv4_hdrlen(x) (((x) & 0x0f) * 4)
  uint8_t        dscp;            /* differentiated services code point */
  uint16_t       totallen;        /* len of fragment (header + data) in bytes */
  uint16_t       id;              /* identification */
  uint16_t       flags_foff;      /* flags & fragment offset field */
    #define IPv4_DF       0x4000  /* dont fragment flag */
    #define IPv4_FOF_MASK 0x1fff  /* mask for fragmenting bits */
  uint8_t        ttl;
  uint8_t        proto;           /* protocol
                                     IPPROTO_IP (could be more than once,
                                       but we do not support IP in IP)
                                     IPPROTO_TCP
                                     IPPROTO_UDP */
  uint16_t       checksum;
  struct in_addr src;
  struct in_addr dst;
} ipv4_hdr_t;

/* IPv6 header (according to RFC 2460) */
typedef struct {
  uint32_t ver_class_label;  /* 4b version; 8b traffic class; 20b flow label */
    #define IPv6_version(x) ((x) >> (8 + 20))  /* should be IPPROTO_IPV6 */
  uint16_t payloadlen;  /* len of the data after current header in bytes */
  uint8_t nexthdr;  /* same as IPv4 protocol field
                       netinet/in.h:
                         IPPROTO_NONE no next header
                         IPPROTO_IPV6 ipv6 header (can be more than once)
                         IPPROTO_FRAGMENT */
  uint8_t hoplimit;
  struct in6_addr src;
  struct in6_addr dst;
} ipv6_hdr_t;

/* UDP header (according to RFC 768) */
typedef struct {
  uint16_t src;  /* port */
  uint16_t dst;  /* port */
  uint16_t len;  /* len of (header + data) in bytes */
  uint16_t checksum;
} udp_hdr_t;

struct global_vars_s {
  pcap_t *pcap_handle;
} global_vars;

struct args_s {
  char *d;  // eth device
  FILE *o;  // output
} args;

void process_payload(struct args_s *args, const uint8_t *data,
    const uint32_t len) {
  data = data;
  fprintf(args->o, "_______%d\n", len);//FIXME
  fflush(args->o);
}

#define CHECK_PACKET_LEN \
  do { if (packet > _packet + header->caplen) return; } while (0)

/** remove packet headers (assume only IP) */
void handle_packet(uint8_t *args, const struct pcap_pkthdr *header,
    const uint8_t *_packet) {
  uint8_t *packet = (uint8_t *)_packet;
  /* jump over the ethernet header */
  packet += sizeof(eth_hdr_t);
  CHECK_PACKET_LEN;

  /* jump over the IP header(s) */
  switch (IPv4_version(((ipv4_hdr_t *)packet)->ver_hdrlen)) {
    case IP_VERSION_4:
      /* do not support fragmented packets (but if fragmented, take the
         first fragment and assume, the message is not damaged) */
      if (! (IPv4_DF || (! (IPv4_FOF_MASK &
                ntohs(((ipv4_hdr_t *)packet)->flags_foff)) )) )
        return;

      /* NTP works only using UDP */
      if (((ipv4_hdr_t *)packet)->proto != IPPROTO_UDP) return;

      packet += IPv4_hdrlen(((ipv4_hdr_t *)packet)->ver_hdrlen);
      CHECK_PACKET_LEN;
      break;
    case IP_VERSION_6:
      /* jump over all chained IPv6 headers */
      while (((ipv6_hdr_t *)packet)->nexthdr == IPPROTO_IPV6) {
        packet += sizeof(ipv6_hdr_t);
        CHECK_PACKET_LEN;
      }

      if (((ipv6_hdr_t *)packet)->nexthdr != IPPROTO_UDP) return;

      packet += sizeof(ipv6_hdr_t);
      CHECK_PACKET_LEN;
      break;
    default:
      return;
  }

  packet += sizeof(udp_hdr_t);  /* jump over the UDP header */
  CHECK_PACKET_LEN;
  process_payload((struct args_s *)args, packet, header->caplen - (packet - _packet));
}

int start_capture(struct args_s *args) {
  char errbuf[PCAP_ERRBUF_SIZE];
  errbuf[0] = '\0';

  /* 1 ~ promisc */
  if ((global_vars.pcap_handle = pcap_open_live(args->d, RING_BUF_SIZE, 1,
          READ_TIMEOUT, errbuf)) == NULL) {
    fprintf(stderr, "ERR: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  struct bpf_program filter;

  /* IPv4, IPv6, UDP, port 123
     http://ethereal.cs.pu.edu.tw/lists/ethereal-users/200208/msg00039.html */
  if (pcap_compile(global_vars.pcap_handle, &filter,
        "udp && (port 123)", 1, PCAP_NETMASK_UNKNOWN)) {
    fprintf(stderr, "ERR: %s \"%s\"\n",
        pcap_geterr(global_vars.pcap_handle), args->d);
    return EXIT_FAILURE;
  }

  /* man pcap-filter */
  if (pcap_setfilter(global_vars.pcap_handle, &filter)) {
    fprintf(stderr, "ERR: %s \"%s\"\n",
        pcap_geterr(global_vars.pcap_handle), args->d);
    return EXIT_FAILURE;
  }

  int ret = pcap_loop(global_vars.pcap_handle, -1, handle_packet, (void *)args);
  pcap_close(global_vars.pcap_handle);

  if (ret == -1) {
    fprintf(stderr, "ERR: %s \"%s\"\n",
        pcap_geterr(global_vars.pcap_handle), args->d);
    return EXIT_FAILURE;
  }
  else {
    return EXIT_SUCCESS;
  }
}

/* sigaction handler */
void my_sa_handler(int x) {
  x = x;
  pcap_breakloop(global_vars.pcap_handle);
}

int main(int argc, char *argv[]) {
  global_vars.pcap_handle = NULL;

  sigset_t sigblock;
  sigfillset(&sigblock);
  struct sigaction signew = {
    .sa_handler    = my_sa_handler,
    //.sa_sigaction  = NULL,  /* may overlap with sa_handler => do not use both */
    .sa_mask       = sigblock,
    .sa_flags      = 0,
  };

  sigaction(SIGTERM, &signew, NULL);  /* termination */
  sigaction(SIGHUP,  &signew, NULL);  /* hangup */
  sigaction(SIGINT,  &signew, NULL);  /* interrupt */

  args.d = NULL;
  args.o = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "+hd:o:")) != -1) {
    switch (opt) {
      case 'h':
        printf("USAGE: %s [-h] [-d <eth_device>] [-o <output_file>]\n"
            "  -d ethernet device to watch on\n"
            "    if none given, watch on all available devices\n"
            "  -o output file\n"
            "    if none given, use stdout\n", argv[0]);
        return EXIT_SUCCESS;
      case 'd':
        if (args.d == NULL)
          args.d = argv[optind -1];
        else
          fprintf(stderr, "ERR: Argument -%c can be given only once!", (char)opt);
        break;
      case 'o':
        if (args.o == NULL) {
          int fildes;
          if (
              // obtain file descriptor
              ((fildes = open(argv[optind -1], O_WRONLY | O_CREAT | O_EXCL,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1)
              ||
              // use the obtained file descriptor
              ((args.o = fdopen(fildes, "w")) == NULL)
             ) {
            fprintf(stderr, "ERR: Cannot open \"%s\" (%s).\n",
                argv[optind -1], strerror(errno));
            return EXIT_FAILURE;
          }
        }
        else {
          fprintf(stderr, "ERR: Argument -%c can be given only once!", (char)opt);
        }
        break;
      default:
        break;
    }
  }

  /* optind points to next argument (after the current one) in argv */
  if (optind != argc) {
    fprintf(stderr, "Unknown argument \"%s\".\n", argv[optind]);
    return EXIT_FAILURE;
  }

  if (args.d == NULL) {
    printf("WARN: On some platforms (e.g. Linux) the pcap device \"any\" produces\n"
           "  malformed packets. See -h for choosing a particular device.\n");
    args.d = "any";
  }
  if (args.o == NULL) args.o = stdout;

  printf("Press Ctrl+C for exit.\n");
  int ret = start_capture(&args);
  fclose(args.o);

  return ret;
}
