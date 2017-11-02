/*
 * truncap - a packet capture tool for obtaining only TCP/IP headers (no data payload)
 *
 * tcpdump can capture with a limited snap size but dumps may contain fragments of data
 * which can be problematic for some use cases. truncap fills this gap in functionality
 * by analyzing the traffic and capturing only the variable size headers, leaving the
 * rest of the payload unsaved.
 *
 * truncap will rewrite the packet checksums in order for the new payload-free packet
 * to pass validation, however all other important header fields are left untouched
 * and contain the original information obtained in the capture. the checksum update
 * silences some tools that complain about potentially "damaged" captures with partial
 * payloads.
 *
 *              copyright 2017 Seamus Caveney <scv@brinstar.org>
 *              all rights reserved. license: BSD 2-clause
 *
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#include <sys/time.h>

#define ETH_LEN 14
#define CAP_LEN 96
#define STR_LEN 256
#define HDR_BUF_LEN 1536

/* used for tcp header calculation */
struct ip_pseudo {
  struct in_addr src;
  struct in_addr dst;
  u_char pad;
  u_char proto;
  u_short len;
};

u_char *hdr_buf = NULL;
int hdr_capsz = 0, hdr_rotsz = 20971520;
pcap_dumper_t *hdr_dump = NULL;
char hdr_dump_filename[STR_LEN], target_addr[STR_LEN], target_intf[STR_LEN];

/* tcp/ip checksum, ripped from somewhere on the net */
unsigned short cksum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;

  while (nbytes > 1) {
    sum    += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *) ptr;
    sum += oddbyte;
  }

  sum    = (sum >> 16) + (sum & 0xffff);
  sum    = sum + (sum >> 16);
  answer = (short) ~sum;

  return(answer);
}

void hdr_dump_open() {
  pcap_t *dump_cap;
  struct timeval ctime;
  struct timezone tz;

  gettimeofday(&ctime, &tz);
  sprintf(hdr_dump_filename, "truncap-%s-%ld.cap", target_addr, ctime.tv_sec);

  /* explicitly select DLT_EN10MB instead of RAW to write out ethernet frame */
  dump_cap = pcap_open_dead(DLT_EN10MB, CAP_LEN);

  if ((hdr_dump = pcap_dump_open(dump_cap, hdr_dump_filename)) == NULL) {
    printf("pcap_dump_open(..., %s): %s\n", hdr_dump_filename, pcap_geterr(dump_cap));
    exit(1);
  }
}

void hdr_dump_close(void) {
  pcap_dump_close(hdr_dump);
}

void capture(u_char *user, struct pcap_pkthdr *header, u_char *payload) {
  struct ip *header_ip;
  struct ip_pseudo ipps;
  struct tcphdr *header_tcp;
  struct udphdr *header_udp;
  struct icmp *header_icmp;
  size_t buf_len, header_ip_len, header_ip_payload_len, header_tcp_pseudo_len;
  char header_tcp_pseudo[CAP_LEN]; /* likely smaller */

  /* clean up our stripped packet buffers */
  buf_len = 0;
  memset(hdr_buf, 0, HDR_BUF_LEN);

  /* copy fixed-size ethernet frame to output buf */
  memcpy(hdr_buf, payload, ETH_LEN);
  buf_len += ETH_LEN;

  /* skip ethernet frame and extract ip header */
  payload      += ETH_LEN;
  header_ip     = (struct ip *) payload;
  header_ip_len = header_ip->ip_hl * 4;
  payload      += header_ip_len;

  /* determine ip payload type */
  switch(header_ip->ip_p) {
    case IPPROTO_TCP:
      header_tcp         = (struct tcphdr *) payload;
      header_tcp->th_sum = 0; /* calculated later */

      /* payload is at least 20 bytes */
      header_ip_payload_len     = sizeof(struct tcphdr);
      if (header_tcp->doff > 5) /* doff=size in words, more than 20b indicates options are present */
        header_ip_payload_len  += (header_tcp->doff - 5) * 4;
    break;

    case IPPROTO_UDP:
      header_udp            = (struct udphdr *) payload;
      header_udp->uh_ulen   = htons(sizeof(struct udphdr));
      header_udp->uh_sum    = 0;
      header_udp->uh_sum    = cksum((unsigned short *) header_udp, header_udp->uh_ulen);
      header_ip_payload_len = 8;
    break;

    case IPPROTO_ICMP:
      header_icmp             = (struct icmp *) payload;
      header_icmp->icmp_cksum = 0;
      header_icmp->icmp_cksum = cksum((unsigned short *) header_icmp, 8);
      header_ip_payload_len   = 8; /* we can safely ignore icmp options */
    break;

    default:
      printf("capture(...): bad ip payload %d\n", header_ip->ip_p);
      return;
  }

  /* update ip header with new length and cksum */
  header_ip->ip_len = htons(sizeof(struct ip) + header_ip_payload_len);
  header_ip->ip_sum = 0;
  header_ip->ip_sum = cksum((unsigned short *) header_ip, sizeof(struct ip));

  /* copy ip header into output buf */
  memcpy(hdr_buf + buf_len, header_ip, sizeof(struct ip));
  buf_len += header_ip_len;

  /* if payload is tcp update cksum and pack header */
  if (header_ip->ip_p == IPPROTO_TCP) {
    ipps.src           = header_ip->ip_src;
    ipps.dst           = header_ip->ip_dst;
    ipps.pad           = 0;
    ipps.proto         = IPPROTO_TCP;
    ipps.len           = htons(header_ip_payload_len);

    /* checksum contains full pseudo ip header + full real tcp header and options */
    header_tcp_pseudo_len = sizeof(struct ip_pseudo) + header_ip_payload_len;

    memcpy(header_tcp_pseudo, &ipps, sizeof(struct ip_pseudo));
    memcpy(header_tcp_pseudo + sizeof(struct ip_pseudo), payload, header_ip_payload_len);

    /* update checksum to match empty segment */
    header_tcp->th_sum = cksum((unsigned short *) header_tcp_pseudo, header_tcp_pseudo_len);
  }

  /* copy ip payload into output buf */
  memcpy(hdr_buf + buf_len, payload, header_ip_payload_len);
  buf_len += header_ip_payload_len;

  /* add size of payload-free frame to total size */
  hdr_capsz += buf_len;

  /* fix up pcap headers with new truncated length */
  header->len    = buf_len;
  header->caplen = buf_len;

  /* write the frame to disk */
  pcap_dump((u_char *)hdr_dump, header, hdr_buf);

  /* rotate the cap file if it grows past the dump size */
  if (hdr_capsz > hdr_rotsz) {
    printf("capture(...): cycling capture file\n");
    hdr_dump_close();
    hdr_dump_open();

    hdr_capsz = 0;
  }
}

/* ensure the capture is flushed before exiting */
void sig_handler(int signum) {
  hdr_dump_close();
  exit(0);
}

int main(int argc, char *argv[]) {
  int getopt_ret;
  char err[PCAP_ERRBUF_SIZE], filter_def[STR_LEN];
  struct bpf_program filter;
  pcap_t *cap;

  while ((getopt_ret = getopt(argc, argv, "ht:s:i:")) != -1) {
    switch (getopt_ret) {
      case 'h':
        printf("truncap options: truncap [-h] [-s rotatesize MB] -t ipaddress -i interface\n");
        exit(0);
      break;

      case 's':
        printf("truncap: rotating capture files at %d MB\n", atoi(optarg));
        hdr_rotsz = atoi(optarg) * 1048576;
      break;

      case 't':
        snprintf(target_addr, STR_LEN - 1, "%s", optarg);
      break;

      case 'i':
        snprintf(target_intf, STR_LEN - 1, "%s", optarg);
      break;

      case ':':
      case '?':
    printf("optopt=%c\n", optopt);
        switch (optopt) {
          case 't':
            printf("truncap: option -t <ipaddress> is mandatory\n");
            exit(1);
          break;

          case 'i':
            printf("truncap: option -i <interface> is mandatory\n");
            exit(1);
          break;

          case 's':
            printf("truncap: option -s <rotatesize MB> requires an argument\n");
            exit(1);
          break;
        }
    }
  }

  if (! target_addr[0] || ! target_intf[0]) {
    printf("truncap options: truncap [-h] [-s rotatesize MB] -t ipaddress -i interface\n");
    printf("both the -t and -i options are mandatory\n");
    exit(1);
  }

  if ((hdr_buf = malloc(HDR_BUF_LEN)) == NULL) {
    printf("failed to alloc hdr_buf\n");
    exit(1);
  }

  memset(filter_def, 0, sizeof(filter_def));
  snprintf(filter_def, STR_LEN - 1, "(tcp or udp or icmp) and host %s", target_addr);


  if ((cap = pcap_open_live(target_intf, CAP_LEN, 1, 1000, err)) == NULL) {
    printf("pcap_open_live(%s, ...): %s\n", target_intf, err);
    exit(1);
  }

  if (pcap_compile(cap, &filter, filter_def, 0, 0) == -1) {
    printf("pcap_compile(...): failed\n");
    exit(1);
  }

  signal(SIGINT, sig_handler);
  pcap_setfilter(cap, &filter);
  hdr_dump_open();

  if (pcap_loop(cap, -1, (pcap_handler)capture, NULL) < 0) {
    printf("pcap_loop(...): %s\n", pcap_geterr(cap));
    exit(1);
  }

  exit(0);
}

