// SPDX-License-Identifier: Unlicense
//
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>

#include "log.h"
#include "print_icmp.h"
#include "print_ip.h"
#include "util.h"

#define BANNER(title) printf("\n======== %s ========\n", title)

void
print_icmp_hdr(struct icmphdr *icmp)
{
  BANNER("ICMP HEADER");
  printf("type=%d\n", icmp->type);
  printf("code=%d\n", icmp->code);
  printf("csum=%x\n", ntohs(icmp->checksum));
}

int
parse_icmp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  struct icmphdr *icmp =
      (struct icmphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
  print_icmp_hdr(icmp);
  return 0;
}
