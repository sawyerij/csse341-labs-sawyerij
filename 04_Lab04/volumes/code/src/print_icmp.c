// SPDX-License-Identifier: Unlicense
//
#include <net/ethernet.h>
<<<<<<< HEAD
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
=======
#include <net/if_arp.h>
#include <netinet/ether.h>

#include "log.h"
#include "print_icmp.h"
#include "util.h"

int
parse_icmp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an ICMPP packet.
  //
>>>>>>> 9908967e2f56d6e9f06789abfc1c269e58a635bb
  return 0;
}
