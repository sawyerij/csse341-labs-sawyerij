// SPDX-License-Identifier: Unlicense
//

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "log.h"
#include "print_icmp.h"
#include "print_ip.h"
#include "util.h"

<<<<<<< HEAD
#define BANNER(title) printf("\n======== %s ========\n", title)

void
print_ip_hdr(struct iphdr *ip)
{
  BANNER("IP HEADER");
  printf("version=%d\n", ip->version);
  printf("ihl=%d bytes\n", ip->ihl);
  printf("tos=%d\n", ip->tos);
  printf("total_length=%d\n", ntohs(ip->tot_len));
  printf("id=%d\n", ntohs(ip->id));
  printf("frag_offset=0x%x\n", ntohs(ip->frag_off));
  printf("ttl=%d\n", ip->ttl);
  printf("protocol=%d\n", ip->protocol);
  printf("checksum=0x%x\n", ntohs(ip->check));
  printf("src ip: %s\n", ip_to_str((uint8_t *)&ip->saddr));
  printf("dst ip: %s\n", ip_to_str((uint8_t *)&ip->daddr));
}

int
parse_ip(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  struct iphdr *iphdr = (struct iphdr *)(pkt + sizeof(struct ethhdr));
  print_ip_hdr(iphdr);
  if (iphdr->protocol == IPPROTO_ICMP) {
    parse_icmp(pkt, hdr, handle);
  } else {
    print_log("(%s) Got a packet of len %d that is not an IP packet!\n\n",
              fmt_ts(&hdr->ts), hdr->len);
  }
=======
int
parse_ip(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an IP packet.

>>>>>>> 9908967e2f56d6e9f06789abfc1c269e58a635bb
  return 0;
}
