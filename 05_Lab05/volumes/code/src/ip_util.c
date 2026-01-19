// SPDX-License-Identifier: Unlicense

#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "icmp_util.h"
#include "ip_util.h"
#include "log.h"
#include "util.c"

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
  printf("src ip: %s\n", ip_to_str(&ip->saddr));
  printf("dst ip: %s\n", ip_to_str(&ip->daddr));
}

void
parse_ip(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
         unsigned len)
{
  struct iphdr *iphdr;
  uint8_t protocol;
  struct in_addr addr;

  (void)protocol;
  (void)addr;

  // move forward to the ip header
  iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  protocol = iphdr->protocol;
  printf("\n");
  if (iphdr->protocol == IPPROTO_ICMP) {
    parse_icmp(pkt, my_mac_addr, handle, len);
  } else {
    print_log("Dropped non-ICMP packet");
  }
}
