// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
<<<<<<< HEAD
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "icmp_util.h"
#include "log.h"
#include "util.h"

void
print_icmp_hdr(struct icmphdr *icmp)
{
  BANNER("ICMP HEADER");
  printf("type=%d\n", icmp->type);
  printf("code=%d\n", icmp->code);
  printf("csum=%x\n", ntohs(icmp->checksum));
}

void
create_icmp_reply(uint8_t *my_mac_addr, u_char *pkt, int data_len)
{
  struct ether_header *ethhdr = (struct ether_header *)pkt;
  struct iphdr *iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  struct icmphdr *icmphdr =
      (struct icmphdr *)(pkt + sizeof(struct ether_header) +
                         sizeof(struct iphdr));

  /* Create the Ethernet header */
  if (ethhdr == NULL)
    perror("malloc");

  memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, 6);
  memcpy(ethhdr->ether_shost, my_mac_addr, 6);

  /* Create the IP header */
  uint32_t temp_daddr = iphdr->daddr;
  iphdr->daddr = iphdr->saddr;
  iphdr->saddr = temp_daddr;

  iphdr->check = 0;
  iphdr->check = chksum((uint16_t *)iphdr, sizeof(struct iphdr));

  /* Create ICMP header */
  icmphdr->type = ICMP_ECHOREPLY;
  icmphdr->code = 0;
  icmphdr->checksum = 0;
  icmphdr->checksum =
      chksum((uint16_t *)icmphdr, sizeof(struct icmphdr) + data_len);
}
=======

#include "icmp_util.h"
#include "log.h"
>>>>>>> 9908967e2f56d6e9f06789abfc1c269e58a635bb

void
parse_icmp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
           unsigned len)
{
  struct iphdr *iphdr;
  struct icmphdr *icmphdr;
  struct ether_addr *eth_addr;
  u_char *retpkt;

  iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  icmphdr =
      (struct icmphdr *)(pkt + sizeof(struct ether_header) + sizeof *iphdr);
  eth_addr = ether_aton(my_mac_addr);

<<<<<<< HEAD
  if (icmphdr->type == ICMP_ECHO) {
    print_log("Received ICMP Echo from %s\n", ip_to_str(&iphdr->saddr));
    int icmp_len = len - sizeof(struct ether_header) - sizeof(struct iphdr);
    int icmp_payload_len = icmp_len - sizeof(struct icmphdr);
    retpkt = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) +
                    sizeof(struct icmphdr) + icmp_len);
    if (retpkt == NULL)
      perror("malloc");
    memcpy(retpkt, pkt, len);

    create_icmp_reply((uint8_t *)&eth_addr->ether_addr_octet, retpkt,
                      icmp_payload_len);
    pcap_inject(handle, retpkt, len);
    free(retpkt);
    print_log("Sent ICMP Echo Reply");
  }
=======
  // TODO:
  // =====
  //  Remove these lines once you're starting, they're here to silence the
  //  compiler warnings.
  (void)icmphdr;
  (void)eth_addr;
  (void)retpkt;

  // TODO:
  // =====
  //
  //  1. Check if the ICMP header is an Echo request, if so, just print that
  //     you have received it, and the source from which it originated.
  //
  //     Recall that the source IPv4 address is in the IPv4 header, not the
  //     ICMP header.
  //
  //  2. Send an ICMP Echo Reply to whoever sent you the request.
  //     Here's on approach to do:
  //
  //     2.1 Allocate room for the new packet, use retpkt from above.
  //
  //     2.2 Copy the old packet into the new one, using memcpy.
  //          Hint: we know the full size of the packet already, it is len!
  //
  //     2.3 Adjust the fields of each header that need to be adjusted.
  //
  //     2.4 Use pcap_inject(handle, retpkt, len); to send the packet on the
  //         wire.
  //
  //     2.5 Free the retpkt to make sure you have no memory LEAKS.
  //
>>>>>>> 9908967e2f56d6e9f06789abfc1c269e58a635bb
}
