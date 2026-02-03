// SPDX-License-Identifier: Unlicense

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arp_util.h"
#include "log.h"

int
send_arp_packets(pcap_t *handle, int npkts, int type, const char *smac,
                 const char *dmac, const char *sip, const char *dip)
{
	char req_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  // TODO:
  // ====
  //  Add code here to craft and send num_req ARP requests.
  //
  //  You should build two headers, an Ethernet header and an ARP header and
  //  set their approriate fields.
  //
  struct ether_header *eth;    // the Ethernet header to fill in.
  struct ether_arp *arp;       // the ARP header to fill in.
  struct ether_addr *eth_addr; // use this to hold Ethernet addresses
  struct in_addr addr;         // use this for ipv4 addresses
  u_char *pkt;                 // the packet to create.
  int count = 0;               // the number of packets sent so far.

  // Allocate enough room for the packet itself to be held in memory.
  pkt = malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
  if (!pkt) {
    print_err(
        "[PANIC]: Could not find room in memory to allocate a new packet!\n");
    perror("[PANIC]: ");
    exit(EXIT_FAILURE);
  }

  // Grab the two headers at the start of the packet and the payload of Eth.
  eth = (struct ether_header *)pkt;
  arp = (struct ether_arp *)(pkt + sizeof *eth);

  // Set the source MAC address
  eth_addr = ether_aton(smac);
  memcpy(eth->ether_shost, eth_addr->ether_addr_octet, sizeof eth->ether_shost);

  // TODO:
  //  Set the destination MAC address.
  if (dmac) {
    eth_addr = ether_aton(dmac);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet,
           sizeof eth->ether_dhost);
  } else {
    memcpy(eth->ether_dhost, &req_mac, sizeof eth->ether_dhost);
  }
  print_log("copied source and dest mac\n");

  // TODO:
  //  Set the Ethernet type field
  //  Use a switch statement depending on the `type`.
  eth->ether_type = htons(ETHERTYPE_ARP);

  // TODO:
  //  Set up ARP packet operation type. That depends on the `type` variable.
  switch (type) {
  case ARP_PKT_REQUEST:
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    break;
  case ARP_PKT_REPLY:
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    break;
	case ARP_PKT_GRATUITOUS:
		arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
		break;
  default:
    print_err("Unknown ARP type\n");
    free(pkt);
    return -1;
  }
  print_log("finished eth fields\n");

  // TODO:
  //  Set the ARP hardware protocol and address length
  arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);

  // TODO:
  //  Set the ARP target protocol and length
  arp->ea_hdr.ar_hln = ETH_ALEN;
  arp->ea_hdr.ar_pln = 4;

  print_log("finished arp protocol fields\n");

  // TODO:
  //  Set up source ARP fields
  //  Those are: arp->arp_sha and arp->arp_spa
  //  I give you to way to set arp->arp_spa below
  //
  inet_aton(sip, &addr);
  memcpy(arp->arp_spa, &addr.s_addr, 4);

  eth_addr = ether_aton(smac);
  memcpy(arp->arp_sha, eth_addr->ether_addr_octet, sizeof arp->arp_sha);

  print_log("finished arp source fields\n");

  // TODO:
  //  Set up destionation ARP fields
  //  Those are: arp->arp_tha and arp->arp_tpa
  if (dmac) {
    eth_addr = ether_aton(dmac);
    memcpy(arp->arp_tha, eth_addr->ether_addr_octet, sizeof arp->arp_tha);

    print_log("finished arp dest fields\n");
  }
  inet_aton(dip, &addr);
  memcpy(arp->arp_tpa, &addr.s_addr, 4);

  // TODO:
  //  Loop depending on `npkts` and send one packet each time.
  //   Do not recreate the packet, just send the same one over and over again.
  //
  //   Make sure to add `sleep(1);` between each packet to be nice to the
  //   docker network.

  for (int i = 0; i < npkts; i++) {
    pcap_inject(handle, pkt,
                sizeof(struct ether_header) + sizeof(struct ether_arp));
    sleep(1);
  }

  //
  //  Free the packet and leave. Return the total number of packets sent.
  //    Note: if `npkts` is -1, then we will never reach here except on error.

  free(pkt);
  print_log("Done sending packets....\n");
  return count;
}
