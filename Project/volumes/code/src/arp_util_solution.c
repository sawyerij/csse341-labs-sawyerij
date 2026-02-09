// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arp_util.h"
#include "log.h"

int
send_arp_packets(pcap_t *handle, int npkts, int type, const char *smac,
                 const char *dmac, const char *sip, const char *dip)
{
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
  struct in_addr saddr;        // use this for ipv4 addresses
  u_char *pkt;                 // the packet to create.
  unsigned int i = 0;          // loop iterator
  int count      = 0;          // counter of sent packets

  // Allocate enough room for the packet itself to be held in memory.
  pkt = malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
  if(!pkt) {
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
  switch(type) {
  case ARP_PKT_REQUEST:
  case ARP_PKT_GRATUITOUS:
    eth_addr = ether_aton("ff:ff:ff:ff:ff:ff");
    break;
  case ARP_PKT_REPLY:
    eth_addr = ether_aton(dmac);
    break;
  default:
    print_err("Unknown ARP type %d\n", type);
    return 0;
  }
  memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);

  // TODO:
  // Set up Ethernet type
  eth->ether_type = htons(ETHERTYPE_ARP);

  // TODO:
  //  Set up ARP packet
  switch(type) {
  case ARP_PKT_REQUEST:
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    break;
  case ARP_PKT_REPLY:
  case ARP_PKT_GRATUITOUS:
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    break;
  default:
    print_err("Unknown ARP type %d\n", type);
    return 0;
  }

  // TODO:
  // Set the ARP hardware protocol and address length
  arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp->ea_hdr.ar_hln = 6;

  // TODO:
  //  Set the ARP target protocol and length
  arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
  arp->ea_hdr.ar_pln = 4;

  // TODO:
  //  Set up source ARP fields
  eth_addr = ether_aton(smac);
  memcpy(arp->arp_sha, eth_addr->ether_addr_octet, sizeof arp->arp_sha);
  inet_aton(sip, &saddr);
  memcpy(arp->arp_spa, &saddr.s_addr, 4);

  // TODO
  //  Set up destination ARP fields
  switch(type) {
  case ARP_PKT_REQUEST:
    // in case of an ARP request, the destination hardware address is set to
    // zero.
    memset(arp->arp_tha, 0, sizeof arp->arp_tha);
    break;
  case ARP_PKT_REPLY:
    // in case of an ARP reply, the destination hardware address is set to the
    // target hardware address
    eth_addr = ether_aton(dmac);
    memcpy(arp->arp_tha, eth_addr->ether_addr_octet, sizeof arp->arp_tha);
    break;
  case ARP_PKT_GRATUITOUS:
    // in case of a grauitous, either broadcast or all zeros work.
    eth_addr = ether_aton("ff:ff:ff:ff:ff:ff");
    memcpy(arp->arp_tha, eth_addr->ether_addr_octet, sizeof arp->arp_tha);
    break;
  default:
    print_err("Unknown ARP type %d\n", type);
    return 0;
  }

  // TODO
  //  Set up traget IP address
  switch(type) {
  case ARP_PKT_REQUEST:
  case ARP_PKT_REPLY:
    inet_aton(dip, &saddr);
    break;
  case ARP_PKT_GRATUITOUS:
    // for gratuitous, set the target IP as my own
    inet_aton(sip, &saddr);
    break;
  default:
    print_err("Unknown ARP type %d\n", type);
    return 0;
  }
  memcpy(arp->arp_tpa, &saddr.s_addr, sizeof arp->arp_tpa);

  // if npkts is -1, then create an overflow so that we come back to it later.
  for(i = 1; i <= (unsigned int)npkts; i++, count++) {
    int rc = pcap_inject(
        handle, pkt, sizeof(struct ether_header) + sizeof(struct ether_arp));
    if(rc == PCAP_ERROR_NOT_ACTIVATED) {
      print_err("pcap handler was not active, cannot send on it!\n");
      break;
    } else if(rc == PCAP_ERROR) {
      print_err("pcap error: %s\n", pcap_geterr(handle));
      break;
    }
    // sleep for a second not to overflow the network.
    sleep(1);
  }

  free(pkt);
  print_log("Done sending packets....\n");
  return count;
}
