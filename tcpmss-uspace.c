// tcpmss-uspace
// Copyright (C) 2017 Kouhei Ueno
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or (at
// your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA.
//
// Based on nfqnl_test.c by libnetfilter_queue project

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void ip_checksum_add(uint32_t* tmp, const void* vdata, size_t count) {
  const uint8_t* data = (const uint8_t*)vdata;
  while( count > 1 )  {
    *tmp += *(uint16_t*)data;
    data += 2;
    count -= 2;

    while (*tmp>>16)
      *tmp = (*tmp & 0xffff) + (*tmp >> 16);
  }

  if(count > 0)
    *tmp += *data;

  while (*tmp>>16)
    *tmp = (*tmp & 0xffff) + (*tmp >> 16);
}

uint16_t ip_checksum_finalize(uint32_t* tmp) {
  return ~(*tmp);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *cbuserdata)
{
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	struct nfqnl_msg_packet_hw *hwph = nfq_get_packet_hw(nfa);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	uint32_t mark = nfq_get_nfmark(nfa);
	if (mark)
		printf("mark=%u ", mark);

	uint32_t ifi = nfq_get_indev(nfa);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(nfa);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(nfa);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(nfa);
	if (ifi)
		printf("physoutdev=%u ", ifi);

  uint8_t* data;
	int payload_len = nfq_get_payload(nfa, &data);
	if (payload_len >= 0)
		printf("payload_len=%d ", payload_len);

  if (payload_len >= sizeof(struct iphdr)) {
    struct iphdr* iph = (struct iphdr*)(data);
    printf("ip version %u len %u proto %u csum %u ", iph->version, iph->ihl, iph->protocol, iph->check);

    if (iph->protocol == IPPROTO_TCP && payload_len >= (iph->ihl*4) + sizeof(struct tcphdr)) {
      struct tcphdr* tcph = (struct tcphdr*)(data + (iph->ihl*4));
      printf("dst port=%u data_offset=%u syn=%u ", ntohs(tcph->dest), tcph->doff, tcph->syn);
      uint8_t *popt = (uint8_t*)(tcph) + 20;
      uint8_t *pend = data + (iph->ihl + tcph->doff)*4;
      while (popt < pend) {
        uint8_t kind = *popt++;
        printf("opt[kind=%u ", kind);
        if (kind >= 2) {
          uint8_t len = *popt++ - 2;
          printf("len=%u ", len);
          if (kind == TCPOPT_MAXSEG && len == TCPOLEN_MAXSEG-2) {
            uint16_t maxseg = ntohs(*(uint16_t*)popt);
            printf("maxseg=%u ", maxseg);
            if (maxseg > 1414)
              maxseg = 1414;
            *(uint16_t*)popt = htons(maxseg);
          } else if (kind == TCPOPT_WINDOW && len == TCPOLEN_WINDOW-2) {
            printf("wscale=%u ", *popt);
          } else for (int i = 0; i < len; ++ i) {
            printf("%02x ", popt[i]);
          }
          popt += len;
        }
        printf("] ");
      }

      // recompute tcp csum
      tcph->check = 0;
      uint16_t mycsum;
      {
        uint32_t tmp = 0;
        ip_checksum_add(&tmp, &iph->saddr, 4);
        ip_checksum_add(&tmp, &iph->daddr, 4);
        static const uint16_t zeroproto = IPPROTO_TCP << 8;
        ip_checksum_add(&tmp, &zeroproto, 2);
        uint16_t len = ntohs(iph->tot_len) - iph->ihl*4;
        uint16_t nlen = htons(len);
        ip_checksum_add(&tmp, &nlen, 2);
        ip_checksum_add(&tmp, tcph, len);
        mycsum = ip_checksum_finalize(&tmp);
      }
      tcph->check = mycsum;
    }
  }

	fputc('\n', stdout);

	return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, data);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc == 2) {
		queue = atoi(argv[1]);
		if (queue > 65535) {
			fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
