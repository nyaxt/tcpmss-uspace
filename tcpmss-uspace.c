/* tcpmss-uspace
 * Copyright (C) 2017 Kouhei Ueno

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.

 * Based on nfqnl_test.c by libnetfilter_queue project
 */

#include <stdio.h>
#include <string.h>
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

int g_verbose = 0;
int g_maxmss = 1412; /* max mss size to clamp to */
#define dprintf if (g_verbose) printf

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

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *cbuserdata)
{
  int ret;
	uint32_t id = 0;

  uint8_t* data;
	int payload_len = nfq_get_payload(nfa, &data);
  if (payload_len < sizeof(struct iphdr)) {
    ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  } else {
    struct iphdr* iph = (struct iphdr*)(data);
    dprintf("ip version %u len %u proto %u csum %u ", iph->version, iph->ihl, iph->protocol, iph->check);

    if (iph->protocol == IPPROTO_TCP && payload_len >= (iph->ihl*4) + sizeof(struct tcphdr)) {
      struct tcphdr* tcph = (struct tcphdr*)(data + (iph->ihl*4));
      dprintf("dst port=%u data_offset=%u syn=%u ", ntohs(tcph->dest), tcph->doff, tcph->syn);
      uint8_t *popt = (uint8_t*)(tcph) + 20;
      uint8_t *pend = data + (iph->ihl + tcph->doff)*4;
      while (popt < pend) {
        uint8_t kind = *popt++;
        dprintf("opt[kind=%u ", kind);
        if (kind >= 2) {
          uint8_t len = *popt++ - 2;
          dprintf("len=%u ", len);
          if (kind == TCPOPT_MAXSEG && len == TCPOLEN_MAXSEG-2) {
            uint16_t maxseg = ntohs(*(uint16_t*)popt);
            dprintf("maxseg=%u ", maxseg);
            if (maxseg > g_maxmss) {
              dprintf("-> %u ", g_maxmss);
              maxseg = g_maxmss;
              *(uint16_t*)popt = htons(maxseg);
            }
          }
          popt += len;
        }
        dprintf("] ");
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
    ret = nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, data);
  }
  dprintf("\n");

  return ret;
}

void help(const char* argv0) {
  fprintf(stderr, "Usage: %s [-v] queue_id maxmss\n", argv0);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

  const char* argv0 = argv[0];
  argv++; argc--;

  if (argc > 1 && strcmp("-v", argv[0]) == 0) {
    g_verbose = 1; 
    argv++; argc--;
  }

	if (argc != 2)
    help(argv0);

  queue = atoi(argv[0]);
  if (queue > 65535)
    help(argv0);

  g_maxmss = atoi(argv[1]);
	printf("queue id: %d, maxmss: %d\n", queue, g_maxmss);

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
	qh = nfq_create_queue(h, queue, &packet_callback, NULL);
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
			dprintf("pkt received\n");
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
			dprintf("losing packets!\n");
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
