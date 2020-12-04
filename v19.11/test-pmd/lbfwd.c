/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"
#include "hashget.h"

#define uint32_t_to_char(ip, a, b, c, d) do {\
                *a = (unsigned char)(ip >> 24 & 0xff);\
                *b = (unsigned char)(ip >> 16 & 0xff);\
                *c = (unsigned char)(ip >> 8 & 0xff);\
                *d = (unsigned char)(ip & 0xff);\
        } while (0)
#define UNUSED(x)	(void)(x)
#define MAC_FOR_EACH_PACKET

struct hash_ring_clone_t *hash_clone[RTE_MAX_LCORE];
uint32_t nb_hash_clone;

extern void
lb_listen_init(void);
extern void
lb_listen_deinit(void);

static void
pkt_burst_lb_forward_begin(portid_t pi)
{
	UNUSED(pi);
	nb_hash_clone = RTE_MAX_LCORE;
	hash_ring_clone_init(hash_clone, nb_hash_clone);
	lb_listen_init();
}

static void
pkt_burst_lb_forward_end(portid_t pi)
{
	UNUSED(pi);
	lb_listen_deinit();
}

static uint32_t
generate_hash_key(struct rte_ether_hdr *eth_hdr)
{
	uint32_t key;
	uint8_t *smac, *dmac;
	uint16_t ethertype;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vlan_hdr *vlan_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint32_t offset = 0;
        uint16_t sport, dport;
        uint8_t l4_proto;
        uint32_t dip, sip;

	offset += sizeof(struct rte_ether_hdr);
	smac = eth_hdr->s_addr.addr_bytes;
	dmac = eth_hdr->d_addr.addr_bytes;
	ethertype = eth_hdr->ether_type;

	// L2 (VLAN Header)
	if (ethertype == htons(RTE_ETHER_TYPE_VLAN))
	{
		vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
		offset += sizeof(struct rte_vlan_hdr);
		ethertype = vlan_hdr->eth_proto;
	}

	// L3 (IP Header)
	if (ethertype == htons(RTE_ETHER_TYPE_IPV4))
	{
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + offset);
		offset += (ipv4_hdr->version_ihl & 0x0f) * 4;
		sip = ipv4_hdr->src_addr;
		dip = ipv4_hdr->dst_addr;

		// L4 (TCP/UDP Port Header)
		l4_proto = ipv4_hdr->next_proto_id;
		if (l4_proto == IPPROTO_TCP)
		{
			tcp_hdr = (struct rte_tcp_hdr *)((char *)eth_hdr + offset);
			sport = tcp_hdr->src_port;
			dport = tcp_hdr->dst_port;
		}
		else if (l4_proto == IPPROTO_UDP)
		{
			udp_hdr = (struct rte_udp_hdr *)((char *)eth_hdr + offset);
			sport = udp_hdr->src_port;
			dport = udp_hdr->dst_port;
		}
		else
		{
			sport = 0;
			dport = 0;
		}
	}
	else if (ethertype == htons(RTE_ETHER_TYPE_IPV6))
	{
		// Not implemented
		//printf("ipv6 ethertype (0x%x) is not supported\n", ethertype);
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr + offset);
                offset += ipv6_hdr->proto;
		return 0;
	}
	else
	{
		return 0;
	}

	key = hash_tuple(smac, dmac, sip, dip, sport, dport);
	return key;
}

#ifdef PACKET_DUMP
static void
pkt_dump(struct rte_mbuf *mb, portid_t port, int inout)
{
	// Logging
	char smac_str[32];
	char dmac_str[32];
	unsigned char a, b, c, d;
	char sip_str[32];
	char dip_str[32];

	uint8_t *smac, *dmac;
	uint16_t ethertype;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vlan_hdr *vlan_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint32_t offset = 0;
        uint16_t sport, dport;
        uint8_t l4_proto;
        uint32_t dip, sip;
	char l4_proto_str[4];

	// L2 (Ethernet Header)
	eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
	offset += sizeof(struct rte_ether_hdr);
	smac = eth_hdr->s_addr.addr_bytes;
	dmac = eth_hdr->d_addr.addr_bytes;
	sprintf(smac_str, "%02x:%02x:%02x:%02x:%02x:%02x", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	sprintf(dmac_str, "%02x:%02x:%02x:%02x:%02x:%02x", dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
	ethertype = eth_hdr->ether_type;

	// L2 (VLAN Header)
	if (ethertype == htons(RTE_ETHER_TYPE_VLAN))
	{
		vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
		offset += sizeof(struct rte_vlan_hdr);
		ethertype = vlan_hdr->eth_proto;
	}

	// L3 (IP Header)
	if (ethertype == htons(RTE_ETHER_TYPE_IPV4))
	{
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + offset);
		offset += (ipv4_hdr->version_ihl & 0x0f) * 4;
		sip = ipv4_hdr->src_addr;
		dip = ipv4_hdr->dst_addr;

		// L4 (TCP/UDP Port Header)
		l4_proto = ipv4_hdr->next_proto_id;
		if (l4_proto == IPPROTO_TCP)
		{
			strcpy(l4_proto_str, "TCP");
			tcp_hdr = (struct rte_tcp_hdr *)((char *)eth_hdr + offset);
			sport = tcp_hdr->src_port;
			dport = tcp_hdr->dst_port;
		}
		else if (l4_proto == IPPROTO_UDP)
		{
			strcpy(l4_proto_str, "TCP");
			udp_hdr = (struct rte_udp_hdr *)((char *)eth_hdr + offset);
			sport = udp_hdr->src_port;
			dport = udp_hdr->dst_port;
		}
		else
		{
			sport = 0;
			dport = 0;
		}
	}
	else if (ethertype == htons(RTE_ETHER_TYPE_IPV6))
	{
		// Not implemented
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr + offset);
                offset += ipv6_hdr->proto;
		return;
	}
	else
	{
                if (inout == 0)
                        printf("port(%u): %s->%s \n", port, smac_str, dmac_str);
                else
                        printf(">>> port(%u): %s->%s \n", port, smac_str, dmac_str);
		return;
	}

	uint32_t_to_char(rte_bswap32(sip), &a, &b, &c, &d);
	sprintf(sip_str, "%hhu.%hhu.%hhu.%hhu", a, b, c, d);
	uint32_t_to_char(rte_bswap32(dip), &a, &b, &c, &d);
	sprintf(dip_str, "%hhu.%hhu.%hhu.%hhu", a, b, c, d);
	UNUSED(dport);
	UNUSED(sport);
	if (inout == 0)
		printf("port(%u): %s->%s, %s->%s, %s:%u, %u\n", port, smac_str,
			dmac_str, sip_str, dip_str, l4_proto_str, sport, dport);
	else
		printf(">>> port(%u): %s->%s, %s->%s, %s:%u, %u\n", port, smac_str,
			dmac_str, sip_str, dip_str, l4_proto_str, sport, dport);

}
#endif /* PACKET_DUMP */

/*
 * Forwarding of packets in LB mode.
 * Change the source and the destination Ethernet addressed of packets
 * before forwarding them.
 */
static void
pkt_burst_lb_forward(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct rte_port  *txp;
	struct rte_mbuf  *mb;
	struct rte_ether_hdr *eth_hdr = NULL;
	uint32_t retry;
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint16_t i;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif
        struct rte_ether_addr mac;
        uint32_t key = 0;
	lcoreid_t lcore;
	int ret = -1;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	lcore = rte_lcore_id();
	hash_clone[lcore] = (struct hash_ring_clone_t *)(uintptr_t)hash_clone_new;

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	fs->rx_packets += nb_rx;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	if (tx_offloads	& DEV_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = PKT_TX_VLAN_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= PKT_TX_QINQ_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= PKT_TX_MACSEC;
	for (i = 0; i < nb_rx; i++) {
		if (likely(i < nb_rx - 1))
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
						       void *));
		mb = pkts_burst[i];
#ifdef PACKET_DUMP
		pkt_dump(mb, fs->rx_port, 0);
#endif
		eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
		if (eth_hdr == NULL)
		{
			printf("eth_hdr of packet %u is NULL\n", i);
			continue;
		}
		if (fs->generate == 1)
		{
#ifdef MAC_FOR_EACH_PACKET
			/* Generate hash and find mac for each packet */
			key = generate_hash_key(eth_hdr);
			if (key != 0)
				ret = hash_ring_clone_get_mac(hash_clone[lcore], key, mac.addr_bytes);
#else
			/* Generate hash and get mac once, and apply for all packets in a single read */
                        if (key == 0)
                        {
                                key = generate_hash_key(mb);
                                if (key != 0)
                                        ret = hash_ring_clone_get_mac(hash_clone[lcore], key, mac.addr_bytes);
                        }
#endif
                        if (ret == 0)
                        {
                                rte_ether_addr_copy(&ports[fs->tx_port].eth_addr,
                                        &eth_hdr->s_addr);
                                rte_ether_addr_copy(&mac, &eth_hdr->d_addr);
                        }
		}
		else
		{
			rte_ether_addr_copy(&ports[fs->tx_port].eth_addr,
				&eth_hdr->s_addr);
			rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr],
				&eth_hdr->d_addr);
		}
#ifdef PACKET_DUMP
		pkt_dump(mb, fs->rx_port, 1);
#endif
		mb->ol_flags &= IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF;
		mb->ol_flags |= ol_flags;
		mb->l2_len = sizeof(struct rte_ether_hdr);
		mb->l3_len = sizeof(struct rte_ipv4_hdr);
		mb->vlan_tci = txp->tx_vlan_id;
		mb->vlan_tci_outer = txp->tx_vlan_id_outer;
	}
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}

	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
}

struct fwd_engine lb_fwd_engine = {
	.fwd_mode_name  = "lb",
	.port_fwd_begin = pkt_burst_lb_forward_begin,
	.port_fwd_end   = pkt_burst_lb_forward_end,
	.packet_fwd     = pkt_burst_lb_forward,
};
