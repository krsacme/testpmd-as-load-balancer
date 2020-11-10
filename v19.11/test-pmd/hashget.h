#ifndef _HASHGET_H_
#define _HASHGET_H_

#include <stdlib.h>
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
#include <rte_jhash.h>
#include <rte_ether.h>

struct hash_ring_clone_t
{
    uint32_t length;
    struct hash_ring_key_map_t *list;
};

struct hash_ring_key_map_t
{
    uint32_t key;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
};

extern volatile struct hash_ring_clone_t *hash_clone_new;

void
hash_ring_clone_init(struct hash_ring_clone_t **clone_holders, uint32_t nb);

void
hash_ring_clone_get_mac(struct hash_ring_clone_t *clone, uint32_t key, uint8_t *mac);

void
hash_ring_clone_trigger(struct hash_ring_clone_t *new_clone);

uint32_t
hash_tuple(uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

#endif /* _HASHGET_H_ */
