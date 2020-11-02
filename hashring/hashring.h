#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAC_LEN (6)

struct hash_ring_node_t
{
    uint8_t *name;
    uint32_t name_length;
    uint8_t mac[MAC_LEN];
    // possibility to add IP
};

struct hash_ring_node_ll_t
{
    struct hash_ring_node_t *node;
    struct hash_ring_node_ll_t *next;
};

struct hash_ring_item_t
{
    uint32_t key;
    struct hash_ring_node_t *node;
};

struct hash_ring_t
{
    uint32_t node_replicas;
    uint32_t node_length;
    struct hash_ring_node_ll_t *nodes;
    struct hash_ring_item_t **items;
    uint32_t item_length;
};

struct hash_ring_t *
hash_ring_create(uint32_t replicas);

void
hash_ring_destroy(struct hash_ring_t *ring);

void
hash_ring_remove_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in);

void
hash_ring_add_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in);

void
hash_ring_dump(struct hash_ring_t *ring);
