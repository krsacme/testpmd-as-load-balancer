#include "hashring.h"
#include "hashget.h"


/////////////////// hashring ///////////////////
struct hash_ring_t *
hash_ring_create(uint32_t replicas)
{
    struct hash_ring_t *ring = malloc(sizeof(struct hash_ring_t));

    if (ring != NULL)
    {
        ring->node_replicas = replicas;
        ring->node_length = 0;
        ring->nodes = NULL;
        ring->items = NULL;
        ring->item_length = 0;
    }
    return ring;
}

void
hash_ring_destroy(struct hash_ring_t *ring)
{
    uint32_t i;
    struct hash_ring_node_ll_t *ll_entry;

    if (ring != NULL)
    {
        ll_entry = ring->nodes;
        while (ring->nodes != NULL)
        {
            ll_entry = ring->nodes;
            ring->nodes = ll_entry->next;
            free(ll_entry);
        }

        if (ring->items != NULL)
        {
            for (i = 0; i < ring->item_length; i++)
            {
                if (ring->items[i] != NULL)
                    free(ring->items[i]);
            }
            free(ring->items);
        }

        free(ring);
    }
}

static struct hash_ring_node_t *
hash_ring_ll_add_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in)
{
    struct hash_ring_node_t *new_node;
    struct hash_ring_node_ll_t *entry;

    new_node = malloc(sizeof(struct hash_ring_node_t));
    if (new_node == NULL)
    {
        perror("failed to allocate memory for node");
        return NULL;
    }

    new_node->name = malloc(sizeof(uint8_t) * node_in->name_length);
    if (new_node->name == NULL)
    {
        perror("failed to allocate memory for node name");
        free(new_node);
        return NULL;
    }
    memcpy(new_node->name, node_in->name, node_in->name_length);
    new_node->name_length = node_in->name_length;
    memcpy(new_node->mac, node_in->mac, MAC_LEN);

    entry = malloc(sizeof(struct hash_ring_node_ll_t));
    if (entry == NULL)
    {
        free(new_node->name);
        free(new_node);
        perror("failed to allocat memory for ll node");
        return NULL;
    }

    entry->next = ring->nodes;
    entry->node = new_node;
    ring->nodes = entry;
    ring->node_length++;
    return new_node;
}

static int
hash_ring_compare_node(struct hash_ring_node_t *node_a, struct hash_ring_node_t *node_b)
{
    int cmp_value = 0;

    if (node_a->name_length != node_b->name_length)
    {
        return -1;
    }

    cmp_value |= memcmp(node_a->name, node_b->name, node_a->name_length);
    cmp_value |= memcmp(node_a->mac, node_b->mac, MAC_LEN);
    return cmp_value;
}

static void
hash_ring_ll_remove_node(struct hash_ring_t *ring, struct hash_ring_node_t *node)
{
    struct hash_ring_node_ll_t *ll_entry;
    struct hash_ring_node_ll_t *ll_prev = NULL;
    int cmp_value;

    ll_entry = ring->nodes;
    while (ll_entry != NULL)
    {
        cmp_value = hash_ring_compare_node(node, ll_entry->node);
        if (cmp_value == 0)
        {
            if (ll_prev != NULL)
                ll_prev->next = ll_entry->next;
            else
                ring->nodes = ll_entry->next;

            free(ll_entry->node->name);
            free(ll_entry->node);
            free(ll_entry);
            ring->node_length--;
            return;

        }
        ll_prev = ll_entry;
        ll_entry = ll_entry->next;
    }
}

static uint32_t
hash_ring_create_node_hash(struct hash_ring_node_t *node, uint32_t round)
{
    uint8_t *buffer;
    uint32_t length = 0;
    uint32_t start = 0;

    length += (node->name_length * sizeof(uint8_t));
    length += (MAC_LEN * sizeof(uint8_t));
    length += sizeof(uint32_t);

    buffer = malloc(length);
    if (buffer != NULL)
    {
        start = 0;
        memcpy(buffer + start, node->name, node->name_length);
        start += node->name_length;
        memcpy(buffer + start, node->mac, MAC_LEN);
        start += MAC_LEN;
        memcpy(buffer + start, &round, sizeof(uint32_t));
        start += sizeof(uint32_t);
        return rte_jhash(buffer, length, 0);
    }
    return 0;
}

static int
item_sort(const void *a, const void *b)
{
    const struct hash_ring_item_t *item_a = *(const struct hash_ring_item_t**)(uintptr_t)a;
    const struct hash_ring_item_t *item_b = *(const struct hash_ring_item_t**)(uintptr_t)b;

    if (item_a == NULL)
       return 1;
    if (item_b == NULL)
       return -1;

    if(item_a->key < item_b->key)
        return -1;
    else if(item_a->key > item_b->key)
        return 1;
    else
        return 0;
}

static int
hash_ring_add_items(struct hash_ring_t *ring, struct hash_ring_node_t *node)
{
    uint32_t item_length = ring->node_replicas * ring->node_length;
    uint32_t item_start, i;
    struct hash_ring_item_t **resized;
    struct hash_ring_item_t *item_entry;

    resized = realloc(ring->items, item_length * sizeof(struct hash_ring_item_t*));
    if (resized == NULL)
    {
        perror("failed to allocate memory for items");
        return -1;
    }

    ring->items = resized;
    item_start = item_length - ring->node_replicas;
    for (i = item_start; i < item_length; i++)
    {
        item_entry = malloc(sizeof(struct hash_ring_item_t));
        if (item_entry == NULL)
        {
            perror("failed to allocate memory for an item");
            return -1;
        }
        item_entry->node = node;
        item_entry->key = hash_ring_create_node_hash(node, i);
        if (item_entry->key == 0)
        {
            free(item_entry);
            perror("failed to create hash for node item");
            return -1;
        }
        ring->items[i] = item_entry;
    }
    ring->item_length = item_length;

    qsort((void**)ring->items, ring->item_length, sizeof(struct hash_ring_item_t*), item_sort);
    return 0;
}

static void
hash_ring_remove_items(struct hash_ring_t *ring, struct hash_ring_node_t *node)
{
    uint32_t i;

    for (i = 0; i < ring->item_length; i++)
    {
        if (ring->items[i]->node == node)
        {
            free(ring->items[i]);
            ring->items[i] = NULL;
        }
    }

    qsort((void**)ring->items, ring->item_length, sizeof(struct hash_ring_item_t*), item_sort);
    ring->item_length -= ring->node_replicas;
}

static struct hash_ring_node_t *
hash_ring_find_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in)
{
    struct hash_ring_node_ll_t *ll_entry;
    int cmp_value;

    ll_entry = ring->nodes;
    while (ll_entry != NULL)
    {
        cmp_value = hash_ring_compare_node(node_in, ll_entry->node);
        if (cmp_value == 0)
            return ll_entry->node;

        ll_entry = ll_entry->next;
    }
    return NULL;
}

void
hash_ring_remove_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in)
{
    struct hash_ring_node_t* node;

    node = hash_ring_find_node(ring, node_in);
    if (node != NULL)
    {
        hash_ring_remove_items(ring,node);
        hash_ring_ll_remove_node(ring, node);
    }
}

void
hash_ring_add_node(struct hash_ring_t *ring, struct hash_ring_node_t *node_in)
{
    struct hash_ring_node_t *node;
    int ret;

    node = hash_ring_find_node(ring, node_in);
    if (node != NULL)
    {
        return;
    }

    // Add new node to the linked list of ring
    node = hash_ring_ll_add_node(ring, node_in);
    if (node == NULL)
    {
        perror("failed to allocate node");
        return;
    }

    // Re-alloc items array of struct hash_ring_item_t with new node
    // Create hash key for new node items
    ret = hash_ring_add_items(ring, node);
    if (ret != 0)
    {
        perror("failed to add items");
        hash_ring_remove_node(ring, node);
        return;
    }
}

void
hash_ring_updated(struct hash_ring_t *ring)
{
	struct hash_ring_clone_t *new_clone;

	new_clone = hash_ring_clone_create(ring);
	if (new_clone == NULL)
	{
		perror("failed to create a new clone\n");
		return;
	}
	hash_ring_clone_trigger(new_clone);
}

/*
static struct hash_ring_node_t *
hash_ring_get_node(struct hash_ring_t *ring, uint32_t key)
{
    int i;

    for (i = 0; i < ring->item_length; i++)
    {
        if (key < ring->items[i]->key)
        {
            return ring->items[i]->node;
        }
    }
    return ring->items[ring->item_length - 1]->node;
}
*/

void
hash_ring_dump(struct hash_ring_t *ring)
{
    struct hash_ring_node_ll_t *entry;
    uint8_t buffer[128];
    uint8_t *mac;
    uint32_t i;

    printf("----------------------------------------------\n");
    printf("Nodes Count: %u\n", ring->node_length);
    printf("Items Count: %u\n", ring->item_length);
    printf("Replicas   : %u\n", ring->node_replicas);

    entry = ring->nodes;
    if (entry != NULL)
    {
        while (entry != NULL)
        {
            memset(buffer, 0, 128);
            memcpy(buffer, entry->node->name, entry->node->name_length);
            mac = entry->node->mac;
            printf("Name(%s) Mac(%02x:%02x:%02x:%02x:%02x:%02x)\n", buffer, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            entry = entry->next;
        }
        printf("\n");
        for (i = 0; i < ring->item_length; i++)
        {
            memset(buffer, 0, 128);
            memcpy(buffer, ring->items[i]->node->name, ring->items[i]->node->name_length);
            printf("Item(%03d) key(%010u) Node(%s)\n", i, ring->items[i]->key, buffer);
        }
    }
    else
    {
        printf("No nodes available\n");
    }
    printf("----------------------------------------------\n");
}

/////////////////// hasget ///////////////////
struct hash_ring_clone_t *
hash_ring_clone_create(struct hash_ring_t *ring)
{
    void *alloc;
    uint32_t array_mem, items_mem, i;
    struct hash_ring_clone_t *clone;

    if (ring->item_length == 0)
    {
	    printf("no items to clone\n");
	    return NULL;
    }

    // Array
    array_mem = ring->item_length * sizeof(struct hash_ring_item_t*);
    // Actual Items
    items_mem = ring->item_length * sizeof(struct hash_ring_item_t);

    alloc = malloc(array_mem + items_mem);
    if (alloc == NULL)
    {
        perror("failed to clone the items");
        return NULL;
    }
    memset(alloc, 0, array_mem + items_mem);
    clone = alloc;
    clone->length = ring->item_length;
    clone->list = (struct hash_ring_key_map_t *)((uint8_t *)alloc + sizeof(struct hash_ring_clone_t));

    for (i = 0; i < ring->item_length; i++)
    {
        clone->list[i].key = ring->items[i]->key;
        memcpy(clone->list[i].mac, ring->items[i]->node->mac, MAC_LEN);
    }
    return clone;
}

void
hash_ring_clone_destroy(struct hash_ring_clone_t *clone)
{
    if (clone != NULL)
        free(clone);
}

void
hash_ring_clone_dump(struct hash_ring_clone_t *clone)
{
    uint32_t i;
    uint8_t *mac;

    printf("----------------------------------------------\n");
    printf("Count: %u\n", clone->length);

    for (i = 0; i < clone->length; i++)
    {
        mac = clone->list[i].mac;
        printf("Item(%03d) key(%010u) Mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                i, clone->list[i].key, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    printf("----------------------------------------------\n");
}
