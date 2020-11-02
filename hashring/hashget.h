
struct hash_ring_clone_t
{
    uint32_t length;
    struct hash_ring_key_map_t *list;
};

struct hash_ring_key_map_t
{
    uint32_t key;
    uint8_t mac[MAC_LEN];
};

void
hash_ring_clone_get_mac(struct hash_ring_clone_t *clone, uint32_t key, uint8_t *mac);
