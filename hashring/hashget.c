#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define MAC_LEN (6)


uint32_t hash_tuple(uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    uint32_t idx = 0;
    uint32_t hash_val = 0;
    uint8_t buffer[32];
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA_CTX shactx;
    int i;

    memcpy(&buffer[idx], smac, MAC_LEN);
    idx += MAC_LEN;
    memcpy(&buffer[idx], dmac, MAC_LEN);
    idx += MAC_LEN;
    memcpy(&buffer[idx], &sip, 4);
    idx += 4;
    memcpy(&buffer[idx], &dip, 4);
    idx += 4;
    memcpy(&buffer[idx], &sport, 2);
    idx += 2;
    memcpy(&buffer[idx], &dport, 2);
    idx += 2;

    hash_val = rte_jhash(buffer, idx, 0);

    return hash_val;
}

/////////////////// hashget ///////////////////

void
hash_ring_clone_get_mac(struct hash_ring_clone_t *clone, uint32_t key, uint8_t *mac)
{
    int i;

    if (mac != NULL)
    {
        for (i = 0; i < clone->length; i++)
        {
            if (key < clone->list[i].key)
            {
                memcpy(mac, clone->list[i].mac. MAC_LEN);
                return
            }
        }
        memcpy(mac, clone->list[clone->length - 1].mac, MACL_LEN);
    }
}

void
hash_ring_clone_dump(struct hash_ring_clone_t *clone)
{
    int i;
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
