#include "hashget.h"
#include "hashring.h"

#define MAC_LEN (6)
#define HASH_CLONE_MARK_SWEEP_MAX (16)

volatile struct hash_ring_clone_t *hash_clone_new;
struct hash_ring_clone_t *hash_clone_mark_sweep[HASH_CLONE_MARK_SWEEP_MAX];
struct hash_ring_clone_t **hash_clone_list;
uint32_t nb_hash_clone_list;

/////////////////// hashget - TestPMD Main Thread operations///////////////////

/* Called from TestPMD main thread before starting PMD (withing start hook)
 * Stores the list of clones to be used by different PMD threads.
 * It is used to identify used clone instances by PMD threads to free the
 * unused clones.
 */
void
hash_ring_clone_init(struct hash_ring_clone_t **clone_list, uint32_t nb)
{
	hash_clone_list = clone_list;
	nb_hash_clone_list = nb;
}

// Called from TestPMD LB Listen Thread when DUT is added/removed
void
hash_ring_clone_trigger(struct hash_ring_clone_t *new_clone)
{
	struct hash_ring_clone_t *old_clone;
	uint32_t i, j, found;

	if (new_clone == NULL)
		return;


	/* Update the volatile pointer to be accessed by PMD threads */
	old_clone = (struct hash_ring_clone_t *)(uintptr_t)hash_clone_new;
	hash_clone_new = new_clone;

	for (i = 0; i < HASH_CLONE_MARK_SWEEP_MAX; i++)
	{
		if (hash_clone_mark_sweep[i] == NULL)
		{
			hash_clone_mark_sweep[i] = old_clone;
			break;
		}
	}

	for (i = 0; i < HASH_CLONE_MARK_SWEEP_MAX; i++)
	{
		found = 0;
		if (hash_clone_mark_sweep[i] == NULL)
			continue;
		for (j = 0; j < nb_hash_clone_list; j++)
		{
			if (hash_clone_list[j] == NULL)
				continue;
			if (hash_clone_mark_sweep[i] == hash_clone_list[j])
			{
				found = 1;
			}
		}

		if (found == 0)
		{
			hash_ring_clone_destroy(hash_clone_mark_sweep[i]);
			hash_clone_mark_sweep[i] = NULL;
		}
	}
}

/////////////////// hashget - PMD Thread operations///////////////////

// Called from the PMD thread
uint32_t
hash_tuple(uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
	uint32_t idx = 0;
	uint32_t hash_val = 0;
	uint32_t i;
	uint8_t buffer[32];

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
/*
        for (i = 0; i < idx; i++)
                hash_val += (buffer[i] * 353535);
*/
                /*hash_val += (buffer[i] * 365365365);*/

	return hash_val;
}

// Called from the PMD Thread
int
hash_ring_clone_get_mac(struct hash_ring_clone_t *clone, uint32_t key, uint8_t *mac)
{
	uint32_t i;

        if (clone == NULL)
        {
                return -2;
        }

        if (mac == NULL)
        {
                return -3;
        }

        if (clone->length == 0)
        {
                return -4;
        }

        for (i = 0; i < clone->length; i++)
        {
                if (key < clone->list[i].key)
                {
                        memcpy(mac, clone->list[i].mac, MAC_LEN);
                        return 0;
                }
        }
        memcpy(mac, clone->list[clone->length - 1].mac, MAC_LEN);
        return 0;
}
