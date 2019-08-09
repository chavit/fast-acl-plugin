/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef mask_inlines_h
#define mask_inlines_h

#include <stdint.h>

#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <plugins/acl/hash_lookup_private.h>
#include <plugins/acl/exported_types.h>

always_inline u32
find_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
    ace_mask_type_entry_t *mte;
    /* *INDENT-OFF* */
    pool_foreach(mte, am->ace_mask_type_pool,
                 ({
                     if(memcmp(&mte->mask, mask, sizeof(*mask)) == 0)
                         return (mte - am->ace_mask_type_pool);
                 }));
    /* *INDENT-ON* */
    return ~0;
}

always_inline u32
assign_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
    u32 mask_type_index = find_mask_type_index(am, mask);
    ace_mask_type_entry_t *mte;
    if(~0 == mask_type_index) {
        pool_get_aligned (am->ace_mask_type_pool, mte, CLIB_CACHE_LINE_BYTES);
        mask_type_index = mte - am->ace_mask_type_pool;
        clib_memcpy_fast(&mte->mask, mask, sizeof(mte->mask));
        mte->refcount = 0;

        /*
         * We can use only 16 bits, since in the match there is only u16 field.
         * Realistically, once you go to 64K of mask types, it is a huge
         * problem anyway, so we might as well stop half way.
         */
        ASSERT(mask_type_index < 32768);
    }
    mte = am->ace_mask_type_pool + mask_type_index;
    mte->refcount++;
    DBG0("ASSIGN MTE index %d new refcount %d", mask_type_index, mte->refcount);
    return mask_type_index;
}

always_inline void
lock_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
    DBG0("LOCK MTE index %d", mask_type_index);
    ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
    mte->refcount++;
    DBG0("LOCK MTE index %d new refcount %d", mask_type_index, mte->refcount);
}

always_inline void
release_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
    DBG0("RELEAS MTE index %d", mask_type_index);
    ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
    mte->refcount--;
    DBG0("RELEAS MTE index %d new refcount %d", mask_type_index, mte->refcount);
    if (mte->refcount == 0) {
        /* we are not using this entry anymore */
        clib_memset(mte, 0xae, sizeof(*mte));
        pool_put(am->ace_mask_type_pool, mte);
    }
}

/* check if mask2 can be contained by mask1 */
always_inline u8
first_mask_contains_second_mask(int is_ip6, fa_5tuple_t * mask1, fa_5tuple_t * mask2)
{
    int i;
    if (is_ip6)
    {
        for (i = 0; i < 2; i++)
        {
            if ((mask1->ip6_addr[0].as_u64[i] & mask2->ip6_addr[0].as_u64[i]) !=
                mask1->ip6_addr[0].as_u64[i])
                return 0;
            if ((mask1->ip6_addr[1].as_u64[i] & mask2->ip6_addr[1].as_u64[i]) !=
                mask1->ip6_addr[1].as_u64[i])
                return 0;
        }
    }
    else
    {
        /* check the pads, both masks must have it 0 */
        u32 padcheck = 0;
        int i;
        for (i=0; i<6; i++) {
            padcheck |= mask1->l3_zero_pad[i];
            padcheck |= mask2->l3_zero_pad[i];
        }
        if (padcheck != 0)
            return 0;
        if ((mask1->ip4_addr[0].as_u32 & mask2->ip4_addr[0].as_u32) !=
            mask1->ip4_addr[0].as_u32)
            return 0;
        if ((mask1->ip4_addr[1].as_u32 & mask2->ip4_addr[1].as_u32) !=
            mask1->ip4_addr[1].as_u32)
            return 0;
    }

    /* take care if port are not exact-match  */
    if ((mask1->l4.as_u64 & mask2->l4.as_u64) != mask1->l4.as_u64)
        return 0;

    if ((mask1->pkt.as_u64 & mask2->pkt.as_u64) != mask1->pkt.as_u64)
        return 0;

    return 1;
}

always_inline void
ip4_address_mask_from_width (ip4_address_t * a, u32 width)
{
    int i, byte, bit, bitnum;
    ASSERT (width <= 32);
    clib_memset (a, 0, sizeof (a[0]));
    for (i = 0; i < width; i++)
    {
        bitnum = (7 - (i & 7));
        byte = i / 8;
        bit = 1 << bitnum;
        a->as_u8[byte] |= bit;
    }
}

always_inline void
fill_address_mask(fa_5tuple_t* mask, u8 prefix_len, int index, int is_ip6)
{
    if (is_ip6) {
        ip6_address_mask_from_width(&mask->ip6_addr[index], prefix_len);
    } else {
        ip4_address_mask_from_width(&mask->ip4_addr[index], prefix_len);
    }
}

#endif
