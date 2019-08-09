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
 *
 * TupleMerge
 *
 * Initial adaptation by Valerio Bruschi (valerio.bruschi@telecom-paristech.fr)
 * based on the TupleMerge [1] simulator kindly made available
 * by  James Daly (dalyjamese@gmail.com) and  Eric Torng (torng@cse.msu.edu)
 * ( http://www.cse.msu.edu/~dalyjame/ or http://www.cse.msu.edu/~torng/ ),
 * refactoring by Andrew Yourtchenko.
 *
 * [1] James Daly, Eric Torng "TupleMerge: Building Online Packet Classifiers
 * by Omitting Bits", In Proc. IEEE ICCCN 2017, pp. 1-10
 *
 */


#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <vlib/unix/plugin.h>
#include <plugins/acl/public_inlines.h>
#include "hash_lookup.h"
#include "elog_acl_trace.h"
#include <vppinfra/bihash_48_8.h>
#include "tuple_merge.h"
#include "mask_inlines.h"

/*
 * TupleMerge:
 *
 * Consider the situation when we have to create a new table
 * T for a given rule R. This occurs for the first rule inserted and
 * for later rules if it is incompatible with all existing tables.
 * In this event, we need to determine mT for a new table.
 * Setting mT = mR is not a good strategy; if another similar,
 * but slightly less specific, rule appears we will be unable to
 * add it to T and will thus have to create another new table. We
 * thus consider two factors: is the rule more strongly aligned
 * with source or destination addresses (usually the two most
 * important fields) and how much slack needs to be given to
 * allow for other rules. If the source and destination addresses
 * are close together (within 4 bits for our experiments), we use
 * both of them. Otherwise, we drop the smaller (less specific)
 * address and its associated port field from consideration; R is
 * predominantly aligned with one of the two fields and should
 * be grouped with other similar rules. This is similar to TSS
 * dropping port fields, but since it is based on observable rule
 * characteristics it is more likely to keep important fields and
 * discard less useful ones.
 * We then look at the absolute lengths of the addresses. If
 * the address is long, we are more likely to try to add shorter
 * lengths and likewise the reverse. We thus remove a few bits
 * from both address fields with more bits removed from longer
 * addresses. For 32 bit addresses, we remove 4 bits, 3 for more
 * than 24, 2 for more than 16, and so on (so 8 and fewer bits
 * don’t have any removed). We only do this for prefix fields like
 * addresses; both range fields (like ports) and exact match fields
 * (like protocol) should remain as they are.
 */

static int
count_bits (u64 word)
{
    int counter = 0;
    while (word)
    {
        counter += word & 1;
        word >>= 1;
    }
    return counter;
}

static u32
shift_ip4_if(u32 mask, u32 thresh, int numshifts, u32 else_val)
{
    if (mask > thresh)
        return clib_host_to_net_u32((clib_net_to_host_u32(mask) << numshifts) & 0xFFFFFFFF);
    else
        return else_val;
}

static void
relax_ip4_addr(ip4_address_t *ip4_mask, int relax2) {
    int shifts_per_relax[2][4] = { { 6, 5, 4, 2 }, { 3, 2, 1, 1 } };

    int *shifts = shifts_per_relax[relax2];
    if(ip4_mask->as_u32 == 0xffffffff)
        ip4_mask->as_u32 = clib_host_to_net_u32((clib_net_to_host_u32(ip4_mask->as_u32) << shifts[0])&0xFFFFFFFF);
    else
        ip4_mask->as_u32 = shift_ip4_if(ip4_mask->as_u32, 0xffffff00, shifts[1],
                                        shift_ip4_if(ip4_mask->as_u32, 0xffff0000, shifts[2],
                                                     shift_ip4_if(ip4_mask->as_u32, 0xff000000, shifts[3], ip4_mask->as_u32)));
}

static void
relax_ip6_addr(ip6_address_t *ip6_mask, int relax2) {
    /*
     * This "better than nothing" relax logic is based on heuristics
     * from IPv6 knowledge, and may not be optimal.
     * Some further tuning may be needed in the future.
     */
    if (ip6_mask->as_u64[0] == 0xffffffffffffffffULL) {
        if (ip6_mask->as_u64[1] == 0xffffffffffffffffULL) {
            /* relax a /128 down to /64  - likely to have more hosts */
            ip6_mask->as_u64[1] = 0;
        } else if (ip6_mask->as_u64[1] == 0) {
            /* relax a /64 down to /56 - likely to have more subnets */
            ip6_mask->as_u64[0] = clib_host_to_net_u64(0xffffffffffffff00ULL);
        }
    }
}


static void
relax_tuple(fa_5tuple_t *mask, int is_ip6, int relax2){
    fa_5tuple_t save_mask = *mask;

    int counter_s = 0, counter_d = 0;
    if (is_ip6) {
        int i;
        for(i=0; i<2; i++){
            counter_s += count_bits(mask->ip6_addr[0].as_u64[i]);
            counter_d += count_bits(mask->ip6_addr[1].as_u64[i]);
        }
    } else {
        counter_s += count_bits(mask->ip4_addr[0].as_u32);
        counter_d += count_bits(mask->ip4_addr[1].as_u32);
    }

/*
 * is the rule more strongly aligned with source or destination addresses
 * (usually the two most important fields) and how much slack needs to be
 * given to allow for other rules. If the source and destination addresses
 * are close together (within 4 bits for our experiments), we use both of them.
 * Otherwise, we drop the smaller (less specific) address and its associated
 * port field from consideration
 */
    const int deltaThreshold = 4;
    /* const int deltaThreshold = 8; if IPV6? */
    int delta = counter_s - counter_d;
    if (-delta > deltaThreshold) {
        if (is_ip6)
            mask->ip6_addr[0].as_u64[1] = mask->ip6_addr[0].as_u64[0] = 0;
        else
            mask->ip4_addr[0].as_u32 = 0;
        mask->l4.port[0] = 0;
    } else if (delta > deltaThreshold) {
        if (is_ip6)
            mask->ip6_addr[1].as_u64[1] = mask->ip6_addr[1].as_u64[0] = 0;
        else
            mask->ip4_addr[1].as_u32 = 0;
        mask->l4.port[1] = 0;
    }

    if (is_ip6) {
        relax_ip6_addr(&mask->ip6_addr[0], relax2);
        relax_ip6_addr(&mask->ip6_addr[1], relax2);
    } else {
        relax_ip4_addr(&mask->ip4_addr[0], relax2);
        relax_ip4_addr(&mask->ip4_addr[1], relax2);
    }
    mask->pkt.is_nonfirst_fragment = 0;
    mask->pkt.l4_valid = 0;
    if(!first_mask_contains_second_mask(is_ip6, mask, &save_mask)){
        DBG( "TM-relaxing-ERROR");
        *mask = save_mask;
    }
    DBG( "TM-relaxing-end");
}



static u32 get_covering_mask_type_index(acl_main_t *am, u32 lc_index, fa_5tuple_t *mask, int is_ip6) {
    vec_validate(am->hash_applied_mask_info_vec_by_lc_index, lc_index);
    hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(am->hash_applied_mask_info_vec_by_lc_index, lc_index);
    hash_applied_mask_info_t *minfo;
    u32 mask_type_index = ~0;
    ace_mask_type_entry_t *mte = 0;
    for (int order_index = vec_len((*hash_applied_mask_info_vec)) - 1; order_index >= 0; order_index--) {
        minfo = vec_elt_at_index((*hash_applied_mask_info_vec), order_index);
        mte = vec_elt_at_index(am->ace_mask_type_pool, minfo->mask_type_index);
        if (first_mask_contains_second_mask(is_ip6, &mte->mask, mask)) {
            mask_type_index = (mte - am->ace_mask_type_pool);
            break;
        }
    }
    return mask_type_index;
}


static void
split_partition(acl_main_t *am, u32 first_index, u32 lc_index, int is_ip6);


void
check_collision_count_and_maybe_split(acl_main_t *am, u32 lc_index, int is_ip6, u32 first_index)
{
    applied_hash_ace_entry_t **applied_hash_aces =  vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
    applied_hash_ace_entry_t *first_pae = vec_elt_at_index((*applied_hash_aces), first_index);
    if (vec_len(first_pae->colliding_rules) > am->split_threshold) {
        split_partition(am, first_index, lc_index, is_ip6);
    }
}

void assign_tm_mask_types(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, int offset, u32 lc_index) {
    ace_mask_type_entry_t *mte;
    fa_5tuple_t *mask;
    hash_applied_mask_info_t *minfo;

    for (int i = offset; i < vec_len(*applied_hash_aces); i++) {
        applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), i);
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
        hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
        mask = &mte->mask;
        int is_ip6 = ace_info->match.pkt.is_ip6;

        u32 mask_type_index = get_covering_mask_type_index(am, lc_index, mask, is_ip6);

        if (mask_type_index == ~0) {
            /* if no mask is found, then let's use a relaxed version of the original one, in order to be used by new ace_entries */
            DBG("TM-assigning mask type index-new one");
            fa_5tuple_t relaxed_mask = *mask;
            relax_tuple(&relaxed_mask, is_ip6, 0);
            mask_type_index = assign_mask_type_index(am, &relaxed_mask);

            hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(
                    am->hash_applied_mask_info_vec_by_lc_index, lc_index);


            int spot = vec_len((*hash_applied_mask_info_vec));
            vec_validate((*hash_applied_mask_info_vec), spot);
            minfo = vec_elt_at_index((*hash_applied_mask_info_vec), spot);
            minfo->mask_type_index = mask_type_index;

            /*
             * We can use only 16 bits, since in the match there is only u16 field.
             * Realistically, once you go to 64K of mask types, it is a huge
             * problem anyway, so we might as well stop half way.
             */
            ASSERT(mask_type_index < 32768);
        } else {
            lock_mask_type_index(am, mask_type_index);
        }
        pae->mask_type_index = mask_type_index;
        u32 first_index = activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, i);
        check_collision_count_and_maybe_split(am, lc_index, is_ip6, first_index);
    }
}



/*
 * Split of the partition needs to happen when the collision count
 * goes over a specified threshold.
 *
 * This is a signal that we ignored too many bits in
 * mT and we need to split the table into two tables. We select
 * all of the colliding rules L and find their maximum common
 * tuple mL. Normally mL is specific enough to hash L with few
 * or no collisions. We then create a new table T2 with tuple mL
 * and transfer all compatible rules from T to T2. If mL is not
 * specific enough, we find the field with the biggest difference
 * between the minimum and maximum tuple lengths for all of
 * the rules in L and set that field to be the average of those two
 * values. We then transfer all compatible rules as before. This
 * guarantees that some rules from L will move and that T2 will
 * have a smaller number of collisions than T did.
 */


static void
ensure_ip6_min_addr (ip6_address_t * min_addr, ip6_address_t * mask_addr)
{
    int update =
            (clib_net_to_host_u64 (mask_addr->as_u64[0]) <
             clib_net_to_host_u64 (min_addr->as_u64[0]))
            ||
            ((clib_net_to_host_u64 (mask_addr->as_u64[0]) ==
              clib_net_to_host_u64 (min_addr->as_u64[0]))
             && (clib_net_to_host_u64 (mask_addr->as_u64[1]) <
                 clib_net_to_host_u64 (min_addr->as_u64[1])));
    if (update)
    {
        min_addr->as_u64[0] = mask_addr->as_u64[0];
        min_addr->as_u64[1] = mask_addr->as_u64[1];
    }
}

static void
ensure_ip6_max_addr (ip6_address_t * max_addr, ip6_address_t * mask_addr)
{
    int update =
            (clib_net_to_host_u64 (mask_addr->as_u64[0]) >
             clib_net_to_host_u64 (max_addr->as_u64[0]))
            ||
            ((clib_net_to_host_u64 (mask_addr->as_u64[0]) ==
              clib_net_to_host_u64 (max_addr->as_u64[0]))
             && (clib_net_to_host_u64 (mask_addr->as_u64[1]) >
                 clib_net_to_host_u64 (max_addr->as_u64[1])));
    if (update)
    {
        max_addr->as_u64[0] = mask_addr->as_u64[0];
        max_addr->as_u64[1] = mask_addr->as_u64[1];
    }
}

static void
ensure_ip4_min_addr (ip4_address_t * min_addr, ip4_address_t * mask_addr)
{
    int update =
            (clib_net_to_host_u32 (mask_addr->as_u32) <
             clib_net_to_host_u32 (min_addr->as_u32));
    if (update)
        min_addr->as_u32 = mask_addr->as_u32;
}

static void
ensure_ip4_max_addr (ip4_address_t * max_addr, ip4_address_t * mask_addr)
{
    int update =
            (clib_net_to_host_u32 (mask_addr->as_u32) >
             clib_net_to_host_u32 (max_addr->as_u32));
    if (update)
        max_addr->as_u32 = mask_addr->as_u32;
}

enum {
    DIM_SRC_ADDR = 0,
    DIM_DST_ADDR,
    DIM_SRC_PORT,
    DIM_DST_PORT,
    DIM_PROTO,
};

static void
split_partition(acl_main_t *am, u32 first_index,
                u32 lc_index, int is_ip6){
    DBG( "TM-split_partition - first_entry:%d", first_index);
    applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
    ace_mask_type_entry_t *mte;
    fa_5tuple_t the_min_tuple, *min_tuple = &the_min_tuple;
    fa_5tuple_t the_max_tuple, *max_tuple = &the_max_tuple;
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), first_index);
    hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
    hash_ace_info_t *ace_info;
    u32 coll_mask_type_index = pae->mask_type_index;
    clib_memset(&the_min_tuple, 0, sizeof(the_min_tuple));
    clib_memset(&the_max_tuple, 0, sizeof(the_max_tuple));

    int i=0;
    collision_match_rule_t *colliding_rules = pae->colliding_rules;
    u64 collisions = vec_len(pae->colliding_rules);
    for(i=0; i<collisions; i++){
        /* reload the hash acl info as it might be a different ACL# */
        pae = vec_elt_at_index((*applied_hash_aces), colliding_rules[i].applied_entry_index);
        ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

        DBG( "TM-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)",
             pae->ace_index, pae->mask_type_index, coll_mask_type_index);

        ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
        fa_5tuple_t *mask = &mte->mask;

        if(pae->mask_type_index != coll_mask_type_index) continue;
        /* Computing min_mask and max_mask for colliding rules */
        if(i==0){
            clib_memcpy_fast(min_tuple, mask, sizeof(fa_5tuple_t));
            clib_memcpy_fast(max_tuple, mask, sizeof(fa_5tuple_t));
        }else{
            int j;
            for(j=0; j<2; j++){
                if (is_ip6)
                    ensure_ip6_min_addr(&min_tuple->ip6_addr[j], &mask->ip6_addr[j]);
                else
                    ensure_ip4_min_addr(&min_tuple->ip4_addr[j], &mask->ip4_addr[j]);

                if ((mask->l4.port[j] < min_tuple->l4.port[j]))
                    min_tuple->l4.port[j] = mask->l4.port[j];
            }

            if ((mask->l4.proto < min_tuple->l4.proto))
                min_tuple->l4.proto = mask->l4.proto;

            if(mask->pkt.as_u64 < min_tuple->pkt.as_u64)
                min_tuple->pkt.as_u64 = mask->pkt.as_u64;


            for(j=0; j<2; j++){
                if (is_ip6)
                    ensure_ip6_max_addr(&max_tuple->ip6_addr[j], &mask->ip6_addr[j]);
                else
                    ensure_ip4_max_addr(&max_tuple->ip4_addr[j], &mask->ip4_addr[j]);

                if ((mask->l4.port[j] > max_tuple->l4.port[j]))
                    max_tuple->l4.port[j] = mask->l4.port[j];
            }

            if ((mask->l4.proto < max_tuple->l4.proto))
                max_tuple->l4.proto = mask->l4.proto;

            if(mask->pkt.as_u64 > max_tuple->pkt.as_u64)
                max_tuple->pkt.as_u64 = mask->pkt.as_u64;
        }
    }

    /* Computing field with max difference between (min/max)_mask */
    int best_dim=-1, best_delta=0, delta=0;

    /* SRC_addr dimension */
    if (is_ip6) {
        int i;
        for(i=0; i<2; i++){
            delta += count_bits(max_tuple->ip6_addr[0].as_u64[i]) - count_bits(min_tuple->ip6_addr[0].as_u64[i]);
        }
    } else {
        delta += count_bits(max_tuple->ip4_addr[0].as_u32) - count_bits(min_tuple->ip4_addr[0].as_u32);
    }
    if(delta > best_delta){
        best_delta = delta;
        best_dim = DIM_SRC_ADDR;
    }

    /* DST_addr dimension */
    delta = 0;
    if (is_ip6) {
        int i;
        for(i=0; i<2; i++){
            delta += count_bits(max_tuple->ip6_addr[1].as_u64[i]) - count_bits(min_tuple->ip6_addr[1].as_u64[i]);
        }
    } else {
        delta += count_bits(max_tuple->ip4_addr[1].as_u32) - count_bits(min_tuple->ip4_addr[1].as_u32);
    }
    if(delta > best_delta){
        best_delta = delta;
        best_dim = DIM_DST_ADDR;
    }

    /* SRC_port dimension */
    delta = count_bits(max_tuple->l4.port[0]) - count_bits(min_tuple->l4.port[0]);
    if(delta > best_delta){
        best_delta = delta;
        best_dim = DIM_SRC_PORT;
    }

    /* DST_port dimension */
    delta = count_bits(max_tuple->l4.port[1]) - count_bits(min_tuple->l4.port[1]);
    if(delta > best_delta){
        best_delta = delta;
        best_dim = DIM_DST_PORT;
    }

    /* Proto dimension */
    delta = count_bits(max_tuple->l4.proto) - count_bits(min_tuple->l4.proto);
    if(delta > best_delta){
        best_delta = delta;
        best_dim = DIM_PROTO;
    }

    int shifting = 0; //, ipv4_block = 0;
    switch(best_dim){
        case DIM_SRC_ADDR:
            shifting = (best_delta)/2; // FIXME IPV4-only
            // ipv4_block = count_bits(max_tuple->ip4_addr[0].as_u32);
            min_tuple->ip4_addr[0].as_u32 =
                    clib_host_to_net_u32((clib_net_to_host_u32(max_tuple->ip4_addr[0].as_u32) << (shifting))&0xFFFFFFFF);

            break;
        case DIM_DST_ADDR:
            shifting = (best_delta)/2;
/*
			ipv4_block = count_bits(max_tuple->addr[1].as_u64[1]);
			if(ipv4_block > shifting)
				min_tuple->addr[1].as_u64[1] =
					clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[1].as_u64[1]) << (shifting))&0xFFFFFFFF);
			else{
				shifting = shifting - ipv4_block;
				min_tuple->addr[1].as_u64[1] = 0;
				min_tuple->addr[1].as_u64[0] =
					clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[1].as_u64[0]) << (shifting))&0xFFFFFFFF);
			}
*/
            min_tuple->ip4_addr[1].as_u32 =
                    clib_host_to_net_u32((clib_net_to_host_u32(max_tuple->ip4_addr[1].as_u32) << (shifting))&0xFFFFFFFF);

            break;
        case DIM_SRC_PORT: min_tuple->l4.port[0] = max_tuple->l4.port[0]  << (best_delta)/2;
            break;
        case DIM_DST_PORT: min_tuple->l4.port[1] = max_tuple->l4.port[1] << (best_delta)/2;
            break;
        case DIM_PROTO: min_tuple->l4.proto = max_tuple->l4.proto << (best_delta)/2;
            break;
        default: relax_tuple(min_tuple, is_ip6, 1);
            break;
    }

    min_tuple->pkt.is_nonfirst_fragment = 0;
    u32 new_mask_type_index = assign_mask_type_index(am, min_tuple);

    hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(am->hash_applied_mask_info_vec_by_lc_index, lc_index);

    hash_applied_mask_info_t *minfo;
    //search in order pool if mask_type_index is already there
    int search;
    for (search=0; search < vec_len((*hash_applied_mask_info_vec)); search++){
        minfo = vec_elt_at_index((*hash_applied_mask_info_vec), search);
        if(minfo->mask_type_index == new_mask_type_index)
            break;
    }

    vec_validate((*hash_applied_mask_info_vec), search);
    minfo = vec_elt_at_index((*hash_applied_mask_info_vec), search);
    minfo->mask_type_index = new_mask_type_index;
    minfo->num_entries = 0;
    minfo->max_collisions = 0;
    minfo->first_rule_index = ~0;

    DBG( "TM-split_partition - mask type index-assigned!! -> %d", new_mask_type_index);

    if(coll_mask_type_index == new_mask_type_index){
        //vlib_cli_output(vm, "TM-There are collisions over threshold, but i'm not able to split! %d %d", coll_mask_type_index, new_mask_type_index);
        return;
    }


    /* populate new partition */
    DBG( "TM-Populate new partition");
    u32 r_ace_index = first_index;
    int repopulate_count = 0;

    collision_match_rule_t *temp_colliding_rules = vec_dup(colliding_rules);
    collisions = vec_len(temp_colliding_rules);

    for(i=0; i<collisions; i++){

        r_ace_index = temp_colliding_rules[i].applied_entry_index;

        applied_hash_ace_entry_t *pop_pae = vec_elt_at_index((*applied_hash_aces), r_ace_index);
        ha = vec_elt_at_index(am->hash_acl_infos, pop_pae->acl_index);
        DBG( "TM-Population-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)",
             pop_pae->ace_index, pop_pae->mask_type_index, coll_mask_type_index);

        ASSERT(pop_pae->mask_type_index == coll_mask_type_index);

        ace_info = vec_elt_at_index(ha->rules, pop_pae->hash_ace_info_index);
        mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
        //can insert rule?
        //mte = vec_elt_at_index(am->ace_mask_type_pool, pop_pae->mask_type_index);
        fa_5tuple_t *pop_mask = &mte->mask;

        if(!first_mask_contains_second_mask(is_ip6, min_tuple, pop_mask)) continue;
        DBG( "TM-new partition can insert -> applied_ace:%d", r_ace_index);

        //delete and insert in new format
        deactivate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index);

        /* insert the new entry */
        pop_pae->mask_type_index = new_mask_type_index;
        /* The very first repopulation gets the lock by virtue of a new mask being created above */
        if (++repopulate_count > 1)
            lock_mask_type_index(am, new_mask_type_index);

        activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index);

    }
    vec_free(temp_colliding_rules);

    DBG( "TM-Populate new partition-END");
    DBG( "TM-split_partition - END");

}
