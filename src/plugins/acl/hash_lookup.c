/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stddef.h>
#include <netinet/in.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include <vppinfra/bihash_48_8.h>

#include "hash_lookup.h"
#include "hash_lookup_private.h"
#include "mask_inlines.h"

#include "sax_pac.h"
#include "tuple_merge.h"
#include "tuple_space_search.h"


static void
hashtable_add_del(acl_main_t *am, clib_bihash_kv_48_8_t *kv, int is_add)
{
    DBG("HASH ADD/DEL: %016llx %016llx %016llx %016llx %016llx %016llx %016llx add %d",
                        kv->key[0], kv->key[1], kv->key[2],
                        kv->key[3], kv->key[4], kv->key[5], kv->value, is_add);
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, kv, is_add);
}



static void
fill_applied_hash_ace_kv(acl_main_t *am,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 lc_index,
                            u32 new_index, clib_bihash_kv_48_8_t *kv)
{
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv->key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv->value;
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

  /* apply the mask to ace key */
  hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
  ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, pae->mask_type_index);

  u64 *pmatch = (u64 *) &ace_info->match;
  u64 *pmask = (u64 *)&mte->mask;
  u64 *pkey = (u64 *)kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  kv_key->pkt.mask_type_index_lsb = pae->mask_type_index;
  kv_key->pkt.lc_index = lc_index;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = new_index;
}

static void
add_del_hashtable_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
			    u32 index, int is_add)
{
  clib_bihash_kv_48_8_t kv;

  fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, index, &kv);
  hashtable_add_del(am, &kv, is_add);
}


static void
remake_hash_applied_mask_info_vec (acl_main_t * am,
                                   applied_hash_ace_entry_t **
                                   applied_hash_aces, u32 lc_index)
{
  DBG0("remake applied hash mask info lc_index %d", lc_index);
  hash_applied_mask_info_t *new_hash_applied_mask_info_vec =
    vec_new (hash_applied_mask_info_t, 0);

  hash_applied_mask_info_t *minfo;
  int i;
  for (i = 0; i < vec_len ((*applied_hash_aces)); i++)
    {
      applied_hash_ace_entry_t *pae =
        vec_elt_at_index ((*applied_hash_aces), i);

      /* check if mask_type_index is already there */
      u32 new_pointer = vec_len (new_hash_applied_mask_info_vec);
      int search;
      for (search = 0; search < vec_len (new_hash_applied_mask_info_vec);
           search++)
        {
          minfo = vec_elt_at_index (new_hash_applied_mask_info_vec, search);
          if (minfo->mask_type_index == pae->mask_type_index)
            break;
        }
       
      vec_validate ((new_hash_applied_mask_info_vec), search);
      minfo = vec_elt_at_index ((new_hash_applied_mask_info_vec), search);
      if (search == new_pointer)
        {
          DBG0("remaking index %d", search);
          minfo->mask_type_index = pae->mask_type_index;
          minfo->num_entries = 0;
          minfo->max_collisions = 0;
          minfo->first_rule_index = ~0;
        }

      minfo->num_entries = minfo->num_entries + 1;

      if (vec_len (pae->colliding_rules) > minfo->max_collisions)
        minfo->max_collisions = vec_len (pae->colliding_rules);

      if (minfo->first_rule_index > i)
        minfo->first_rule_index = i;
    }

  vec_validate(am->hash_applied_mask_info_vec_by_lc_index, lc_index);
  hash_applied_mask_info_t **hash_applied_mask_info_vec =
    vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);

  vec_free ((*hash_applied_mask_info_vec));
  (*hash_applied_mask_info_vec) = new_hash_applied_mask_info_vec;
}

static void
vec_del_collision_rule (collision_match_rule_t ** pvec,
                        u32 applied_entry_index)
{
  u32 i = 0;
  u32 deleted = 0;
  while (i < _vec_len ((*pvec)))
    {
      collision_match_rule_t *cr = vec_elt_at_index ((*pvec), i);
      if (cr->applied_entry_index == applied_entry_index)
        {
          /* vec_del1 ((*pvec), i) would be more efficient but would reorder the elements. */
          vec_delete((*pvec), 1, i);
          deleted++;
          DBG0("vec_del_collision_rule deleting one at index %d", i);
        }
      else
        {
          i++;
        }
    }
  ASSERT(deleted > 0);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae);

static void
del_colliding_rule (applied_hash_ace_entry_t ** applied_hash_aces,
                    u32 head_index, u32 applied_entry_index)
{
  DBG0("DEL COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);


  applied_hash_ace_entry_t *head_pae =
    vec_elt_at_index ((*applied_hash_aces), head_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
  vec_del_collision_rule (&head_pae->colliding_rules, applied_entry_index);
  if (vec_len(head_pae->colliding_rules) == 0) {
    vec_free(head_pae->colliding_rules);
  }
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
}

static void
add_colliding_rule (acl_main_t * am,
                    applied_hash_ace_entry_t ** applied_hash_aces,
                    u32 head_index, u32 applied_entry_index)
{
  applied_hash_ace_entry_t *head_pae =
    vec_elt_at_index ((*applied_hash_aces), head_index);
  applied_hash_ace_entry_t *pae =
    vec_elt_at_index ((*applied_hash_aces), applied_entry_index);
  DBG0("ADD COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);

  collision_match_rule_t cr;

  cr.acl_index = pae->acl_index;
  cr.ace_index = pae->ace_index;
  cr.acl_position = pae->acl_position;
  cr.applied_entry_index = applied_entry_index;
  cr.rule = am->acls[pae->acl_index].rules[pae->ace_index];
  pae->collision_head_ae_index = head_index;
  vec_add1 (head_pae->colliding_rules, cr);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
}

u32
activate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 new_index)
{
  clib_bihash_kv_48_8_t kv;
  ASSERT(new_index != ~0);
  DBG("activate_applied_ace_hash_entry lc_index %d new_index %d", lc_index, new_index);

  fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, new_index, &kv);

  DBG("APPLY ADD KY: %016llx %016llx %016llx %016llx %016llx %016llx",
			kv.key[0], kv.key[1], kv.key[2],
			kv.key[3], kv.key[4], kv.key[5]);

  clib_bihash_kv_48_8_t result;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
  ASSERT(new_index != ~0);
  ASSERT(new_index < vec_len((*applied_hash_aces)));
  if (res == 0) {
    u32 first_index = result_val->applied_entry_index;
    ASSERT(first_index != ~0);
    ASSERT(first_index < vec_len((*applied_hash_aces)));
    /* There already exists an entry or more. Append at the end. */
    DBG("A key already exists, with applied entry index: %d", first_index);
    add_colliding_rule(am, applied_hash_aces, first_index, new_index);
    return first_index;
  } else {
    /* It's the very first entry */
    hashtable_add_del(am, &kv, 1);
    ASSERT(new_index != ~0);
    add_colliding_rule(am, applied_hash_aces, new_index, new_index);
    return new_index;
  }
}


static void *
hash_acl_set_heap(acl_main_t *am)
{
  if (0 == am->hash_lookup_mheap) {
    am->hash_lookup_mheap = mheap_alloc_with_lock (0 /* use VM */ , 
                                                   am->hash_lookup_mheap_size,
                                                   1 /* locked */);
    if (0 == am->hash_lookup_mheap) {
        clib_error("ACL plugin failed to allocate lookup heap of %U bytes", 
                   format_memory_size, am->hash_lookup_mheap_size);
    }
#if USE_DLMALLOC != 0
    /*
     * DLMALLOC is being "helpful" in that it ignores the heap size parameter
     * by default and tries to allocate the larger amount of memory.
     *
     * Pin the heap so this does not happen and if we run out of memory
     * in this heap, we will bail out with "out of memory", rather than
     * an obscure error sometime later.
     */
    mspace_disable_expand(am->hash_lookup_mheap);
#endif
  }
  void *oldheap = clib_mem_set_heap(am->hash_lookup_mheap);
  return oldheap;
}

void
acl_plugin_hash_acl_set_validate_heap(int on)
{
  acl_main_t *am = &acl_main;
  clib_mem_set_heap(hash_acl_set_heap(am));
#if USE_DLMALLOC == 0
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_VALIDATE;
    h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
    mheap_validate(h);
  } else {
    h->flags &= ~MHEAP_FLAG_VALIDATE;
    h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
  }
#endif
}

void
acl_plugin_hash_acl_set_trace_heap(int on)
{
  acl_main_t *am = &acl_main;
  clib_mem_set_heap(hash_acl_set_heap(am));
#if USE_DLMALLOC == 0
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_TRACE;
  } else {
    h->flags &= ~MHEAP_FLAG_TRACE;
  }
#endif
}



static int
add_acl_to_lc_links(acl_main_t *am, u32 lc_index, u32 *acls) {
    applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
    vec_validate((*applied_hash_acls), lc_index);
    applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

    for (uint i=0; i < vec_len(acls); i++) {
        u32 index = vec_search(pal->applied_acls, acls[i]);
        if (index != ~0) {
            clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to lc",
                         acls[i], lc_index);
            return 0;
        }
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acls[i]);
        u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

        u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
        if (index2 != ~0) {
            clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to hash h-acl info",
                         acls[i], lc_index);
            return 0;
        }
    }

    for (uint i = 0; i < vec_len(acls); i++) {
        vec_add1(pal->applied_acls, acls[i]);
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acls[i]);
        u32 **hash_acl_applied_lc_index = &ha->lc_index_list;
        vec_add1((*hash_acl_applied_lc_index), lc_index);
    }

    return 1;
}


static void
create_hash_aces(acl_main_t *am, int acl_index, u32 acl_position, applied_hash_ace_entry_t **applied_hash_aces)
{
    vec_validate(am->hash_acl_infos, acl_index);
    hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
    int base_offset = vec_len(*applied_hash_aces);
    if (vec_len(ha->rules) > 0) {
        vec_validate((*applied_hash_aces), base_offset + vec_len(ha->rules) - 1);
    }

    /* add the rules from the ACL to the hash table for lookup and append to the vector*/
    for(int i=0; i < vec_len(ha->rules); i++) {
        u32 new_index = base_offset + i;
        applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
        pae->acl_index = acl_index;
        pae->ace_index = ha->rules[i].ace_index;
        pae->acl_position = acl_position;
        pae->action = ha->rules[i].action;
        pae->hitcount = 0;
        pae->hash_ace_info_index = i;
        /* we might link it in later */
        pae->collision_head_ae_index = ~0;
        pae->colliding_rules = NULL;
        pae->mask_type_index = ~0;
    }
}

static void
assign_and_activate_mask_types(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, int offset, u32 lc_index) {
    INIT_TIMER
    switch (am->hash_lookup_constructing_algorithm) {
        case SAX_PAC :
            assign_sax_pac_mask_types(am, applied_hash_aces, offset, lc_index);
            break;
        case TUPLE_MERGE :
            assign_tm_mask_types(am, applied_hash_aces, offset, lc_index);
            break;
        default :
            assign_tss_mask_types(am,  applied_hash_aces, offset, lc_index);
    }
    STOP_TIMER("Running time of the mask assigning --")
}

static void
print_group_info(acl_main_t *am, u32 lc_index, applied_hash_ace_entry_t *applied_hash_aces) {
    hash_applied_mask_info_t *hash_applied_mask_info_vec =am->hash_applied_mask_info_vec_by_lc_index[lc_index];
    u32 len = vec_len(applied_hash_aces);
    int num_groups = 0, num_groups_in_95 = 0, avg = 0;
    for (int i = 0; i < vec_len(hash_applied_mask_info_vec); i++) {
        hash_applied_mask_info_t * vl = vec_elt_at_index(hash_applied_mask_info_vec, i);
        u32 add = 0;
        if (am->hash_lookup_constructing_algorithm == SAX_PAC) {
            add =  (vl->max_collisions + am->split_threshold - 1) / am -> split_threshold;
            avg += (len - vl->first_rule_index) * ((vl->max_collisions + am->split_threshold - 1) / am -> split_threshold);
        } else {
            add = 1;
            avg += (len - vl->first_rule_index);
        }

        clib_warning("Group info: first rule index - %d, max collisions - %d, num_entriess - %d",
                vl->first_rule_index, vl->max_collisions, vl->num_entries);

        num_groups += add;


        if (vl->first_rule_index < len * 0.95)  {
            num_groups_in_95 += add;
        }

    }

    clib_warning( "Number of groups : %d\n", num_groups);
    clib_warning( "Number of groups with rules in first 95%%: %d\n", num_groups_in_95);
    clib_warning( "Average number of groups under uniform distribution : %.2f\n", avg * 1.0 / len);

    int max_col = 3;
    for (u32 col = 1; col <= max_col + 1; col++) {
        u32 nrules  = 0;
        for (u32 i = 0; i <  vec_len(applied_hash_aces); i++) {
            int size = vec_len(applied_hash_aces[i].colliding_rules);
            if (col == max_col + 1 && size >= col) {
                nrules++;
            }
            if (col <= max_col && size == col) {
                nrules++;
            }
        }
        clib_warning("There is %d rules with colliding vector size %s %d", nrules, col == 4 ? ">=" : "=", col);
    }

    int avg_col = 0, num_col = 0, max_col_size = 0;

    for (u32 i = 0; i <  vec_len(applied_hash_aces); i++) {
        int size = vec_len(applied_hash_aces[i].colliding_rules);
        if (size) {
            avg_col += size;
            num_col++;
        }
        if (size > max_col_size) {
            max_col_size = size;
        }
    }

    clib_warning( "Maximum colliding vector size : %d\n", max_col_size);
    clib_warning( "Average colliding vector size : %.2f\n", 1.0*avg_col / num_col);
}


void
hash_acl_apply(acl_main_t *am, u32 lc_index,  u32* acls)
{
    void *oldheap = hash_acl_set_heap(am);
    if (!am->acl_lookup_hash_initialized) {
        BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                               am->hash_lookup_hash_buckets, am->hash_lookup_hash_memory);
        am->acl_lookup_hash_initialized = 1;
    }

    if (!add_acl_to_lc_links(am, lc_index, acls)) {
        goto done;
    }

    vec_validate(am->hash_entry_vec_by_lc_index, lc_index);
    applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
    u32 offset = vec_len(*applied_hash_aces);
    for(uint i = 0; i < vec_len(acls); i++)
        create_hash_aces(am,  acls[i], i, applied_hash_aces);


    assign_and_activate_mask_types(am, applied_hash_aces, offset, lc_index);
    remake_hash_applied_mask_info_vec(am, applied_hash_aces, lc_index);

    if (ACL_HASH_LOOKUP_DEBUG > 0)
        print_group_info(am, lc_index,*applied_hash_aces);

done:
    clib_mem_set_heap (oldheap);
}

static u32
find_head_applied_ace_index(applied_hash_ace_entry_t **applied_hash_aces, u32 curr_index)
{
  ASSERT(curr_index != ~0);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), curr_index);
  ASSERT(pae);
  ASSERT(pae->collision_head_ae_index != ~0);
  return pae->collision_head_ae_index;
}

static void
set_collision_head_ae_index(applied_hash_ace_entry_t **applied_hash_aces, collision_match_rule_t *colliding_rules, u32 new_index)
{
	collision_match_rule_t *cr;
	vec_foreach(cr, colliding_rules) {
            applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), cr->applied_entry_index);
            pae->collision_head_ae_index = new_index;
	}
}

static void
move_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index, u32 new_index)
{
  ASSERT(old_index != ~0);
  ASSERT(new_index != ~0);
  /* move the entry */
  *vec_elt_at_index((*applied_hash_aces), new_index) = *vec_elt_at_index((*applied_hash_aces), old_index);

  /* update the linkage and hash table if necessary */
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);
  applied_hash_ace_entry_t *new_pae = vec_elt_at_index((*applied_hash_aces), new_index);

  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("Moving pae from %d to %d", old_index, new_index);
    acl_plugin_print_pae(am->vlib_main, old_index, pae);
  }

  if (pae->collision_head_ae_index == old_index) {
    /* first entry - so the hash points to it, update */
    add_del_hashtable_entry(am, lc_index,
                            applied_hash_aces, new_index, 1);
  }
  if (new_pae->colliding_rules) {
    /* update the information within the collision rule entry */
    ASSERT(vec_len(new_pae->colliding_rules) > 0);
    collision_match_rule_t *cr = vec_elt_at_index (new_pae->colliding_rules, 0);
    ASSERT(cr->applied_entry_index == old_index);
    cr->applied_entry_index = new_index;
    set_collision_head_ae_index(applied_hash_aces, new_pae->colliding_rules, new_index);
  } else {
    /* find the index in the collision rule entry on the head element */
    u32 head_index = find_head_applied_ace_index(applied_hash_aces, new_index);
    ASSERT(head_index != ~0);
    applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);
    ASSERT(vec_len(head_pae->colliding_rules) > 0);
    u32 i;
    for (i=0; i<vec_len(head_pae->colliding_rules); i++) {
      collision_match_rule_t *cr = vec_elt_at_index (head_pae->colliding_rules, i);
      if (cr->applied_entry_index == old_index) {
        cr->applied_entry_index = new_index;
      }
    }
    if (ACL_HASH_LOOKUP_DEBUG > 0) {
      clib_warning("Head pae at index %d after adjustment", head_index);
      acl_plugin_print_pae(am->vlib_main, head_index, head_pae);
    }
  }
  /* invalidate the old entry */
  pae->collision_head_ae_index = ~0;
  pae->colliding_rules = NULL;
}

void
deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index)
{
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);
  DBG("UNAPPLY DEACTIVATE: lc_index %d applied index %d", lc_index, old_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("Deactivating pae at index %d", old_index);
    acl_plugin_print_pae(am->vlib_main, old_index, pae);
  }

  if (pae->collision_head_ae_index != old_index) {
    DBG("UNAPPLY = index %d has collision head %d", old_index, pae->collision_head_ae_index);

    u32 head_index = find_head_applied_ace_index(applied_hash_aces, old_index);
    ASSERT(head_index != ~0);
    del_colliding_rule(applied_hash_aces, head_index, old_index);

  } else {
    /* It was the first entry. We need either to reset the hash entry or delete it */
    /* delete our entry from the collision vector first */
    del_colliding_rule(applied_hash_aces, old_index, old_index);
    if (vec_len(pae->colliding_rules) > 0) {
      u32 next_pae_index = pae->colliding_rules[0].applied_entry_index;
      applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), next_pae_index);
      /* Remove ourselves and transfer the ownership of the colliding rules vector */
      next_pae->colliding_rules = pae->colliding_rules;
      set_collision_head_ae_index(applied_hash_aces, next_pae->colliding_rules, next_pae_index);
      add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, next_pae_index, 1);
    } else {
      /* no next entry, so just delete the entry in the hash table */
      add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, old_index, 0);
    }
  }
  DBG0("Releasing mask type index %d for pae index %d on lc_index %d", pae->mask_type_index, old_index, lc_index);
  release_mask_type_index(am, pae->mask_type_index);
  /* invalidate the old entry */
  pae->mask_type_index = ~0;
  pae->collision_head_ae_index = ~0;
  /* always has to be 0 */
  pae->colliding_rules = NULL;
}


void
hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  int i;

  DBG0("HASH ACL unapply: lc_index %d acl %d", lc_index, acl_index);
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("unapplying acl %d", acl_index);
    acl_plugin_show_tables_mask_type();
    acl_plugin_show_tables_acl_hash_info(acl_index);
    acl_plugin_show_tables_applied_info(lc_index);
  }

  /* remove this acl# from the list of applied hash acls */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index == ~0) {
    clib_warning("BUG: trying to unapply unapplied acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    return;
  }
  vec_del1(pal->applied_acls, index);

  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 == ~0) {
    clib_warning("BUG: trying to unapply twice acl_index %d on lc_index %d, according to h-acl info",
                 acl_index, lc_index);
    return;
  }
  vec_del1((*hash_acl_applied_lc_index), index2);

  applied_hash_ace_entry_t **applied_hash_aces =  vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);

  for(i=0; i < vec_len((*applied_hash_aces)); i++) {
    if (vec_elt_at_index(*applied_hash_aces,i)->acl_index == acl_index) {
      DBG("Found applied ACL#%d at applied index %d", acl_index, i);
      break;
    }
  }
  if (vec_len((*applied_hash_aces)) <= i) {
    DBG("Did not find applied ACL#%d at lc_index %d", acl_index, lc_index);
    /* we went all the way without finding any entries. Probably a list was empty. */
    return;
  }

  void *oldheap = hash_acl_set_heap(am);
  int base_offset = i;
  int tail_offset = base_offset + vec_len(ha->rules);
  int tail_len = vec_len((*applied_hash_aces)) - tail_offset;
  DBG("base_offset: %d, tail_offset: %d, tail_len: %d", base_offset, tail_offset, tail_len);

  for(i=0; i < vec_len(ha->rules); i ++) {
    deactivate_applied_ace_hash_entry(am, lc_index,
                                      applied_hash_aces, base_offset + i);
  }
  for(i=0; i < tail_len; i ++) {
    /* move the entry at tail offset to base offset */
    /* that is, from (tail_offset+i) -> (base_offset+i) */
    DBG0("UNAPPLY MOVE: lc_index %d, applied index %d -> %d", lc_index, tail_offset+i, base_offset + i);
    move_applied_ace_hash_entry(am, lc_index, applied_hash_aces, tail_offset + i, base_offset + i);
  }
  /* trim the end of the vector */
  _vec_len((*applied_hash_aces)) -= vec_len(ha->rules);

  remake_hash_applied_mask_info_vec(am, applied_hash_aces, lc_index);

  if (vec_len((*applied_hash_aces)) == 0) {
    vec_free((*applied_hash_aces));
  }

  clib_mem_set_heap (oldheap);
}

/*
 * Create the applied ACEs and update the hash table,
 * taking into account that the ACL may not be the last
 * in the vector of applied ACLs.
 *
 * For now, walk from the end of the vector and unapply the ACLs,
 * then apply the one in question and reapply the rest.
 */

void
hash_acl_reapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);
  u32 **applied_acls = &acontext->acl_indices;
  int i;
  int start_index = vec_search((*applied_acls), acl_index);

  DBG0("Start index for acl %d in lc_index %d is %d", acl_index, lc_index, start_index);
  /*
   * This function is called after we find out the lc_index where ACL is applied.
   * If the by-lc_index vector does not have the ACL#, then it's a bug.
   */
  ASSERT(start_index < vec_len(*applied_acls));

  /* unapply all the ACLs at the tail side, up to the current one */
  for(i = vec_len(*applied_acls) - 1; i > start_index; i--) {
    hash_acl_unapply(am, lc_index, *vec_elt_at_index(*applied_acls, i));
  }

  hash_acl_apply(am, lc_index, *applied_acls);
}

static void
make_port_mask(u16 *portmask, u16 port_first, u16 port_last)
{
  if (port_first == port_last) {
    *portmask = 0xffff;
    /* single port is representable by masked value */
    return;
  }

  *portmask = 0;
  return;
}

static void
make_mask_and_match_from_rule(fa_5tuple_t *mask, acl_rule_t *r, hash_ace_info_t *hi)
{
  clib_memset(mask, 0, sizeof(*mask));
  clib_memset(&hi->match, 0, sizeof(hi->match));
  hi->action = r->is_permit;

  /* we will need to be matching based on lc_index and mask_type_index when applied */
  mask->pkt.lc_index = ~0;
  /* we will assign the match of mask_type_index later when we find it*/
  mask->pkt.mask_type_index_lsb = ~0;

  mask->pkt.is_ip6 = 1;
  hi->match.pkt.is_ip6 = r->is_ipv6;

  fill_address_mask(mask, r->src_prefixlen, 0, r->is_ipv6);
  fill_address_mask(mask, r->dst_prefixlen, 1, r->is_ipv6);

  if (r->is_ipv6) {
    hi->match.ip6_addr[0] = r->src.ip6;
    hi->match.ip6_addr[1] = r->dst.ip6;
  } else {
    clib_memset(hi->match.l3_zero_pad, 0, sizeof(hi->match.l3_zero_pad));
    hi->match.ip4_addr[0] = r->src.ip4;
    hi->match.ip4_addr[1] = r->dst.ip4;
  }

  if (r->proto != 0) {
    mask->l4.proto = ~0; /* L4 proto needs to be matched */
    hi->match.l4.proto = r->proto;

    /* Calculate the src/dst port masks and make the src/dst port matches accordingly */
    make_port_mask(&mask->l4.port[0], r->src_port_or_type_first, r->src_port_or_type_last);
    hi->match.l4.port[0] = r->src_port_or_type_first & mask->l4.port[0];

    make_port_mask(&mask->l4.port[1], r->dst_port_or_code_first, r->dst_port_or_code_last);
    hi->match.l4.port[1] = r->dst_port_or_code_first & mask->l4.port[1];
    /* L4 info must be valid in order to match */
    mask->pkt.l4_valid = 1;
    hi->match.pkt.l4_valid = 1;
    /* And we must set the mask to check that it is an initial fragment */
    mask->pkt.is_nonfirst_fragment = 1;
    hi->match.pkt.is_nonfirst_fragment = 0;
    if ((r->proto == IPPROTO_TCP) && (r->tcp_flags_mask != 0)) {
      /* if we want to match on TCP flags, they must be masked off as well */
      mask->pkt.tcp_flags = r->tcp_flags_mask;
      hi->match.pkt.tcp_flags = r->tcp_flags_value;
      /* and the flags need to be present within the packet being matched */
      mask->pkt.tcp_flags_valid = 1;
      hi->match.pkt.tcp_flags_valid = 1;
    }
  }
  /* Sanitize the mask and the match */
  u64 *pmask = (u64 *)mask;
  u64 *pmatch = (u64 *)&hi->match;
  int j;
  for(j=0; j<6; j++) {
    pmatch[j] = pmatch[j] & pmask[j];
  }
}


int hash_acl_exists(acl_main_t *am, int acl_index)
{
  if (acl_index >= vec_len(am->hash_acl_infos))
    return 0;

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  return ha->hash_acl_exists;
}

void hash_acl_add(acl_main_t *am, int acl_index)
{
  void *oldheap = hash_acl_set_heap(am);
  DBG("HASH ACL add : %d", acl_index);
  int i;
  acl_rule_t *acl_rules = am->acls[acl_index].rules;
  vec_validate(am->hash_acl_infos, acl_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  clib_memset(ha, 0, sizeof(*ha));
  ha->hash_acl_exists = 1;

  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */

  /* avoid small requests by preallocating the entire vector before running the additions */
  if (vec_len(acl_rules) > 0) {
    vec_validate(ha->rules, vec_len(acl_rules)-1);
    vec_reset_length(ha->rules);
  }

  for(i=0; i < vec_len(acl_rules); i++) {
    hash_ace_info_t ace_info;
    fa_5tuple_t mask;
    clib_memset(&ace_info, 0, sizeof(ace_info));
    ace_info.acl_index = acl_index;
    ace_info.ace_index = i;

    make_mask_and_match_from_rule(&mask, &acl_rules[i], &ace_info);
    mask.pkt.flags_reserved = 0b000;
    ace_info.base_mask_type_index = assign_mask_type_index(am, &mask);
    /* assign the mask type index for matching itself */
    ace_info.match.pkt.mask_type_index_lsb = ace_info.base_mask_type_index;
    DBG("ACE: %d mask_type_index: %d", i, ace_info.base_mask_type_index);
    vec_add1(ha->rules, ace_info);
  }
  /*
   * if an ACL is applied somewhere, fill the corresponding lookup data structures.
   * We need to take care if the ACL is not the last one in the vector of ACLs applied to the interface.
   */
  if (acl_index < vec_len(am->lc_index_vec_by_acl)) {
    u32 *lc_index;
    vec_foreach(lc_index, am->lc_index_vec_by_acl[acl_index]) {
      hash_acl_reapply(am, *lc_index, acl_index);
    }
  }
  clib_mem_set_heap (oldheap);
}

void hash_acl_delete(acl_main_t *am, int acl_index)
{
  void *oldheap = hash_acl_set_heap(am);
  DBG0("HASH ACL delete : %d", acl_index);
  /*
   * If the ACL is applied somewhere, remove the references of it (call hash_acl_unapply)
   * this is a different behavior from the linear lookup where an empty ACL is "deny all",
   *
   * However, following vpp-dev discussion the ACL that is referenced elsewhere
   * should not be possible to delete, and the change adding this also adds
   * the safeguards to that respect, so this is not a problem.
   *
   * The part to remember is that this routine is called in process of reapplication
   * during the acl_add_replace() API call - the old acl ruleset is deleted, then
   * the new one is added, without the change in the applied ACLs - so this case
   * has to be handled.
   */
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 *lc_list_copy = 0;
  {
    u32 *lc_index;
    lc_list_copy = vec_dup(ha->lc_index_list);
    vec_foreach(lc_index, lc_list_copy) {
      hash_acl_unapply(am, *lc_index, acl_index);
    }
    vec_free(lc_list_copy);
  }
  vec_free(ha->lc_index_list);

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  int i;
  for(i=0; i < vec_len(ha->rules); i++) {
    release_mask_type_index(am, ha->rules[i].base_mask_type_index);
  }
  ha->hash_acl_exists = 0;
  vec_free(ha->rules);
  clib_mem_set_heap (oldheap);
}


void
show_hash_acl_hash (vlib_main_t * vm, acl_main_t *am, u32 verbose)
{
  vlib_cli_output(vm, "\nACL lookup hash table:\n%U\n",
                  BV (format_bihash), &am->acl_lookup_hash, verbose);
}

void
acl_plugin_show_tables_mask_type (void)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  ace_mask_type_entry_t *mte;

  vlib_cli_output (vm, "Mask-type entries:");
    /* *INDENT-OFF* */
    pool_foreach(mte, am->ace_mask_type_pool,
    ({
      vlib_cli_output(vm, "     %3d: %016llx %016llx %016llx %016llx %016llx %016llx  refcount %d",
		    mte - am->ace_mask_type_pool,
		    mte->mask.kv_40_8.key[0], mte->mask.kv_40_8.key[1], mte->mask.kv_40_8.key[2],
		    mte->mask.kv_40_8.key[3], mte->mask.kv_40_8.key[4], mte->mask.kv_40_8.value, mte->refcount);
    }));
    /* *INDENT-ON* */
}

void
acl_plugin_show_tables_acl_hash_info (u32 acl_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 i, j;
  u64 *m;
  vlib_cli_output (vm, "Mask-ready ACL representations\n");
  for (i = 0; i < vec_len (am->hash_acl_infos); i++)
    {
      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}
      hash_acl_info_t *ha = &am->hash_acl_infos[i];
      vlib_cli_output (vm, "acl-index %u bitmask-ready layout\n", i);
      vlib_cli_output (vm, "  applied lc_index list: %U\n",
		       format_vec32, ha->lc_index_list, "%d");
      for (j = 0; j < vec_len (ha->rules); j++)
	{
	  hash_ace_info_t *pa = &ha->rules[j];
	  m = (u64 *) & pa->match;
	  vlib_cli_output (vm,
			   "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx base mask index %d acl %d rule %d action %d\n",
			   j, m[0], m[1], m[2], m[3], m[4], m[5],
			   pa->base_mask_type_index, pa->acl_index, pa->ace_index,
			   pa->action);
	}
    }
}

static void
acl_plugin_print_colliding_rule (vlib_main_t * vm, int j, collision_match_rule_t *cr) {
  vlib_cli_output(vm,
                  "        %4d: acl %d ace %d acl pos %d pae index: %d",
                  j, cr->acl_index, cr->ace_index, cr->acl_position, cr->applied_entry_index);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae)
{
  vlib_cli_output (vm,
		   "    %4d: acl %d rule %d action %d bitmask-ready rule %d mask type index: %d colliding_rules: %d collision_head_ae_idx %d hitcount %lld acl_pos: %d",
		   j, pae->acl_index, pae->ace_index, pae->action,
		   pae->hash_ace_info_index, pae->mask_type_index, vec_len(pae->colliding_rules), pae->collision_head_ae_index,
		   pae->hitcount, pae->acl_position);
  int jj;
  for(jj=0; jj<vec_len(pae->colliding_rules); jj++)
    acl_plugin_print_colliding_rule(vm, jj, vec_elt_at_index(pae->colliding_rules, jj));
}

static void
acl_plugin_print_applied_mask_info (vlib_main_t * vm, int j, hash_applied_mask_info_t *mi)
{
  vlib_cli_output (vm,
		   "    %4d: mask type index %d first rule index %d num_entries %d max_collisions %d",
		   j, mi->mask_type_index, mi->first_rule_index, mi->num_entries, mi->max_collisions);
}

void
acl_plugin_show_tables_applied_info (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 lci, j;
  vlib_cli_output (vm, "Applied lookup entries for lookup contexts");

  for (lci = 0;
       (lci < vec_len(am->applied_hash_acl_info_by_lc_index)); lci++)
    {
      if ((lc_index != ~0) && (lc_index != lci))
	{
	  continue;
	}
      vlib_cli_output (vm, "lc_index %d:", lci);
      if (lci < vec_len (am->applied_hash_acl_info_by_lc_index))
	{
	  applied_hash_acl_info_t *pal =
	    &am->applied_hash_acl_info_by_lc_index[lci];
	  vlib_cli_output (vm, "  applied acls: %U", format_vec32,
			   pal->applied_acls, "%d");
	}
      if (lci < vec_len (am->hash_applied_mask_info_vec_by_lc_index))
	{
	  vlib_cli_output (vm, "  applied mask info entries:");
	  for (j = 0;
	       j < vec_len (am->hash_applied_mask_info_vec_by_lc_index[lci]);
	       j++)
	    {
	      acl_plugin_print_applied_mask_info (vm, j,
				    &am->hash_applied_mask_info_vec_by_lc_index
				    [lci][j]);
	    }
	}
      if (lci < vec_len (am->hash_entry_vec_by_lc_index))
	{
	  vlib_cli_output (vm, "  lookup applied entries:");
	  for (j = 0;
	       j < vec_len (am->hash_entry_vec_by_lc_index[lci]);
	       j++)
	    {
	      acl_plugin_print_pae (vm, j,
				    &am->hash_entry_vec_by_lc_index
				    [lci][j]);
	    }
	}
    }
}

void
acl_plugin_show_tables_bihash (u32 show_bihash_verbose)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  show_hash_acl_hash (vm, am, show_bihash_verbose);
}
