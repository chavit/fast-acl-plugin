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

#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <vlib/unix/plugin.h>
#include <plugins/acl/public_inlines.h>
#include "hash_lookup.h"
#include "elog_acl_trace.h"
#include <vppinfra/bihash_48_8.h>
#include "sax_pac.h"
#include "mask_inlines.h"

#define USE_FAST_SAX_PAC 1

/* filter out all ace entries whose masks do not include sax-pax group mask */
static void sax_pac_filter_non_mask_including(acl_main_t *am, applied_hash_ace_entry_t **from, applied_hash_ace_entry_t **to, fa_5tuple_t* mask, int is_ip6) {
    fa_5tuple_t *rule_mask;
    vec_validate(to, vec_len(from)-1);
    int l = 0;
    for (int i = 0; i < vec_len(from); i++) {
        applied_hash_ace_entry_t *pae = from[i];
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
        hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        rule_mask = &vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index)->mask;
        if (!first_mask_contains_second_mask(is_ip6, mask, rule_mask)) {
            continue;
        }
        to[l++] = pae;
    }
    _vec_len(to) = l;
}

/* construct mask for sax-pac group */
static void make_sax_pac_mask(fa_5tuple_t* mask, int src_len, int dst_len, int is_proto, int is_src_port, int is_dst_port,
                               int is_ip6) {
    clib_memset(mask, 0, sizeof(*mask));
    fill_address_mask(mask, src_len, 0, is_ip6);
    fill_address_mask(mask, dst_len, 1, is_ip6);
    if (is_proto) {
        mask->l4.proto = ~0;
    }
    if (is_src_port) {
        mask->l4.port[0] = ~0;
    }
    if (is_dst_port) {
        mask->l4.port[1] = ~0;
    }
}

/* construct a single group
 * masks of all aces in applied_hash_ace_entry should contain sax-pac group mask
 * result is a size of selected sax-pac group
 * all aces in the selected group are appended to array *taken
 * if taken == NULL then only the size of group is calculated*/
static u32 calculate_size_of_sax_pac_group(acl_main_t *am, u32 coll_rate, applied_hash_ace_entry_t **applied_hash_aces, fa_5tuple_t* mask, applied_hash_ace_entry_t*** taken) {
    u32 ans = 0;
    u32 len = vec_len(applied_hash_aces);

    if (!len) {
        return 0;
    }

    clib_bihash_48_8_t group_cand;
    clib_memset (&group_cand, 0, sizeof (group_cand));
    clib_bihash_init_48_8(&group_cand, "SAX-PAC", len/BIHASH_KVP_PER_PAGE+1, 3*(len+10)* sizeof(clib_bihash_kv_48_8_t));
    for (int i = 0; i < len; i++) {
        applied_hash_ace_entry_t *pae = applied_hash_aces[i];
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
        hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        clib_bihash_kv_48_8_t search_kv, return_kv;
        u64 *pmask = (u64 *) mask;
        u64 *pmatch = (u64 *) &ace_info->match;
        for (int j = 0; j < 6; j++) {
            search_kv.key[j] = pmatch[j] & pmask[j];
        }
        int lookup_result = clib_bihash_search_48_8(&group_cand, &search_kv, &return_kv);
        u32 value = lookup_result < 0 ? 1 : return_kv.value + 1;
        if (value <= coll_rate) {
            ans++;
            if (taken) {
                vec_add1(*taken, pae);
            }
            search_kv.value = value;
            clib_bihash_add_del_48_8(&group_cand, &search_kv, 1);
        }
    }
    clib_bihash_free_48_8(&group_cand);
    return ans;
}


always_inline void update_best_mask(u32* best_size, u32 cur_size, fa_5tuple_t* best, fa_5tuple_t* cur)
{
    if (*best_size < cur_size) {
        *best_size = cur_size;
        clib_memcpy_fast(best, cur, sizeof(fa_5tuple_t));
    }
}

/* find the mask producing the biggest sax-pac group
 * slow version -- calculating sax-pac group size for all possible masks*/
static u32
select_sax_pac_best_group(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, fa_5tuple_t* best_mask, int is_ip6) {
    clib_memset (best_mask, 0, sizeof (*best_mask));
    u32 ans = 0;
    fa_5tuple_t cand;

    applied_hash_ace_entry_t** mask_including_aces_final = vec_new(applied_hash_ace_entry_t, vec_len(applied_hash_aces));
    applied_hash_ace_entry_t** mask_including_aces_no_dst = vec_new(applied_hash_ace_entry_t, vec_len(applied_hash_aces));
    applied_hash_ace_entry_t** mask_including_aces_port_proto = vec_new(applied_hash_ace_entry_t, vec_len(applied_hash_aces));

    int max_len  = is_ip6 ? 128 : 32;

    for (int is_proto = 0; is_proto < 2; is_proto++) {
        for (int is_src_port = 0; is_src_port < 2; is_src_port++) {
            for (int is_dst_port = 0; is_dst_port < 2; is_dst_port++) {
                make_sax_pac_mask(&cand, 0, 0, is_proto, is_src_port, is_dst_port, is_ip6);
                sax_pac_filter_non_mask_including(am, applied_hash_aces, mask_including_aces_port_proto,  &cand, is_ip6);
                if (vec_len(mask_including_aces_port_proto) <= ans) {
                    continue;
                }
                int mul = calculate_size_of_sax_pac_group(am, 1, mask_including_aces_port_proto, &cand, NULL);
                for (int src_len = 0; src_len <= max_len; src_len++) {
                    make_sax_pac_mask(&cand, src_len, 0, is_proto, is_src_port, is_dst_port, is_ip6);
                    sax_pac_filter_non_mask_including(am, mask_including_aces_port_proto, mask_including_aces_no_dst, &cand, is_ip6);

                    if (vec_len(mask_including_aces_no_dst) <= ans) {
                        break; /* for bigger src_len the size of mask_including_aces_no_dst will be even smaller */
                    }

                    for (int dst_len = 0; dst_len <= max_len; dst_len++) {

                        if (src_len + dst_len <= 24 && ((1 << (src_len + dst_len)) <= ans / mul)) {
                            continue; /* ignore small prefix lengths if they can not provide the biggest group */
                        }

                        make_sax_pac_mask(&cand, src_len, dst_len, is_proto, is_src_port, is_dst_port, is_ip6);
                        sax_pac_filter_non_mask_including(am, mask_including_aces_no_dst, mask_including_aces_final, &cand, is_ip6);
                        if (vec_len(mask_including_aces_final) <= ans) {
                            break; /* for bigger dst_len the size of mask_including_aces_no_dst will be even smaller */
                        }
                        u32 temp = calculate_size_of_sax_pac_group(am, 1, mask_including_aces_final, &cand, NULL);
                        update_best_mask(&ans, temp, best_mask, &cand);
                    }
                }
            }
        }
    }

    vec_free(mask_including_aces_final);
    vec_free(mask_including_aces_no_dst);
    vec_free(mask_including_aces_port_proto);
    return ans;
}


/* find the mask producing the biggest sax-pac group that do not include either source address or destination address */
static u32
select_sax_pac_best_group_single_address(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, fa_5tuple_t* best_mask, int is_src, int is_ip6) {
    clib_memset (best_mask, 0, sizeof (*best_mask));
    u32 ans = 0;
    fa_5tuple_t cand;

    int max_len  = is_ip6 ? 128 : 32;

    applied_hash_ace_entry_t** mask_including_aces_final = vec_new(applied_hash_ace_entry_t, vec_len(applied_hash_aces));
    applied_hash_ace_entry_t** mask_including_aces_port_proto = vec_new(applied_hash_ace_entry_t, vec_len(applied_hash_aces));

    for (int is_proto = 0; is_proto < 2; is_proto++) {
        for (int is_src_port = 0; is_src_port < 2; is_src_port++) {
            for (int is_dst_port = 0; is_dst_port < 2; is_dst_port++) {
                make_sax_pac_mask(&cand, 0, 0, is_proto, is_src_port, is_dst_port, is_ip6);
                sax_pac_filter_non_mask_including(am, applied_hash_aces, mask_including_aces_port_proto,  &cand, is_ip6);
                if (vec_len(mask_including_aces_port_proto) <= ans) {
                    continue;
                }
                int mul = calculate_size_of_sax_pac_group(am, 1, mask_including_aces_port_proto, &cand, NULL);
                for (int len = 0; len <= max_len; len++) {
                    if (len <= 24 && ((1 << len) <= ans / mul)) {
                        continue; /* ignore small prefix lengths if they can not provide the biggest group */
                    }
                    make_sax_pac_mask(&cand, is_src ? len : 0, is_src ? 0 : len, is_proto, is_src_port, is_dst_port, is_ip6);
                    sax_pac_filter_non_mask_including(am, mask_including_aces_port_proto, mask_including_aces_final, &cand, is_ip6);
                    if (vec_len(mask_including_aces_final) <= ans) {
                        break; /* for bigger len the size of mask_including_aces_no_dst will be even smaller */
                    }
                    u32 temp = calculate_size_of_sax_pac_group(am, 1, mask_including_aces_final, &cand, NULL);
                    update_best_mask(&ans, temp, best_mask, &cand);
                }
            }
        }
    }

    vec_free(mask_including_aces_final);
    vec_free(mask_including_aces_port_proto);
    return ans;
}


static u32
select_sax_pac_best_group_fast_core(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, fa_5tuple_t* best_mask, int is_ip6, int is_src_first) {
    int max_len  = is_ip6 ? 128 : 32;
    applied_hash_ace_entry_t** mask_including = vec_dup(applied_hash_aces);
    u32 ans = 0;
    fa_5tuple_t cand;

    select_sax_pac_best_group_single_address(am, applied_hash_aces, &cand, is_src_first, is_ip6);
    for (int i = 0; i <= max_len; i++) {
        fill_address_mask(&cand, i, is_src_first ? 1 : 0, is_ip6);
        sax_pac_filter_non_mask_including(am, mask_including, mask_including, &cand, is_ip6);
        if (vec_len(mask_including) <= ans) {
            break;
        }
        u32 cand_src = calculate_size_of_sax_pac_group(am, 1, mask_including, &cand, NULL);
        update_best_mask(&ans, cand_src, best_mask, &cand);
    }

    vec_free(mask_including);
    return ans;
}

/* find the mask producing almost the biggest sax-pac group
 * the number of calculated sax-pac group sizes is  proportional to the length of rule */
static u32
select_sax_pac_best_group_fast(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, fa_5tuple_t* best_mask, int is_ip6) {
    fa_5tuple_t best_src, best_dst;
    u32 ans_src = select_sax_pac_best_group_fast_core(am, applied_hash_aces, &best_src, is_ip6, 1);
    u32 ans_dst = select_sax_pac_best_group_fast_core(am, applied_hash_aces, &best_dst, is_ip6, 0);
    if (ans_src >= ans_dst) {
        clib_memcpy_fast(best_mask, &best_src, sizeof(fa_5tuple_t));
        return ans_src;
    }
    else {
        clib_memcpy_fast(best_mask, &best_dst, sizeof(fa_5tuple_t));
        return ans_dst;
    }
}

static void split_aces_ipv4_ipv6(acl_main_t *am, applied_hash_ace_entry_t ** applied_hash_aces, u32 offset, applied_hash_ace_entry_t*** aces_ipv4, applied_hash_ace_entry_t*** aces_ipv6) {
    for (int i = offset; i < vec_len(*applied_hash_aces); i++) {
        applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), i);
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
        hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        int is_ip6 = ace_info->match.pkt.is_ip6;
        if (is_ip6) {
            vec_add1(*aces_ipv6, pae);
        } else {
            vec_add1(*aces_ipv4, pae);
        }
    }
}

static void sax_pac_filter_selected(applied_hash_ace_entry_t** aces, applied_hash_ace_entry_t** in_group) {
    int l = 0;
    for (int i = 0; i < vec_len(aces); i++) {
        if (l  < vec_len(in_group) && aces[i] == in_group[l]) {
            l++;
        } else {
            aces[i-l] = aces[i];
        }
    }
    ASSERT(l == vec_len(in_group));
    _vec_len(aces) = vec_len(aces) - vec_len(in_group);
}

static void assign_sax_pac_mask_type_core(acl_main_t *am, applied_hash_ace_entry_t **applied_aces, int is_ip6) {
    applied_aces = vec_dup(applied_aces);
    fa_5tuple_t best;
    applied_hash_ace_entry_t** for_filtering = vec_new(ace_mask_type_entry_t*, vec_len(applied_aces));

    while (vec_len(applied_aces) > 0) {

        if (USE_FAST_SAX_PAC) {
            select_sax_pac_best_group_fast(am, applied_aces, &best, is_ip6);
        } else {
            select_sax_pac_best_group(am, applied_aces, &best, is_ip6);
        }

        applied_hash_ace_entry_t** in_group = vec_new(ace_mask_type_entry_t*, 0);
        sax_pac_filter_non_mask_including(am, applied_aces, for_filtering, &best, is_ip6);
        calculate_size_of_sax_pac_group(am, am->split_threshold, for_filtering, &best, &in_group);

        best.pkt.lc_index = ~0;
        best.pkt.is_ip6 = ~0;
        best.pkt.mask_type_index_lsb = ~0;

        u32 mask_type_index = assign_mask_type_index(am, &best);
        for (int i = 0; i < vec_len(in_group); i++) {
            in_group[i]->mask_type_index = mask_type_index;
            if (i) {
                lock_mask_type_index(am, mask_type_index);
            }
        }

        sax_pac_filter_selected(applied_aces, in_group);
        vec_free(in_group);
    }

    vec_free(for_filtering);
    vec_free(applied_aces);
}

void assign_sax_pac_mask_types(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, int offset, u32 lc_index)
{
    applied_hash_ace_entry_t** aces_ipv4 = vec_new(applied_hash_ace_entry_t*, 0);
    applied_hash_ace_entry_t** aces_ipv6 = vec_new(applied_hash_ace_entry_t*, 0);
    split_aces_ipv4_ipv6(am, applied_hash_aces, offset, &aces_ipv4, &aces_ipv6);
    assign_sax_pac_mask_type_core(am, aces_ipv4, 0);
    assign_sax_pac_mask_type_core(am, aces_ipv6, 1);

    vec_free(aces_ipv4);
    vec_free(aces_ipv6);

    for (int i = offset; i < vec_len(*applied_hash_aces); i++) {
        activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, i);
    }
}