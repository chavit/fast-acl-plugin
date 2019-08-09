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
#include "hash_lookup.h"
#include <vppinfra/bihash_48_8.h>
#include "mask_inlines.h"

void assign_tss_mask_types(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces, int offset, u32 lc_index) {;
    for(int i = offset; i < vec_len(*applied_hash_aces); i++) {
        applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), i);
        hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
        hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
        pae->mask_type_index = ace_info->base_mask_type_index;
        activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces,  i);
        lock_mask_type_index(am, pae->mask_type_index);
    }
}
