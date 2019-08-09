Improving the efficiency of the ACL plugin 
========================

This repository is a fork of VPP framework (https://gerrit.fd.io/r/vpp) with improved efficiency of the ACL classification mechanism.

Our contribution is the following (see the last commit):
* we add a sanitization of ip addresses with corresponding masks (lines 429-430 in "/src/plugins/acl/acl.c") in structure `acl_rule_t`; the abscense of this sanitization is a bug since matching checks against single rule are implemented with usage of `acl_rule_t`
* we modify the infrastructure of the ACL plugin to support different algorithms constructing reprsentations of ACL classifiers that allows to perform efficient classification lookups.
* we implement an algorithm based on SAX-PAC method (http://www.sigcomm.org/sites/default/files/ccr/papers/2014/August/2619239-2626294.pdf) constructing efficient representations of acl classifiers.

## The modified infrastructue
In the ACL plugin the representation of classifiers consists of groups, where each group `x` is specified by group mask `mask_x` and contains only rules whose masks include `mask_x`.  In each group `x` rules are stored in a hash table, where each rule is represented by the hash entry constructed from rule bits included in `mask_x`. The classification process consists of lookups in these hash tables and succeding false positive checks on corresponding rules. Actually, all constructed hash tables are combined into one by adding the group id to the entry key.

All rules of classifiers attached to the same lookup context are stored in a single list, where each rule is represented by the structure `applied_hash_ace_entry_t`. The id of the corresponding group is stored in the field `mask_type_index`.
Previously, the infrastructure of the ACL plugin supported only algorithms assigning `mask_type_index` during single traversal of the list containing `applied_hash_ace_entry_t`. We modify the infrastructure to support any type of algorithms splitting rules into groups.

After modifications the procedure `hash_acl_apply`(file: "/src/plugins/acl/hash_lookup.c") constructs a representation for the corresponding lookup index taking all applied classifiers at once. In the previous version, `hash_acl_apply` constructs the representation only for a single classifier and was called for each applied classifier seperately. 

The running process of the modified `hash_acl_apply` consists of the following steps:
1. create all links connecting classifiers with the corresponding lookup context (procedure `add_acl_to_lc_links`)
2. for all rules in the applied classifiers create corresponding `applied_hash_ace_entry_t` structures with undefined values of `mask_type_index` (lines  464-465)
3. split rules into groups by assigning the value of `mask_type_index` in the created `applied_hash_ace_entry_t` and add the corresponding entries to the hash table (procedure `assign_and_activate_mask_types`) 
4. update a list  maintaining information about all group masks (procedure `remake_hash_applied_mask_info_vec`) 

In the step 3 the algorithm splitting rules on groups is selected according to the value of   
`am->hash_lookup_constructing_algorithm`, which is a parameter of the ACL plugin. 
Currently, the following algorithms are supported: `Tuple Space Search`, `Tuple Merge` and `SAX-PAC`. Each algorithm is implemented in a separate [.ch] files. The code for the `Tuple Space Search` and `Tuple Merge` was taken from the file '/src/plugins/acl/hash_lookup.c', `SAX-PAC` is a new implemented algorithm.

Procedures related to group masks and group ids are moved to the file "/src/plugins/acl/mask_inlines.h".

## SAX-PAC based algorithm
Additionaly to the `Tuple Space Search` and `Tuple Merge` we implement the modification of `SAX-PAC` method intended for classifier representations in the regular memory. The implemented version of `SAX-PAC` splits rules on groups iteratively: at each iteration the group mask for the new group is selected by greedy heuristic maximizing the group size. In the group of the `SAX-PAC` representation at most `SAX_PAC_SPLIT_THRESHOLD` rules  can correspond to the same hash entry. The default value of `SAX_PAC_SPLIT_THRESHOLD` is `3` which is significantly smaller than the default value for the same threshold in the `Tuple Merge` algorithm (`TM_SPLIT_THRESHOLD = 39`).

### Comparison of SAX-PAC and Tuple Merge reprsentations
We compare the efficiency of `Tuple Merge` and `SAX-PAC` reprsentations on `12` classifiers generated by ClassBench (see "ClassBenchClassifiers.zip").

In the worst case, the number of hash table lookups during header classification equals to the number of groups in the corresponding classifier reprsentation. Hence, we compare the number of groups in the `Tuple Merge` and `SAX-PAC` representations (see the table below). 

Note that the classification result can be determined after lookups into hash tables corresponding to the first several groups of a representation (with succeding false-positive checks) if the priority of the already found matching rule is bigger than the priority of any other rule in remaining groups. Thus, we also compare the average number of hash table lookups during classification by `Tuple Merge` and `SAX-PAC` representations under the assumption that the rule determining the classification result for an incoming header is chosen according to the uniform distribution (see the table below). 

| Classifier    | # groups, `SAX-PAC` | # groups, `Tuple Merge` | avg. hash table lookups, `SAX-PAC` | avg. hash table lookups, `Tuple Merge` |
| :-------------: | :------: | :-----: | :-----: | :-----: |
| acl1.txt | 14 | 77 | 1.02 | 6.21 |
| acl2.txt | 51 | 133 | 18.39 | 37.86 |
| acl3.txt | 15 | 98 | 3.27 | 11.98 |
| acl4.txt | 22 | 149 | 5.42 | 25.76 |
| acl5.txt | 7 | 10 | 4.16 | 4.63 |
| fw1.txt | 25 | 85 | 2.21 | 27.83 |
| fw2.txt | 10 | 41 | 2.64 | 16.22 |
| fw3.txt | 43 | 63 | 10 | 4.51 |
| fw4.txt | 32 | 90 | 3.06 | 22.74 |
| fw5.txt | 30 | 80 | 5.69 | 18.62 |
| ipc1.txt | 11| 178 | 2.08| 46.24 |
| ipc2.txt | 2| 7  | 1.62 | 4.38 |

In `SAX-PAC` representation the number of groups is significantly smaller than in `Tuple Merge` representation for all evaluated classifiers. The avarage number of hash table lookups is also significantly smaller in `SAX-PAC` representation for all classifiers except `fw3.txt`.

The perfomance of the header classification also depends on the number of false positive checks against rules represented by corresponding hash table entries. Hence for `Tuple Merge` and `SAX-PAC`repsentations we compare the average number of rules `B_avg` corresponding to the same hash entry.

| Classifier    | `B_avg`, `SAX-PAC` | `B_avg`, `Tuple Merge` |
| :-------------: | :------: | :-----: |
| acl1.txt | 1.00 | 1.02 |
| acl2.txt | 1.22 | 1.22 |
| acl3.txt | 1.07 | 1.11 |
| acl4.txt | 1.12 | 1.27 |
| acl5.txt | 1.29 | 1.84 |
| fw1.txt | 1.01 | 1.01 | 
| fw2.txt | 1.00 | 1.03 | 
| fw3.txt | 1.04 | 1.03 | 
| fw4.txt | 1.02 | 1.02 | 
| fw5.txt | 1.02 | 1.01 | 
| ipc1.txt | 1.00 | 1.00 |
| ipc2.txt | 1.00 | 1.00 |

The value of `B_avg` is noticeably smaller in `SAX-PAC` representation for classifiers `acl4.txt` and `acl5.txt`. For all other evaluated classifiers the value of `B_avg` is almost the same in both representations.

Combining the described above results we obtain that the classification perfomance in `SAX-PAC` representation is significantly bigger than in `Tuple Merge` representation for all classifiers except `fw3.txt`.   

Each evaluated classifier consists of ~50k rules; the construction of `SAX-PAC` representation for such classifier takes at most `3.2 sec` in a single core of Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz. The construction time of `Tuple Merge` representation is significantly smaller, since `Tuple Merge` splits rules on groups during the single traversal of given classifiers. But the classification perfomance in `Tuple Merge` representation is significantly smaller.

Note that the implementation of `SAX-PAC` representation has two versions: fast version selecting mask for each new group by heuristic, and optimal version selecting group mask among all possible masks. All described above evaluations are done for the fast version. The classification perfomance in `SAX-PAC` representations constructed by optimal version of algorithm is almost the same as for fast version, but the construction time is 10 times bigger. For other non evalauted classifiers the optimal version of algorithm hypotetically can provide more efficient representations. The version of the algorithm constructing `SAX_PAC` representation is controlled by the macros `USE_FAST_SAX_PAC` defined in the file "src/plugins/acl/sax_pac.c".



