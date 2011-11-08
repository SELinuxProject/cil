/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
 */

#ifndef _CIL_BINARY_H_
#define _CIL_BINARY_H_

#include <sepol/policydb/policydb.h>

#include "cil_internal.h"

struct cil_neverallow {
	struct cil_tree_node *node;
	struct cil_list *data;
};

struct cil_neverallow_data {
	avtab_key_t *key;
	int types;
};

/**
 * Create a binary policydb from the cil db.
 *
 * @param[in] db The cil database.
 * @param[in] pdb The policy database.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_binary_create(const struct cil_db *db, sepol_policydb_t *pdb);

/**
 * Insert cil common structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the common into.
 * @param[in] node The tree node that contains the cil_common.
 * @param[out] common_out The sepol common to send back.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_common_to_policydb(policydb_t *pdb, struct cil_tree_node *node, common_datum_t **common_out);

/**
 * Insert cil class structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the class into.
 * @param[in] node The tree node that contains the cil_class.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_class_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil class common structure into sepol policydb.
 * Each cil_class has a common property which, if defined, contains the
 * common associated with that class.
 *
 * @param[in] pdb The policy database to insert the classcommon into.
 * @param[in] node The tree node that contains the cil_class.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_classcommon_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil role structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the role into.
 * @param[in] node The tree node that contains the cil_role.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_role_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil roletype structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the roletype into.
 * @param[in] db The cil database
 * @param[in] node The tree node that contains the cil_roletype.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_roletype_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_tree_node *node);

/**
 * Insert cil roledominance structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the roledominance into.
 * @param[in] node The tree node that contains the cil_roledominance.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_roledominance_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil role bounds structure into sepol policydb.
 * Each cil_role contains a bounds property which, if defined, contains
 * the role bounds associated with that role.
 *
 * @param[in] pdb The policy database to insert the rolebounds into.
 * @param[in] node The tree node that contains the cil_role.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_rolebounds_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil type structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the type into.
 * @param[in] node The tree node that contains the cil_type.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_type_to_policydb(policydb_t *pdb, struct cil_tree_node *node, ebitmap_t *types_bitmap);

/**
 * Insert cil typealias structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the typealias into.
 * @param[in] node The tree node that contains the cil_typealias.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_typealias_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil typepermissive structure into sepol policydb.
 * The function looks up the perviously inserted type and flips the bit
 * in the permssive types bitmap that corresponds to that type's value.
 *
 * @param[in] pdb The policy database to insert the typepermissive into.
 * @param[in] node The tree node that contains the cil_typepermissive.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_typepermissive_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil attribute structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the attribute into.
 * @param[in] node The tree node that contains the cil_attribute.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_typeattribute_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil attribute structure into sepol type->attribute bitmap.
 * The function calls helper functions to loop over the attributes lists
 * of types and negative types. If either of the lists contain an attribute,
 * the helper functions will recurse into the attribute and record the
 * attribute's types and negative types. There is no minimum depth.
 *
 * @param[in] pdb The policy database that contains the type->attribute bitmap.
 * @param[in] db The cil database
 * @param[in] node The tree node that contains the cil_attribute.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_typeattribute_to_bitmap(policydb_t *pdb, const struct cil_db *cdb, struct cil_tree_node *node);

/**
 * Insert cil policycap structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the policycap into.
 * @param[in] node The tree node that contains the cil_policycap.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_policycap_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil user structure into sepol policydb.
 *
 * @param[in] pdb THe policy database to insert the user into.
 * @param[in] node The tree node that contains the cil_user.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_user_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil userrole structure into sepol policydb.
 *
 * @param[in] pdb THe policy database to insert the userrole into.
 * @param[in] node The tree node that contains the cil_userrole.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_userrole_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil bool structure into sepol policydb.
 *
 * @param[in] pdb THe policy database to insert the bool into.
 * @param[in] node The tree node that contains the cil_bool.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_bool_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert all ordered cil category structures into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the categories into.
 * @param[in] db The cil database that contains the category order list.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_catorder_to_policydb(policydb_t *pdb, const struct cil_db *db);

/**
 * Insert cil category alias structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the category alias into.
 * @param[in] node The tree node that contains the cil_catalias.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_catalias_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert the cil dominance order into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the dominance into.
 * @param[in] db the cil database that contains the dominance order list.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_dominance_to_policydb(policydb_t *pdb, const struct cil_db *db);

/**
 * Insert cil type rule structure into sepol policydb.  This includes
 * typetransition, typechange, and typemember.
 *
 * @param[in] pdb The policy database to insert the type rule into.
 * @param[in] node The tree node that contains the cil_type_rule.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_type_rule_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil avrule structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the avrule into.
 * @param[in] node The tree node that contains the cil_avrule.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_avrule_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_tree_node *node, struct cil_list *neverallows);

/**
 * Insert cil booleanif structure into sepol policydb.  This populates the
 * policydb conditional list.  Each conditional node contains an expression
 * and true/false avtab_ptr lists that point into te_cond_avtab.
 *
 * @param[in] pdb The policy database to insert the booleanif into.
 * @param[in] node The tree node that contains the cil_booleanif.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_booleanif_to_policydb(policydb_t *pdb, struct cil_tree_node *node, struct cil_list *neverallows);

/**
 * Insert cil role transition structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the role transition into.
 * @param[in] node The tree node that contains the cil_role_trans.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_roletrans_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil role allow structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the role allow into.
 * @param[in] node The tree node that contains the cil_role_allow.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_roleallow_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil file transition structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the file transition into.
 * @param[in] node The tree node that contains the cil_filetransition.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_filetransition_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil constrain/mlsconstrain structure(s) into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the (mls)constrain into.
 * @param[in] node The tree node that contains the cil_(mls)constrain.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_constrain_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Define sepol level.
 * Associates the sepol level (sensitivity) with categories.
 * Looks at the cil_sens structure for a list of cil_catsets and
 * cil_catranges to associate the sensitivity with.
 * Sets the sepol level as defined in the sepol policy database.
 *
 * @param[in] pdb The policy database that holds the sepol level.
 * @param[in] node The tree node that contains the cil_sens.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR upon error.
 */
int cil_sepol_level_define(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil sid structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the sid into.
 * @param[in] node The tree node that contains the cil_sid.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_sid_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil rangetransition structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the rangetransition into.
 * @param[in] node The tree node that contains the cil_rangetransition.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_rangetransition_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Insert cil portcon structure into sepol policydb.
 * The function is given a structure containing the sorted portcons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the portcon into.
 * @param[in] node The cil_sort structure that contains the sorted portcons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_portcon_to_policydb(policydb_t *pdb, struct cil_sort *portcons);

/**
 * Insert cil netifcon structure into sepol policydb.
 * The function is given a structure containing the sorted netifcons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the netifcon into.
 * @param[in] node The cil_sort structure that contains the sorted netifcons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_netifcon_to_policydb(policydb_t *pdb, struct cil_sort *netifcons);

/**
 * Insert cil nodecon structure into sepol policydb.
 * The function is given a structure containing the sorted nodecons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the nodecon into.
 * @param[in] node The cil_sort structure that contains the sorted nodecons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_nodecon_to_policydb(policydb_t *pdb, struct cil_sort *nodecons);

/**
 * Insert cil fsuse structure into sepol policydb.
 * The function is given a structure containing the sorted fsuses and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the fsuse into.
 * @param[in] node The cil_sort structure that contains the sorted fsuses.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_fsuse_to_policydb(policydb_t *pdb, struct cil_sort *fsuses);

/**
 * Insert cil genfscon structure into sepol policydb.
 * The function is given a structure containing the sorted genfscons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the genfscon into.
 * @param[in] node The cil_sort structure that contains the sorted genfscons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_genfscon_to_policydb(policydb_t *pdb, struct cil_sort *genfscons);

/**
 * Insert cil pirqcon structure into sepol policydb.
 * The function is given a structure containing the sorted pirqcons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the pirqcon into.
 * @param[in] node The cil_sort structure that contains the sorted pirqcons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_pirqcon_to_policydb(policydb_t *pdb, struct cil_sort *pirqcons);

/**
 * Insert cil iomemcon structure into sepol policydb.
 * The function is given a structure containing the sorted iomemcons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the iomemcon into.
 * @param[in] node The cil_sort structure that contains the sorted iomemcons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_iomemcon_to_policydb(policydb_t *pdb, struct cil_sort *iomemcons);

/**
 * Insert cil ioportcon structure into sepol policydb.
 * The function is given a structure containing the sorted ioportcons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the ioportcon into.
 * @param[in] node The cil_sort structure that contains the sorted ioportcons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_ioportcon_to_policydb(policydb_t *pdb, struct cil_sort *ioportcons);

/**
 * Insert cil pcidevicecon structure into sepol policydb.
 * The function is given a structure containing the sorted pcidevicecons and
 * loops over this structure inserting them into the policy database.
 *
 * @param[in] pdb The policy database to insert the pcidevicecon into.
 * @param[in] node The cil_sort structure that contains the sorted pcidevicecons.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_pcidevicecon_to_policydb(policydb_t *pdb, struct cil_sort *pcidevicecons);


#endif //_CIL_BINARY_H_
