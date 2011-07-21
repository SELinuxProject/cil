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

#ifndef _CIL_BINARY_INTERNAL_H_
#define _CIL_BINARY_INTERNAL_H_

#include <sepol/policydb/policydb.h>

#include "cil.h"


/**
 * Insert cil common structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the common into.
 * @param[in] node The tree node that contains the cil_common.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_common_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

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
 * Insert cil classcommon structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the classcommon into.
 * @param[in] node The tree node that contains the cil_classcommon.
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
 * @param[in] node The tree node that contains the cil_roletype.
 *
 * @return SEPOL_OK upon success or SEPOL_ERR otherwise.
 */
int cil_roletype_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

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
 * Insert cil rolebounds structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the rolebounds into.
 * @param[in] node The tree node that contains the cil_rolebounds.
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
int cil_type_to_policydb(policydb_t *pdb, struct cil_tree_node *node);

/**
 * Initialize type attribute and attribute type bitmaps within the
 * policy database.
 *
 * @param[in] pdb The policy database which contains the types, which
 * contain the bitmaps.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int policydb_type_ebitmap_init(policydb_t *pdb);

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
int cil_dominance_to_policydb(policydb_t *pdb, struct cil_db *db);

/**
 * Insert cil avrule structure into sepol policydb.
 *
 * @param[in] pdb The policy database to insert the avrule into.
 * @param[in] node The tree node that contains the cil_avrule.
 *
 * @return SEPOL_OK upon success or an error otherwise.
 */
int cil_avrule_to_policydb(policydb_t *pdb, struct cil_tree_node *node);


#endif //_CIL_BINARY_INTERNAL_H_
