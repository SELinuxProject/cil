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
 * @param[in] pdb The policy database to insert the class into.
 * @param[in] node The tree node that contains the cil_class.
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


#endif //_CIL_BINARY_INTERNAL_H_
