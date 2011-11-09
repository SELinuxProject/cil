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

#ifndef CIL_H_
#define CIL_H_

#include <sepol/policydb/policydb.h>

struct cil_db;
typedef struct cil_db cil_db_t;

extern void cil_db_init(cil_db_t **db);
extern void cil_db_destroy(cil_db_t **db);

extern int cil_parse_files(cil_db_t *db, char **files_list, int num_files);

extern int cil_db_to_sepol_policydb(cil_db_t *db, sepol_policydb_t *sepol_db);
extern int cil_userprefixes_to_string(cil_db_t *db, sepol_policydb_t *sepol_db, char **out, size_t *size);
extern int cil_selinuxusers_to_string(cil_db_t *db, sepol_policydb_t *sepol_db, char **out, size_t *size);
extern int cil_filecons_to_string(cil_db_t *db, sepol_policydb_t *sepol_db, char **out, size_t *size);

enum cil_log_level {
	CIL_ERR = 1,
	CIL_WARN,
	CIL_INFO
};
extern void cil_set_log_level(enum cil_log_level lvl);
extern void cil_set_log_handler(void (*handler)(int lvl, char *msg));

extern void cil_set_malloc_error_handler(void (*handler)(void));

#endif