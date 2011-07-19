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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "cil_symtab.h"
#include "cil_mem.h"

/*
	Tree/list node types
*/
#define CIL_MIN_DECLARATIVE	500

enum cil_flavor {
	CIL_ROOT = 0,
	CIL_DB,
	CIL_AST_NODE,
	CIL_PARSE_NODE,
	CIL_AST_STR,
	CIL_LIST,
	CIL_LIST_ITEM,
	CIL_INT,
	CIL_FILES,
	CIL_AVRULE,
	CIL_SENS_DOM,
	CIL_SEARCH,
	CIL_TRANS_IF,
	CIL_TRANS_CALL,
	CIL_TRANS_INH_BLK,
	CIL_TRANS_INH_TYPE,
	CIL_TRANS_INH_ROLE,
	CIL_TRANS_DEL,
	CIL_TRANS_TRANS,
	CIL_IN,
	CIL_FILECON,
	CIL_PORTCON,
	CIL_NODECON,
	CIL_GENFSCON,
	CIL_NETIFCON,
	CIL_PIRQCON,
	CIL_IOMEMCON,
	CIL_IOPORTCON,
	CIL_PCIDEVICECON,
	CIL_FSUSE,
	CIL_CONSTRAIN,
	CIL_MLSCONSTRAIN,
	CIL_PERM,
	CIL_USERROLE,
	CIL_USERBOUNDS,
	CIL_ATTRTYPES,
	CIL_TYPE_RULE,
	CIL_TYPEBOUNDS,
	CIL_FILETRANSITION,
	CIL_RANGETRANSITION,
	CIL_TYPEPERMISSIVE,
	CIL_ROLETRANS,
	CIL_ROLEALLOW,
	CIL_ROLETYPE,
	CIL_ROLEDOMINANCE,
	CIL_ROLEBOUNDS,
	CIL_CATORDER,
	CIL_DOMINANCE,
	CIL_SENSCAT,
	CIL_CLASSCOMMON,
	CIL_SIDCONTEXT,
	CIL_CALL,
	CIL_ARGS,
	CIL_BOOLEANIF,
	CIL_TUNABLEIF,
	CIL_TUNABLEIFDEF,
	CIL_TUNABLEIFNDEF,
	CIL_AND,
	CIL_OR,
	CIL_XOR,
	CIL_NOT,
	CIL_EQ,
	CIL_NEQ,
	CIL_ELSE,
	CIL_COND,
	CIL_PARAM,
	CIL_CONS_AND,
	CIL_CONS_OR,
	CIL_CONS_NOT,
	CIL_CONS_EQ,
	CIL_CONS_DOM,
	CIL_CONS_DOMBY,
	CIL_CONS_INCOMP,
	CIL_CONS_U1,
	CIL_CONS_U2,
	CIL_CONS_T1,
	CIL_CONS_T2,
	CIL_CONS_R1,
	CIL_CONS_R2,
	CIL_CONS_L1,
	CIL_CONS_L2,
	CIL_CONS_H1,
	CIL_CONS_H2,

	CIL_BLOCK = CIL_MIN_DECLARATIVE,
	CIL_CLASS,
	CIL_COMMON,
	CIL_SID,
	CIL_USER,
	CIL_ROLE,
	CIL_TYPE,
	CIL_ATTR,
	CIL_BOOL,
	CIL_PERMSET,
	CIL_TUNABLE,
	CIL_TYPEALIAS,
	CIL_CONTEXT,
	CIL_LEVEL,
	CIL_SENS,
	CIL_CAT,
	CIL_SENSALIAS,
	CIL_CATALIAS,
	CIL_CATSET,
	CIL_MACRO,
	CIL_OPTIONAL,
	CIL_POLICYCAP,
	CIL_IPADDR
};

/*
	Keywords
*/
#define CIL_KEY_BLOCK 		"block"
#define CIL_KEY_CLASS		"class"
#define CIL_KEY_PERM		"perm"
#define CIL_KEY_PERMSET		"permissionset"
#define CIL_KEY_COMMON		"common"
#define CIL_KEY_CLASSCOMMON	"classcommon"
#define CIL_KEY_SID		"sid"
#define CIL_KEY_SIDCONTEXT	"sidcontext"
#define CIL_KEY_USER		"user"
#define CIL_KEY_USERBOUNDS	"userbounds"
#define CIL_KEY_ROLE 		"role"
#define CIL_KEY_USERROLE	"userrole"
#define CIL_KEY_ROLETYPE	"roletype"
#define CIL_KEY_ROLETRANS	"roletransition"
#define CIL_KEY_ROLEALLOW	"roleallow"
#define CIL_KEY_ROLEDOMINANCE	"roledominance"
#define CIL_KEY_ROLEBOUNDS	"rolebounds"
#define CIL_KEY_TYPE 		"type"
#define CIL_KEY_ATTR		"attribute"
#define CIL_KEY_BOOL		"bool"
#define CIL_KEY_ALLOW		"allow"
#define CIL_KEY_AUDITALLOW	"auditallow"
#define CIL_KEY_DONTAUDIT	"dontaudit"
#define CIL_KEY_NEVERALLOW	"neverallow"
#define CIL_KEY_TYPETRANS	"typetransition"
#define CIL_KEY_RANGETRANSITION	"rangetransition"
#define CIL_KEY_FILETRANSITION	"filetransition"
#define CIL_KEY_TYPECHANGE	"typechange"
#define CIL_KEY_TYPEMEMBER	"typemember"
#define CIL_KEY_ATTRTYPES	"attributetypes"
#define CIL_KEY_TYPEALIAS	"typealias"
#define CIL_KEY_TYPEBOUNDS	"typebounds"
#define CIL_KEY_TYPEPERMISSIVE	"typepermissive"
#define CIL_KEY_MACRO		"macro"
#define CIL_KEY_CALL		"call"
#define CIL_KEY_POLICYCAP	"policycap"
#define CIL_KEY_CONTEXT		"context"
#define CIL_KEY_FILECON		"filecon"
#define CIL_KEY_PORTCON		"portcon"
#define CIL_KEY_NODECON		"nodecon"
#define CIL_KEY_GENFSCON	"genfscon"
#define CIL_KEY_NETIFCON	"netifcon"
#define CIL_KEY_PIRQCON		"pirqcon"
#define CIL_KEY_IOMEMCON	"iomemcon"
#define CIL_KEY_IOPORTCON	"ioportcon"
#define CIL_KEY_PCIDEVICECON	"pcidevicecon"
#define CIL_KEY_FSUSE		"fsuse"
#define CIL_KEY_SENSITIVITY	"sensitivity"
#define CIL_KEY_SENSALIAS	"sensitivityalias"
#define CIL_KEY_CATEGORY	"category"
#define CIL_KEY_CATALIAS	"categoryalias"
#define CIL_KEY_CATSET		"categoryset"
#define CIL_KEY_CATORDER	"categoryorder"
#define CIL_KEY_DOMINANCE	"dominance"
#define CIL_KEY_SENSCAT		"sensitivitycategory"
#define CIL_KEY_LEVEL		"level"
#define CIL_KEY_MLSCONSTRAIN	"mlsconstrain"
#define CIL_KEY_CONSTRAIN	"constrain"
#define CIL_KEY_BOOLEANIF	"booleanif"
#define CIL_KEY_TUNABLE		"tunable"
#define CIL_KEY_TUNABLEIF	"tunableif"
#define CIL_KEY_TUNABLEIFDEF	"tunableifdef"
#define CIL_KEY_TUNABLEIFNDEF	"tunableifndef"
#define CIL_KEY_AND		"&&"
#define CIL_KEY_OR		"||"
#define CIL_KEY_XOR		"^"
#define CIL_KEY_NOT		"!"
#define CIL_KEY_EQ		"=="
#define CIL_KEY_NEQ		"!="
#define CIL_KEY_ELSE		"else"
#define CIL_KEY_OPTIONAL	"optional"
#define CIL_KEY_IPADDR		"ipaddr"

#define CIL_KEY_CONS_AND	"and"
#define CIL_KEY_CONS_OR		"or"
#define CIL_KEY_CONS_NOT	"not"
#define CIL_KEY_CONS_EQ		"eq"	
#define CIL_KEY_CONS_DOM	"dom"
#define CIL_KEY_CONS_DOMBY	"domby"
#define CIL_KEY_CONS_INCOMP	"incomp"
#define CIL_KEY_CONS_U1		"u1"
#define CIL_KEY_CONS_U2		"u2"
#define CIL_KEY_CONS_T1		"t1"
#define CIL_KEY_CONS_T2		"t2"
#define CIL_KEY_CONS_R1		"r1"
#define CIL_KEY_CONS_R2		"r2"
#define CIL_KEY_CONS_L1		"l1"
#define CIL_KEY_CONS_L2		"l2"
#define CIL_KEY_CONS_H1		"h1"
#define CIL_KEY_CONS_H2		"h2"

/*
	Symbol Table Array Indices
*/
enum cil_sym_index {
	CIL_SYM_FILENAMES = 0,
	CIL_SYM_BLOCKS,
	CIL_SYM_USERS,
	CIL_SYM_ROLES,
	CIL_SYM_TYPES,
	CIL_SYM_COMMONS,
	CIL_SYM_CLASSES,
	CIL_SYM_PERMSETS,
	CIL_SYM_BOOLS,
	CIL_SYM_TUNABLES,
	CIL_SYM_SENS,
	CIL_SYM_CATS,
	CIL_SYM_SIDS,
	CIL_SYM_FILECONS,
	CIL_SYM_PORTCONS,
	CIL_SYM_NETIFCONS,
	CIL_SYM_MACROS,
	CIL_SYM_CONTEXTS,
	CIL_SYM_LEVELS,
	CIL_SYM_POLICYCAPS,
	CIL_SYM_OPTIONALS,
	CIL_SYM_IPADDRS,
	CIL_SYM_NUM,
	CIL_SYM_UNKNOWN,
};

#define CIL_SYM_SIZE		256

struct cil_db {
	struct cil_tree *ast;
	symtab_t symtab[CIL_SYM_NUM];
	struct cil_list *catorder;
	struct cil_list *dominance;
	struct cil_sort *netifcon;
	struct cil_sort *genfscon;
	struct cil_sort *filecon;
	struct cil_sort *nodecon;
	struct cil_sort *portcon;
	struct cil_sort *pirqcon;
	struct cil_sort *iomemcon;
	struct cil_sort *ioportcon;
	struct cil_sort *pcidevicecon;
	struct cil_sort *fsuse;
};

struct cil_sort {
	enum cil_flavor flavor;
	uint32_t count;
	uint32_t index;
	void **array;
};

struct cil_search {
	//Waiting on design
	int x; //temporary while attempting to get this to compile
};

struct cil_block {
	struct cil_symtab_datum datum;
	symtab_t symtab[CIL_SYM_NUM];
	/* TODO CDS eventually, these should probably become a flags bit vector */
	uint16_t is_abstract;
	/* TODO CDS we need to figure out how to handle conditionals */
	char *condition;
};

struct cil_optional {
	struct cil_symtab_datum datum;
};

struct cil_class {
	struct cil_symtab_datum datum;
	symtab_t perms;
	struct cil_common *common;
};

struct cil_perm {
	struct cil_symtab_datum datum;
};

struct cil_permset {
	struct cil_symtab_datum datum;
	struct cil_list *perms_list_str;
};

struct cil_common {
	struct cil_symtab_datum datum;
	symtab_t perms;
};

struct cil_classcommon {
	char *class_str;
	char *common_str;
};
	

struct cil_sid {
	struct cil_symtab_datum datum;
};

struct cil_sidcontext {
	char *sid_str;
	struct cil_sid *sid;
	char *context_str;
	struct cil_context *context;
};

struct cil_user {
	struct cil_symtab_datum datum;
	struct cil_user *bounds;
};

struct cil_userrole {
	char *user_str;
	struct cil_user *user;
	char *role_str;
	struct cil_role *role;
};

struct cil_userbounds {
	char *user_str;
	char *bounds_str;
};

struct cil_role {
	struct cil_symtab_datum datum;
	struct cil_role *bounds;
};

/* TODO Waiting on design */
struct cil_roledominance {
	char *role_str;
	struct cil_role *role;
	char *domed_str;
	struct cil_role *domed;
};

struct cil_roletype {
	char *role_str;
	struct cil_role *role;
	char *type_str;
	struct cil_type *type;
};

struct cil_rolebounds {
	char *role_str;
	char *bounds_str;
};

struct cil_type	{
	struct cil_symtab_datum datum;
	struct cil_list *attrs_list;
	struct cil_type *bounds;
};

struct cil_attribute {
	struct cil_symtab_datum datum;
	struct cil_list *types_list;
	struct cil_list *neg_list;
};

struct cil_attrtypes {
	char *attr_str;
	struct cil_list *types_list_str;
	struct cil_list *neg_list_str;
};

struct cil_typealias {
	struct cil_symtab_datum datum;
	char *type_str;
	struct cil_type *type;
};

struct cil_typebounds {
	char *type_str;
	char *bounds_str;
};

struct cil_typepermissive {
	char *type_str;
	struct cil_type *type;
};

struct cil_filetransition {
	char *src_str;
	struct cil_type *src;
	char *exec_str;
	struct cil_type *exec;
	char *proc_str;
	struct cil_class *proc;
	char *dest_str;
	struct cil_type *dest;
	char *path_str;
};

struct cil_rangetransition {
	char *src_str;
	struct cil_type *src;
	char *exec_str;
	struct cil_type *exec;
	char *obj_str;
	struct cil_class *obj;
	char *low_str;
	struct cil_level *low;
	char *high_str;
	struct cil_level *high;
};

struct cil_bool {
	struct cil_symtab_datum datum;
	uint16_t value;
};

#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
struct cil_avrule {
	uint32_t rule_kind;
	char *src_str;
	void *src;
	uint32_t src_flavor;
	char *tgt_str;	
	void *tgt;
	uint32_t tgt_flavor;
	char *obj_str;
	struct cil_class *obj;
	struct cil_list *perms_list_str;
	struct cil_list *perms_list;
	char *permset_str;
};

#define CIL_TYPE_TRANSITION 16
#define CIL_TYPE_MEMBER     32
#define CIL_TYPE_CHANGE     64
#define CIL_AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
struct cil_type_rule {
	uint32_t rule_kind;
	char *src_str;
	struct cil_type *src;
	char *tgt_str;
	struct cil_type *tgt;
	char *obj_str;
	struct cil_class *obj;
	char *result_str;
	struct cil_type *result;
};

struct cil_role_trans {
	char *src_str;
	struct cil_role *src;
	char *tgt_str;	
	struct cil_type *tgt;
	char *obj_str;
	struct cil_class *obj;
	char *result_str;
	struct cil_role *result;
};

struct cil_role_allow {
	char *src_str;
	struct cil_role *src;
	char *tgt_str;
	struct cil_role *tgt;
};

struct cil_sens {
	struct cil_symtab_datum datum;
	symtab_t cats;
};

struct cil_sensalias {
	struct cil_symtab_datum datum;
	char *sens_str;
	struct cil_sens *sens;
};

struct cil_sens_dominates {
	struct cil_list *sens_list_str;
};

struct cil_cat {
	struct cil_symtab_datum datum;
};

struct cil_catalias {
	struct cil_symtab_datum datum;
	char *cat_str;
	struct cil_cat *cat;
};

struct cil_catset {
	struct cil_symtab_datum datum;
	struct cil_list *cat_list_str;
	struct cil_list *cat_list;
};

struct cil_catorder {
	struct cil_list *cat_list_str;
};

struct cil_senscat {
	char *sens_str;
	struct cil_list *cat_list_str;
	char *catset_str;
	struct cil_catset *catset;
};

struct cil_level {
	struct cil_symtab_datum datum;
	char *sens_str;
	struct cil_sens *sens;
	struct cil_list *cat_list_str;
	struct cil_list *cat_list;
	char *catset_str;
	struct cil_catset *catset;
};

#define CIL_INHERIT_BLOCK 1
#define CIL_INHERIT_ROLE  2
#define CIL_INHERIT_TYPE  3
struct cil_transform_inherit {
	struct cil_symtab_datum datum;
	char *inherit_from_str;
	void *inherit_from;
	struct cil_list_item *except;
	enum cil_flavor flavor;	
};

struct cil_transform_del {
	struct cil_search target;
};

// This is the transform that modifies things in-place
struct cil_transform_transform {
	struct cil_search target;
	// TODO: Transform contents when we figure out what this will look like
};

struct cil_in {
	struct cil_search target;
};

struct cil_context {
	struct cil_symtab_datum datum;
	char *user_str;
	struct cil_user *user;
	char *role_str;
	struct cil_role *role;
	char *type_str;
	struct cil_type *type;
	char *low_str;
	struct cil_level *low;
	char *high_str;
	struct cil_level *high;
};

enum cil_filecon_types {
	CIL_FILECON_FILE = 1,
	CIL_FILECON_DIR,
	CIL_FILECON_CHAR,
	CIL_FILECON_BLOCK,
	CIL_FILECON_SOCKET,
	CIL_FILECON_PIPE,
	CIL_FILECON_SYMLINK,
	CIL_FILECON_ANY
};

struct cil_filecon {
	char *root_str;
	char *path_str;
	enum cil_filecon_types type;
	char *context_str;
	struct cil_context *context;
};

struct cil_portcon {
	char *type_str;
	uint32_t port_low;
	uint32_t port_high;
	char *context_str;
	struct cil_context *context;
};

struct cil_nodecon {
	char *addr_str;
	struct cil_ipaddr *addr;
	char *mask_str;
	struct cil_ipaddr *mask;
	char *context_str;
	struct cil_context *context;
};

struct cil_ipaddr {
	struct cil_symtab_datum datum;
	int family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
};

struct cil_genfscon {
	char *type_str;
	char *path_str;
	char *context_str;
	struct cil_context *context;
};

struct cil_netifcon {
	char *interface_str;
	char *if_context_str;
	struct cil_context *if_context;
	char *packet_context_str;
	struct cil_context *packet_context;
	char *context_str;
};

struct cil_pirqcon {
	uint32_t pirq;
	char *context_str;
	struct cil_context *context;
};

struct cil_iomemcon {
	uint32_t iomem_low;
	uint32_t iomem_high;
	char *context_str;
	struct cil_context *context;
};

struct cil_ioportcon {
	uint32_t ioport_low;
	uint32_t ioport_high;
	char *context_str;
	struct cil_context *context;
};

struct cil_pcidevicecon {
	uint32_t dev;
	char *context_str;
	struct cil_context *context;
};

enum cil_fsuse_types {
	CIL_FSUSE_XATTR = 1,
	CIL_FSUSE_TASK,
	CIL_FSUSE_TRANS
};

struct cil_fsuse {
	enum cil_fsuse_types type;
	char *fs_str;
	char *context_str;
	struct cil_context *context;
};

#define CIL_MLS_LEVELS "l1 l2 h1 h2" 
#define CIL_CONSTRAIN_KEYS "t1 t2 r1 r2 u1 u2"
#define CIL_MLSCONSTRAIN_KEYS CIL_MLS_LEVELS CIL_CONSTRAIN_KEYS
#define CIL_CONSTRAIN_OPER "== != eq dom domby incomp not and or"
struct cil_constrain {
	struct cil_list *class_list_str;
	struct cil_list *class_list;
	struct cil_list *perm_list_str;
	struct cil_list *perm_list;
	struct cil_tree_node *expr;
};

struct cil_param {
	char *str;
	enum cil_flavor flavor;
};

struct cil_macro {
	struct cil_symtab_datum datum;
	symtab_t symtab[CIL_SYM_NUM];
	struct cil_list *params;
};

struct cil_args {
	char *arg_str;
	struct cil_tree_node *arg;
	char *param_str;
	enum cil_flavor flavor;
};

struct cil_call {
	char *macro_str;
	struct cil_macro *macro;
	struct cil_tree *args_tree;
	struct cil_list *args;
};

#define CIL_TRUE	1
#define CIL_FALSE	0

struct cil_booleanif {
	struct cil_tree_node *expr_stack;
};

struct cil_tunableif {
	symtab_t symtab[CIL_SYM_NUM];
	struct cil_tree_node *expr_stack;
};

struct cil_conditional {
	char *str;
	void *data;
	enum cil_flavor flavor;
};

struct cil_policycap {
	struct cil_symtab_datum datum;
};

int cil_db_init(struct cil_db **db);
void cil_db_destroy(struct cil_db **db);

void cil_destroy_data(void **data, enum cil_flavor flavor);

int cil_flavor_to_symtab_index(uint32_t flavor, uint32_t *index);

int cil_symtab_array_init(symtab_t symtab[], uint32_t symtab_num);
void cil_symtab_array_destroy(symtab_t symtab[]);
int cil_destroy_ast_symtabs(struct cil_tree_node *root);
int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, enum cil_sym_index sym_index);

int cil_sort_init(struct cil_sort **sort);
void cil_sort_destroy(struct cil_sort **sort);
int cil_netifcon_init(struct cil_netifcon **netifcon);
int cil_context_init(struct cil_context **context);
int cil_level_init(struct cil_level **level);
int cil_sens_init(struct cil_sens **sens);
int cil_block_init(struct cil_block **block);
int cil_class_init(struct cil_class **class);
int cil_common_init(struct cil_common **common);
int cil_classcommon_init(struct cil_classcommon **classcommon);
int cil_sid_init(struct cil_sid **sid);
int cil_sidcontext_init(struct cil_sidcontext **sidcontext);
int cil_userrole_init(struct cil_userrole **userrole);
int cil_userbounds_init(struct cil_userbounds **userbounds);
int cil_roledominance_init(struct cil_roledominance **roledominance);
int cil_rolebounds_init(struct cil_rolebounds **rolebounds);
int cil_roletype_init(struct cil_roletype **roletype);
int cil_attribute_init(struct cil_attribute **attribute);
int cil_attrtypes_init(struct cil_attrtypes **attrtypes);
int cil_typealias_init(struct cil_typealias **typealias);
int cil_typebounds_init(struct cil_typebounds **typebnds);
int cil_typepermissive_init(struct cil_typepermissive **typeperm);
int cil_filetransition_init(struct cil_filetransition **filetrans);
int cil_rangetransition_init(struct cil_rangetransition **rangetrans);
int cil_bool_init(struct cil_bool **cilbool);
int cil_boolif_init(struct cil_booleanif **bif);
int cil_conditional_init(struct cil_conditional **cond);
int cil_tunif_init(struct cil_tunableif **tif);
int cil_avrule_init(struct cil_avrule **avrule);
int cil_type_rule_init(struct cil_type_rule **type_rule);
int cil_role_trans_init(struct cil_role_trans **role_trans);
int cil_role_allow_init(struct cil_role_allow **role_allow);
int cil_sensalias_init(struct cil_sensalias **sensalias);
int cil_catalias_init(struct cil_catalias **catalias);
int cil_catset_init(struct cil_catset **catset);
int cil_senscat_init(struct cil_senscat **senscat);
int cil_filecon_init(struct cil_filecon **filecon);
int cil_portcon_init(struct cil_portcon **portcon);
int cil_nodecon_init(struct cil_nodecon **nodecon);
int cil_genfscon_init(struct cil_genfscon **genfscon);
int cil_pirqcon_init(struct cil_pirqcon **pirqcon);
int cil_iomemcon_init(struct cil_iomemcon **iomemcon);
int cil_ioportcon_init(struct cil_ioportcon **ioportcon);
int cil_pcidevicecon_init(struct cil_pcidevicecon **pcidevicecon);
int cil_fsuse_init(struct cil_fsuse **fsuse);
int cil_constrain_init(struct cil_constrain **constrain);
int cil_ipaddr_init(struct cil_ipaddr **ipaddr);
int cil_perm_init(struct cil_perm **perm);
int cil_permset_init(struct cil_permset **permset);
int cil_user_init(struct cil_user **user);
int cil_role_init(struct cil_role **role);
int cil_type_init(struct cil_type **type);
int cil_cat_init(struct cil_cat **cat);
int cil_catorder_init(struct cil_catorder **catorder);
int cil_sens_dominates_init(struct cil_sens_dominates **sens_dominates);
int cil_args_init(struct cil_args **args);
int cil_call_init(struct cil_call **call);
int cil_optional_init(struct cil_optional **optional);
int cil_param_init(struct cil_param **param);
int cil_macro_init(struct cil_macro **macro);
int cil_policycap_init(struct cil_policycap **policycap);

#endif
