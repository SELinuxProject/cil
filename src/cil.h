#ifndef CIL_H_
#define CIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "cil_symtab.h"
#include "cil_mem.h"

/*
	Tree/list node types
*/
#define CIL_MIN_DECLARATIVE	500

#define CIL_ROOT		0
#define CIL_PARSER		1
#define CIL_AST_STR		2
#define CIL_SEPOL_ID		3
#define CIL_AVRULE		4
#define CIL_SENS		5
#define CIL_SENS_DOM		6
#define CIL_CAT			7
#define CIL_LEVEL		8
#define CIL_SEARCH		9
#define CIL_TRANS_IF		10
#define CIL_TRANS_CALL		11
#define CIL_TRANS_INH_BLK	12
#define CIL_TRANS_INH_TYPE	13
#define CIL_TRANS_INH_ROLE	14
#define CIL_TRANS_DEL		15
#define CIL_TRANS_TRANS		16
#define CIL_IN			17
#define CIL_CONTEXT		18
#define CIL_FILECON		19
#define CIL_PORTCON		20
#define CIL_NETIFCON		21
#define CIL_FSCON		22
#define CIL_FS_USE		23
#define CIL_CONSTRAIN		24
#define CIL_MLS_CONSTRAIN	25
#define CIL_PERM		26


#define CIL_BLOCK		CIL_MIN_DECLARATIVE
#define CIL_CLASS		CIL_MIN_DECLARATIVE + 1
#define CIL_COMMON		CIL_MIN_DECLARATIVE + 2
#define CIL_SID			CIL_MIN_DECLARATIVE + 3 
#define CIL_USER		CIL_MIN_DECLARATIVE + 4 
#define CIL_ROLE		CIL_MIN_DECLARATIVE + 5 
#define CIL_ROLE_TYPES		CIL_MIN_DECLARATIVE + 6 
#define CIL_TYPE		CIL_MIN_DECLARATIVE + 7 
#define CIL_ATTR		CIL_MIN_DECLARATIVE + 8 
#define CIL_TYPE_ATTR		CIL_MIN_DECLARATIVE + 9 
#define CIL_BOOL		CIL_MIN_DECLARATIVE + 10
#define CIL_ROLE_RULE		CIL_MIN_DECLARATIVE + 11
#define CIL_TYPEALIAS		CIL_MIN_DECLARATIVE + 12

/*
	Keywords
*/
#define CIL_KEY_BLOCK 		"block"
#define CIL_KEY_CLASS		"class"
#define CIL_KEY_PERM		"perm"
#define CIL_KEY_COMMON		"common"
#define CIL_KEY_SID		"sid"
#define CIL_KEY_USER		"user"
#define CIL_KEY_ROLE 		"role"
#define CIL_KEY_ROLETYPE	"roletype"
#define CIL_KEY_TYPE 		"type"
#define CIL_KEY_ATTR		"attribute"
#define CIL_KEY_BOOL		"bool"
#define CIL_KEY_ALLOW		"allow"
#define CIL_KEY_AUDITALLOW	"auditallow"
#define CIL_KEY_DONTAUDIT	"dontaudit"
#define CIL_KEY_NEVERALLOW	"neverallow"
#define CIL_KEY_TYPETRANS	"typetrans"
#define CIL_KEY_TYPEATTR	"typeattribute"
#define CIL_KEY_TYPEALIAS	"typealias"
#define CIL_KEY_INTERFACE	"interface"

/*
	Symbol Table Array Indices
*/

// Global symtabs
#define CIL_SYM_GLOBAL_FILENAMES	0
#define CIL_SYM_GLOBAL_USERS		1
#define CIL_SYM_GLOBAL_ROLES		2
#define CIL_SYM_GLOBAL_COMMONS		3
#define CIL_SYM_GLOBAL_CLASSES		4
#define CIL_SYM_GLOBAL_BOOLS		5
#define CIL_SYM_GLOBAL_SENS		6
#define CIL_SYM_GLOBAL_CATS		7
#define CIL_SYM_GLOBAL_SIDS		8
#define CIL_SYM_GLOBAL_FILECONS		9
#define CIL_SYM_GLOBAL_PORTCONS		10
#define CIL_SYM_GLOBAL_NETIFCONS	11

#define CIL_SYM_GLOBAL_NUM		12

// Local symtabs
#define CIL_SYM_LOCAL_BLOCKS		0
#define CIL_SYM_LOCAL_TYPES		1
#define CIL_SYM_LOCAL_ATTRS		2
#define CIL_SYM_LOCAL_ALIASES		3
#define CIL_SYM_LOCAL_PERMS		4
// TODO CDS this should be MACRO, not INTERFACE
#define CIL_SYM_LOCAL_TRANS_INTERFACES	5

#define CIL_SYM_LOCAL_NUM		6

#define CIL_SYM_SIZE			256 	//TODO Need to determine symtab sizes

typedef uint32_t sepol_id_t;

struct cil_db {
	struct cil_tree *ast;
	symtab_t global_symtab[CIL_SYM_GLOBAL_NUM]; 	//Global namespace
	symtab_t local_symtab[CIL_SYM_LOCAL_NUM];	//Local namespace for top level declarations
};

struct cil_list {
	struct cil_list_item *list;
};

struct cil_list_item {
	struct cil_list_item *next;
	uint32_t flavor;
	void *data;
};

struct cil_search {
	//Design
	int x; //temporary while attempting to get this to compile
};

struct cil_block {
	struct cil_symtab_datum datum;
	symtab_t symtab[CIL_SYM_LOCAL_NUM];
	/* TODO CDS eventually, these should probably become a flags bit vector */
	uint16_t is_abstract;
	uint16_t is_optional;
	/* TODO CDS we need to figure out how to handle conditionals */
	char *condition;
};

struct cil_class {
	struct cil_symtab_datum datum;
	symtab_t perms;
	//(class msg inherits ipc (send receive))
	char *common_str;
	struct cil_common *common;
};

struct cil_perm {
	struct cil_symtab_datum datum;
};

struct cil_common {
	struct cil_symtab_datum datum;
	symtab_t perms;
};

struct cil_sid {
	struct cil_symtab_datum datum;
	struct cil_context *context;
};

struct cil_user {
	struct cil_symtab_datum datum;
};

struct cil_userrole {
	struct cil_user *user;
	struct cil_role *role;
};

struct cil_role {
	struct cil_symtab_datum datum;
};

struct cil_role_dominates {
	char *role_str;
	struct cil_role *role;
	char *dominates_str;
	struct cil_role *dominates;
};

struct cil_role_types {
	char *role_str;
	struct cil_role *role;
	char *type_str;
	struct cil_type *type;
};

struct cil_type	{//Also used for attributes
	struct cil_symtab_datum datum;
};

struct cil_typeattribute {
	char *type_str;
	struct cil_type *type;
	char *attrib_str;
	struct cil_type *attrib;
};

struct cil_typealias {
	struct cil_symtab_datum datum;
	char *type_str;
	struct cil_type *type;
};

struct cil_bool {
	struct cil_symtab_datum datum;
	uint16_t value;
};

#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_AUDITDENY   4
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
struct cil_avrule {
	uint32_t rule_kind;
	char *src_str;
	struct cil_type *src;
	char *tgt_str;	
	struct cil_type *tgt;
	char *obj_str;
	struct cil_class *obj;
	struct cil_list *perms_str;
	struct cil_list *perms_list;
};

#define CIL_AVRULE_TRANSITION 16
#define CIL_AVRULE_MEMBER     32
#define CIL_AVRULE_CHANGE     64
#define CIL_AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
struct cil_typerule {
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

// Define role_rule kinds here
struct cil_role_rule {
	uint32_t rule_kind;
	char *src_str;
	struct cil_role *src;
	char *tgt_str;	
	struct cil_role *tgt;
	/* TODO CDS this should match whatever cil_avrule does */
	char *obj_str;
	struct cil_class *obj;
	struct cil_list *perms;	
};

struct cil_sens {
	struct cil_symtab_datum datum;
};

struct cil_sens_dominates {
	struct cil_list_item *sens;
};

struct cil_cat {
	struct cil_symtab_datum datum;
};

struct cil_level {
	char *sens_str;
	struct cil_sens *sens;
	struct cil_list_item *cats;	
};

struct cil_transform_interface {
	struct cil_symtab_datum datum;
	struct cil_list_item *params;
};

struct cil_transform_call {
	struct cil_list_item *params;
	char *interface_str;
	sepol_id_t interface; 
};

#define CIL_INHERIT_BLOCK 1
#define CIL_INHERIT_ROLE  2
#define CIL_INHERIT_TYPE  3
struct cil_transform_inherit {
	struct cil_symtab_datum datum;
	char *inherit_from_str;
	sepol_id_t inherit_from;
	struct cil_list_item *except;
	uint32_t flavor;	
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
	char *user_str;
	struct cil_user *user;
	char *role_str;
	struct cil_role *role;
	char *type_str;
	struct cil_type *type;
	struct cil_level low;
	struct cil_level high;
};

struct cil_filecon {
	struct cil_symtab_datum datum;
	struct cil_context context;
};

struct cil_portcon {
	struct cil_symtab_datum datum; 
	struct cil_context context;
	char *proto_str;
	sepol_id_t proto;
};

struct cil_netifcon {
	struct cil_symtab_datum datum;
	struct cil_context if_context;
	struct cil_context packet_context;
};

/* There is no fs declaration, but we will create a cil_fs on demand when the cil_fscon or cil_fs_use statements need one */
struct cil_fs {
	struct cil_symtab_datum datum;
};

struct cil_fscon {
	char *fs_str;
	sepol_id_t fs;
	char *path;
	struct cil_context context;
};

#define CIL_FS_USE_XATTR 1
#define CIL_FS_USE_TASK 2
#define CIL_FS_USE_TRANS 3
struct cil_fs_use {
	uint32_t flavor;
	char *fs_str;
	sepol_id_t fs;
	struct cil_context context;
};

/*struct constrain {
	//Design
};

struct mls_constrain {
	//Design
};*/

int cil_db_init(struct cil_db **);
void cil_db_destroy(struct cil_db **);
int cil_list_init(struct cil_list **);
void cil_list_destroy (struct cil_list **);
int cil_list_item_init(struct cil_list_item **);
void cil_list_item_destroy(struct cil_list_item **);
int cil_parse_to_list(struct cil_tree_node *, struct cil_list **, uint32_t);
int cil_gen_perm_nodes(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
int cil_symtab_array_init(symtab_t [], uint32_t);
void cil_symtab_array_destroy(symtab_t []);
int cil_get_parent_symtab(struct cil_db *, struct cil_tree_node *, symtab_t **, uint32_t);
void cil_data_destroy(void **, uint32_t);

int cil_gen_block(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *, uint16_t, uint16_t, char *);
void cil_destroy_block(struct cil_block *);
int cil_gen_perm(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_perm(struct cil_perm *);
int cil_gen_class(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_class(struct cil_class *);
int cil_gen_common(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_common(struct cil_common *);
int cil_gen_sid(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_sid(struct cil_sid *);
int cil_gen_avrule(struct cil_tree_node *, struct cil_tree_node *, uint32_t);
void cil_destroy_avrule(struct cil_avrule *);
int cil_gen_type(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *, uint32_t);
void cil_destroy_type(struct cil_type *);
int cil_gen_user(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_user(struct cil_user *);
int cil_gen_role(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_role(struct cil_role *);
int cil_gen_bool(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_bool(struct cil_bool *);
int cil_gen_typealias(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_typealias(struct cil_typealias *);

#endif
