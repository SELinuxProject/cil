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
#define CIL_DB			1
#define CIL_AST_NODE		2
#define CIL_PARSE_NODE		3
#define CIL_AST_STR		4
#define CIL_LIST		5
#define CIL_SEPOL_ID		6
#define CIL_AVRULE		7
#define CIL_SENS_DOM		8
#define CIL_LEVEL		9
#define CIL_SEARCH		10
#define CIL_TRANS_IF		11
#define CIL_TRANS_CALL		12
#define CIL_TRANS_INH_BLK	13
#define CIL_TRANS_INH_TYPE	14
#define CIL_TRANS_INH_ROLE	15
#define CIL_TRANS_DEL		16
#define CIL_TRANS_TRANS		17
#define CIL_IN			18
#define CIL_FILECON		19
#define CIL_PORTCON		20
#define CIL_NETIFCON		21
#define CIL_FSCON		22
#define CIL_FS_USE		23
#define CIL_CONSTRAIN		24
#define CIL_MLSCONSTRAIN	25
#define CIL_PERM		26
#define CIL_USERROLE		27
#define CIL_TYPE_ATTR		28
#define CIL_TYPE_RULE 		29
#define CIL_ROLETRANS		30
#define CIL_ROLEALLOW		31
#define CIL_ROLETYPE		32 
#define CIL_CATORDER		33
#define CIL_SENSCAT		34

#define CIL_BLOCK		CIL_MIN_DECLARATIVE
#define CIL_CLASS		CIL_MIN_DECLARATIVE + 1
#define CIL_COMMON		CIL_MIN_DECLARATIVE + 2
#define CIL_SID			CIL_MIN_DECLARATIVE + 3 
#define CIL_USER		CIL_MIN_DECLARATIVE + 4 
#define CIL_ROLE		CIL_MIN_DECLARATIVE + 5 
#define CIL_TYPE		CIL_MIN_DECLARATIVE + 7 
#define CIL_ATTR		CIL_MIN_DECLARATIVE + 8 
#define CIL_BOOL		CIL_MIN_DECLARATIVE + 9
#define CIL_TYPEALIAS		CIL_MIN_DECLARATIVE + 10
#define CIL_CONTEXT		CIL_MIN_DECLARATIVE + 11
#define CIL_SENS		CIL_MIN_DECLARATIVE + 12
#define CIL_CAT			CIL_MIN_DECLARATIVE + 13
#define CIL_SENSALIAS		CIL_MIN_DECLARATIVE + 14
#define CIL_CATALIAS		CIL_MIN_DECLARATIVE + 15
#define CIL_CATSET		CIL_MIN_DECLARATIVE + 16

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
#define CIL_KEY_USERROLE	"userrole"
#define CIL_KEY_ROLETYPE	"roletype"
#define CIL_KEY_ROLETRANS	"roletransition"
#define CIL_KEY_ROLEALLOW	"roleallow"
#define CIL_KEY_TYPE 		"type"
#define CIL_KEY_ATTR		"attribute"
#define CIL_KEY_BOOL		"bool"
#define CIL_KEY_ALLOW		"allow"
#define CIL_KEY_AUDITALLOW	"auditallow"
#define CIL_KEY_DONTAUDIT	"dontaudit"
#define CIL_KEY_NEVERALLOW	"neverallow"
#define CIL_KEY_TYPETRANS	"typetransition"
#define CIL_KEY_TYPECHANGE	"typechange"
#define CIL_KEY_TYPEMEMBER	"typemember"
#define CIL_KEY_TYPEATTR	"typeattribute"
#define CIL_KEY_TYPEALIAS	"typealias"
#define CIL_KEY_INTERFACE	"interface"
#define CIL_KEY_CONTEXT		"context"
#define CIL_KEY_NETIFCON	"netifcon"
#define CIL_KEY_SENSITIVITY	"sensitivity"
#define CIL_KEY_SENSALIAS	"sensitivityalias"
#define CIL_KEY_CATEGORY	"category"
#define CIL_KEY_CATALIAS	"categoryalias"
#define CIL_KEY_CATSET		"categoryset"
#define CIL_KEY_CATORDER	"categoryorder"
#define CIL_KEY_SENSCAT		"sensitivitycategory"
#define CIL_KEY_LEVEL		"level"
#define CIL_KEY_MLSCONSTRAIN	"mlsconstrain"

/*
	Symbol Table Array Indices
*/
#define CIL_SYM_FILENAMES	0
#define CIL_SYM_BLOCKS		1
#define CIL_SYM_USERS		2
#define CIL_SYM_ROLES		3
#define CIL_SYM_TYPES		4
#define CIL_SYM_COMMONS		5
#define CIL_SYM_CLASSES		6
#define CIL_SYM_BOOLS		7
#define CIL_SYM_SENS		8
#define CIL_SYM_CATS		9
#define CIL_SYM_SIDS		10
#define CIL_SYM_FILECONS	11
#define CIL_SYM_PORTCONS	12
#define CIL_SYM_NETIFCONS	13
#define CIL_SYM_MACROS		14
#define CIL_SYM_CONTEXTS	15
#define CIL_SYM_LEVELS		16

#define CIL_SYM_NUM		17
#define CIL_SYM_UNKNOWN		18

#define CIL_SYM_SIZE		256 	//TODO Need to determine symtab sizes

struct cil_db {
	struct cil_tree *ast;
	symtab_t symtab[CIL_SYM_NUM];
	symtab_t netif;
	struct cil_list *catorder;
	struct cil_list *dominance;
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
	uint16_t is_optional;
	/* TODO CDS we need to figure out how to handle conditionals */
	char *condition;
};

struct cil_class {
	struct cil_symtab_datum datum;
	symtab_t perms;
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
	char *context_str;
	struct cil_context *context;
};

struct cil_user {
	struct cil_symtab_datum datum;
};

struct cil_userrole {
	char *user_str;
	struct cil_user *user;
	char *role_str;
	struct cil_role *role;
};

struct cil_role {
	struct cil_symtab_datum datum;
};

/* TODO Waiting on design */
struct cil_role_dominates {
	char *role_str;
	struct cil_role *role;
	char *dominates_str;
	struct cil_role *dominates;
};

struct cil_roletype {
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
	char *attr_str;
	struct cil_type *attr;
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
};

struct cil_level {
	struct cil_symtab_datum datum;
	char *sens_str;
	struct cil_sens *sens;
	struct cil_list *cat_list_str;
	struct cil_list *cat_list;	
};

struct cil_transform_interface {
	struct cil_symtab_datum datum;
	struct cil_list_item *params;
};

struct cil_transform_call {
	struct cil_list_item *params;
	char *interface_str;
	//interface; 
};

#define CIL_INHERIT_BLOCK 1
#define CIL_INHERIT_ROLE  2
#define CIL_INHERIT_TYPE  3
struct cil_transform_inherit {
	struct cil_symtab_datum datum;
	char *inherit_from_str;
	void *inherit_from;
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

struct cil_filecon {
	struct cil_symtab_datum datum;
	struct cil_context *context;
};

struct cil_portcon {
	struct cil_symtab_datum datum; 
	struct cil_context *context;
	char *proto_str;
	//proto;
};

struct cil_netifcon {
	struct cil_symtab_datum datum;
	char *if_context_str;
	struct cil_context *if_context;
	char *packet_context_str;
	struct cil_context *packet_context;
};

/* There is no fs declaration, but we will create a cil_fs on demand when the cil_fscon or cil_fs_use statements need one */
struct cil_fs {
	struct cil_symtab_datum datum;
};

struct cil_fscon {
	char *fs_str;
	struct cil_fs *fs;
	char *path;
	struct cil_context context;
};

#define CIL_FS_USE_XATTR 1
#define CIL_FS_USE_TASK 2
#define CIL_FS_USE_TRANS 3
struct cil_fs_use {
	uint32_t flavor;
	char *fs_str;
	struct cil_fs *fs;
	struct cil_context context;
};

/*struct constrain {
	//Design
};*/

#define CIL_CONSTRAIN_KEYS "t1 t2 r1 r2 u1 u2 l1 l2 h1 h2"
#define CIL_CONSTRAIN_OPER "== != eq dom domby incomp and or"
struct cil_mlsconstrain {
	struct cil_list *class_list_str;
	struct cil_list *class_list;
	struct cil_list *perm_list_str;
	struct cil_list *perm_list;
	struct cil_tree *expr;
};

int cil_db_init(struct cil_db **);
void cil_db_destroy(struct cil_db **);
int cil_symtab_array_init(symtab_t [], uint32_t);
void cil_symtab_array_destroy(symtab_t []);
int cil_destroy_ast_symtabs(struct cil_tree_node *);
int cil_get_parent_symtab(struct cil_db *, struct cil_tree_node *, symtab_t **, uint32_t);
void cil_destroy_data(void **, uint32_t);

#endif
