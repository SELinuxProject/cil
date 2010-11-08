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
#define CIL_LIST		3
#define CIL_SEPOL_ID		4
#define CIL_AVRULE		5
#define CIL_SENS_DOM		6
#define CIL_LEVEL		7
#define CIL_SEARCH		8
#define CIL_TRANS_IF		9
#define CIL_TRANS_CALL		10
#define CIL_TRANS_INH_BLK	11
#define CIL_TRANS_INH_TYPE	12
#define CIL_TRANS_INH_ROLE	13
#define CIL_TRANS_DEL		14
#define CIL_TRANS_TRANS		15
#define CIL_IN			16
#define CIL_FILECON		17
#define CIL_PORTCON		18
#define CIL_NETIFCON		19
#define CIL_FSCON		20
#define CIL_FS_USE		21
#define CIL_CONSTRAIN		22
#define CIL_MLS_CONSTRAIN	23
#define CIL_PERM		24
#define CIL_USERROLE		25
#define CIL_TYPE_ATTR		26
#define CIL_TYPE_RULE 		27
#define CIL_ROLETRANS		28
#define CIL_ROLEALLOW		29
#define CIL_ROLETYPE		30 

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
#define CIL_KEY_SENSITIVITY	"sensitivity"
#define CIL_KEY_SENSALIAS	"sensitivityalias"
#define CIL_KEY_CATEGORY	"category"
#define CIL_KEY_CATALIAS	"categoryalias"
#define CIL_KEY_CATSET		"categoryset"

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


typedef uint32_t sepol_id_t;

struct cil_db {
	struct cil_tree *ast;
	symtab_t symtab[CIL_SYM_NUM];
};

struct cil_list {
	struct cil_list_item *head;
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
	char *user_str;
	struct cil_user *user;
	char *role_str;
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
};

struct cil_sensalias {
	struct cil_symtab_datum datum;
	char *sens_str;
	struct cil_sens *sens;
};

struct cil_sens_dominates {
	struct cil_list_item *sens;
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

struct cil_level {
	char *sens_str;
	struct cil_sens *sens;
	struct cil_list *cats_str;
	struct cil_list *cats;	
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
	sepol_id_t proto;
};

struct cil_netifcon {
	struct cil_symtab_datum datum;
	struct cil_context *if_context;
	struct cil_context *packet_context;
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
void cil_list_destroy (struct cil_list **, uint8_t);
int cil_list_item_init(struct cil_list_item **);
void cil_list_item_destroy(struct cil_list_item **, uint8_t);
int cil_parse_to_list(struct cil_tree_node *, struct cil_list *, uint32_t);
int cil_gen_perm_nodes(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
int cil_symtab_array_init(symtab_t [], uint32_t);
void cil_symtab_array_destroy(symtab_t []);
int cil_get_parent_symtab(struct cil_db *, struct cil_tree_node *, symtab_t **, uint32_t);
void cil_destroy_data(void **, uint32_t);

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
int cil_gen_type_rule(struct cil_tree_node *, struct cil_tree_node *, uint32_t);
void cil_destroy_type_rule(struct cil_type_rule *);
int cil_gen_type(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *, uint32_t);
void cil_destroy_type(struct cil_type *);
int cil_gen_user(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_user(struct cil_user *);
int cil_gen_role(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_role(struct cil_role *);
int cil_gen_userrole(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_userrole(struct cil_userrole *);
int cil_gen_roletype(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_roletype(struct cil_roletype *);
int cil_gen_roletrans(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_roletrans(struct cil_role_trans *);
int cil_gen_roleallow(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_roleallow(struct cil_role_allow *);
int cil_gen_bool(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_bool(struct cil_bool *);
int cil_gen_typealias(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_typealias(struct cil_typealias *);
int cil_gen_typeattr(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_typeattr(struct cil_typeattribute *);
int cil_gen_sensitivity(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_sensitivity(struct cil_sens *);
int cil_gen_category(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_category(struct cil_cat *);
int cil_gen_sensalias(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_sensalias(struct cil_sensalias *);
int cil_gen_catalias(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_catalias(struct cil_catalias *);
int cil_catset_to_list(struct cil_tree_node *, struct cil_list *, uint32_t);
int cil_gen_catset(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_catset(struct cil_catset *);
int cil_gen_context(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
void cil_destroy_context(struct cil_context *);


#endif
