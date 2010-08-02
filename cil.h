#ifndef CIL_H_
#define CIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/*
	Tree/list node types
*/
#define CIL_SEARCH		1
#define CIL_MODULE		2
#define CIL_BLOCK		3
#define CIL_CLASS		4
#define CIL_COMMON		5
#define CIL_SID			6
#define CIL_USER		7
#define CIL_ROLE		8
#define CIL_ROLE_TYPES		9
#define CIL_TYPE		10
#define CIL_TYPE_ATTR		11
#define CIL_BOOL		12
#define CIL_AVRULE		13
#define CIL_ROLE_RULE		14
#define CIL_SENS		15
#define CIL_SENS_DOM		16
#define CIL_CAT			17
#define CIL_LEVEL		18
#define CIL_TRANS_IF		19
#define CIL_TRANS_CALL		20
#define CIL_TRANS_INH_BLK	21
#define CIL_TRANS_INH_TYPE	22
#define CIL_TRANS_INH_ROLE	23
#define CIL_TRANS_DEL		24
#define CIL_TRANS_TRANS		25
#define CIL_IN			26
#define CIL_CONTEXT		27
#define CIL_FILECON		28
#define CIL_PORTCON		29
#define CIL_NETIFCON		30
#define CIL_FSCON		31
#define CIL_FS_USE		32
#define CIL_CONSTRAIN		33
#define CIL_MLS_CONSTRAIN	34
#define CIL_PERM		35

/*
	Keywords
*/
#define CIL_KEY_BLOCK 		"block"
#define CIL_KEY_CLASS		"class"
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
#define CIL_KEY_TYPEATTR	"typeattr"
#define CIL_KEY_TYPEALIAS	"typealias"
#define CIL_KEY_INTERFACE	"interface"

typedef uint16_t sepol_id_t;

struct sepol_symtab_datum 
{
	sepol_id_t value;
};

//const char* sepol_symtab_datum_id_to_name(struct sepol_symtab *symtab, sepol_id_t id);

struct cil_list_item
{
	struct cil_list_item *next;
	uint32_t item_class;
	void *data;
};

struct cil_search
{
	//Design
	int x; //temporary while attempting to get this to compile
};

struct cil_module
{
	struct sepol_symtab_datum name;
	struct cil_tree_node *self;
};

struct cil_block
{
	struct sepol_symtab_datum block;
	uint16_t is_abstract;
	uint16_t is_optional;
	char *condition;
	struct cil_tree_node *self;
};

struct cil_class
{
	struct sepol_symtab_datum cls;
	struct cil_list_item *av;
	sepol_id_t common;
};

struct cil_perm
{
	struct sepol_symtab_datum perm;
};

struct cil_common
{
	struct sepol_symtab_datum common;
	struct cil_list_item *av;
};

struct cil_sid
{
	struct sepol_symtab_datum sid;
};

struct cil_user
{
	struct sepol_symtab_datum user;
};

struct cil_role
{
	struct sepol_symtab_datum role;
};

struct cil_role_dominates
{
	sepol_id_t role;
	sepol_id_t dominates;
};

struct cil_role_types
{
	sepol_id_t role;
	sepol_id_t type;
};

struct cil_type	//Also used for attributes
{
	struct sepol_symtab_datum type;
};

struct cil_typeattribute
{
	sepol_id_t type;
	sepol_id_t attrib;
};

struct cil_typealias
{
	struct sepol_symtab_datum alias;
	sepol_id_t type;
};

struct cil_bool
{
	struct sepol_symtab_datum bool;
	uint16_t value;
};

#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_AUDITDENY   4
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
#define CIL_AVRULE_TRANSITION 16
#define CIL_AVRULE_MEMBER     32
#define CIL_AVRULE_CHANGE     64
#define CIL_AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
struct cil_avrule
{
	uint32_t rule_kind;
	sepol_id_t src;	
	sepol_id_t tgt;
	struct cil_list_item *obj;
	uint32_t perms;	
};

// Define role_rule kinds here
struct cil_role_rule
{
	uint32_t rule_kind;
	sepol_id_t src;	
	sepol_id_t tgt;
	sepol_id_t obj;
	uint32_t perms;	
};

struct cil_sens
{
	struct sepol_symtab_datum sens;
};

struct cil_sens_dominates
{
	struct cil_list_item *sens;
};

struct cil_cat
{
	struct sepol_symtab_datum cat;
};

struct cil_level
{
	sepol_id_t sens;
	struct cil_list_item *cats;	
};

struct cil_transform_interface
{
	struct sepol_symtab_datum interface;
	struct cil_list_item *params;
	struct cil_tree_node *self;
};

struct cil_transform_call
{
	struct cil_list_item *params;
	sepol_id_t interface; 
};

#define CIL_INHERIT_BLOCK 1
#define CIL_INHERIT_ROLE  2
#define CIL_INHERIT_TYPE  3
struct cil_transform_inherit
{
	struct sepol_symtab_datum inherit_to;
	sepol_id_t inherit_from;
	struct cil_list_item *except;
	uint32_t flavor;	
};

struct cil_transform_del
{
	struct cil_search target;
};

// This is the transform that modifies things in-place
struct cil_transform_transform
{
	struct cil_search target;
	// TODO: contents when we figure out what this will look like
};

struct cil_in
{
	struct cil_search target;
};

struct cil_context
{
	sepol_id_t user;
	sepol_id_t role;
	sepol_id_t type;
	struct cil_level low;
	struct cil_level high;
};

struct cil_filecon
{
	struct sepol_symtab_datum path;
	struct cil_context context;
};

struct cil_portcon
{
	struct sepol_symtab_datum port_range; 
	struct cil_context context;
	sepol_id_t proto;
};

struct cil_netifcon
{
	struct sepol_symtab_datum netif;
	struct cil_context if_context;
	struct cil_context packet_context;
};

struct cil_fscon
{
	sepol_id_t fs;
	sepol_id_t path;
	struct cil_context context;
};

#define CIL_FS_USE_XATTR 1
#define CIL_FS_USE_TASK 2
#define CIL_FS_USE_TRANS 3
struct cil_fs_use
{
	uint32_t flavor;
	struct sepol_symtab_datum fs;
	struct cil_context context;
};

/*struct constrain
{
	//Design
};

struct mls_constrain
{
	//Design
};*/

/* 
	Functions for creating and populating data structures above from parse tree nodes
*/

struct cil_block * gen_block(struct cil_tree_node *, struct cil_tree_node *, uint16_t, uint16_t, char*);
struct cil_avrule * gen_avrule(struct cil_tree_node *, uint32_t);
struct cil_type * gen_type(struct cil_tree_node *, uint32_t);
struct cil_role * gen_role(struct cil_tree_node*);
struct cil_bool * gen_bool(struct cil_tree_node*);

#endif
