#ifndef CIL_H_
#define CIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sepol/policydb/symtab.h>

/*
	Tree/list node types
*/
#define CIL_PARSER		0
#define CIL_BLOCK		1
#define CIL_CLASS		2
#define CIL_COMMON		3
#define CIL_SID			4
#define CIL_USER		5
#define CIL_ROLE		6
#define CIL_ROLE_TYPES		7
#define CIL_TYPE		8
#define CIL_TYPE_ATTR		9
#define CIL_BOOL		10
#define CIL_AVRULE		11
#define CIL_ROLE_RULE		12
#define CIL_SENS		13
#define CIL_SENS_DOM		14
#define CIL_CAT			15
#define CIL_LEVEL		16
#define CIL_SEARCH		17
#define CIL_TRANS_IF		18
#define CIL_TRANS_CALL		19
#define CIL_TRANS_INH_BLK	20
#define CIL_TRANS_INH_TYPE	21
#define CIL_TRANS_INH_ROLE	22
#define CIL_TRANS_DEL		23
#define CIL_TRANS_TRANS		24
#define CIL_IN			25
#define CIL_CONTEXT		26
#define CIL_FILECON		27
#define CIL_PORTCON		28
#define CIL_NETIFCON		29
#define CIL_FSCON		30
#define CIL_FS_USE		31
#define CIL_CONSTRAIN		32
#define CIL_MLS_CONSTRAIN	33
#define CIL_PERM		34
#define CIL_TYPEALIAS		35

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
#define CIL_KEY_TYPEATTR	"typeattr"
#define CIL_KEY_TYPEALIAS	"typealias"
#define CIL_KEY_INTERFACE	"interface"

/*
	Symbol Table Array Indices
*/
/* TODO CDS why does this start at 1? */
#define CIL_SYM_FILES			1	//Filenames of modules
#define CIL_SYM_BLOCKS			2
#define CIL_SYM_CLASSES			3
#define CIL_SYM_PERMS			4
#define CIL_SYM_COMMONS			5
#define CIL_SYM_SIDS			6
#define CIL_SYM_USERS			7
#define CIL_SYM_ROLES			8
#define CIL_SYM_TYPES			9
#define CIL_SYM_ALIASES			10
#define CIL_SYM_BOOLS			11
#define CIL_SYM_SENS			12
#define CIL_SYM_CATS			13
#define CIL_SYM_FILECONS		14
#define CIL_SYM_PORTCONS		15
#define CIL_SYM_NETIFCONS		16
#define CIL_SYM_TRANS_INTERFACES	17
#define CIL_SYM_TRANS_INHERITS		18
#define CIL_SYM_ATTRS			19

#define CIL_SYM_NUM			20

/* TODO CDS Think about whether we need the self pointer for everything that is in a symtab for search/tranform uses */

/* TODO CDS just use uint32_t instead of sepol_id_t for now, as that's what the libsepol symtab uses */
typedef uint32_t sepol_id_t;

struct cil_db
{
	/* TODO CDS remove parse tree from here, as there will be 1 for each module that is freed after filling out the AST */
	struct cil_tree *parse_root;
	struct cil_tree *ast_root;
	
	symtab_t symtab[CIL_SYM_NUM];
};

struct cil_list_item
{
	struct cil_list_item *next;
	/* TODO CDS rename from item_class to flavor */
	uint32_t item_class;
	void *data;
};

struct cil_stack
{
	struct cil_stack_element *top;
};

struct cil_stack_element
{
	struct cil_stack_element *next;
	void *data;
};

struct cil_search
{
	//Design
	int x; //temporary while attempting to get this to compile
};

struct cil_block
{
	symtab_datum_t block;
	/* TODO CDS eventually, these should probably become a flags bit vector */
	uint16_t is_abstract;
	uint16_t is_optional;
	/* TODO CDS we need to figure out how to handle conditionals */
	char *condition;
	struct cil_tree_node *self;
};

struct cil_class
{
	symtab_datum_t cls;
	struct cil_list_item *av;
	sepol_id_t common;
};

struct cil_perm
{
	symtab_datum_t perm;
};

struct cil_common
{
	symtab_datum_t common;
	struct cil_list_item *av;
};

struct cil_sid
{
	symtab_datum_t sid;
	struct cil_context *context;
};

struct cil_user
{
	symtab_datum_t user;
};

/* TODO CDS need userrole statement to associate users with roles and userlevel statement to associate users with levels */

struct cil_role
{
	symtab_datum_t role;
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
	symtab_datum_t type;
};

struct cil_typeattribute
{
	sepol_id_t type;
	sepol_id_t attrib;
};

struct cil_typealias
{
	symtab_datum_t alias;
	sepol_id_t type;
};

struct cil_bool
{
	symtab_datum_t bool;
	uint16_t value;
};

#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_AUDITDENY   4
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)
struct cil_avrule
{
	uint32_t rule_kind;
	sepol_id_t src;	
	sepol_id_t tgt;
	struct cil_list_item *obj;
	uint32_t perms;	
};

#define CIL_AVRULE_TRANSITION 16
#define CIL_AVRULE_MEMBER     32
#define CIL_AVRULE_CHANGE     64
#define CIL_AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
struct cil_typerule
{
	uint32_t rule_kind;
	sepol_id_t src;
	sepol_id_t tgt;
	struct cil_list_item *obj;
	sepol_id_t result;
};

// Define role_rule kinds here
struct cil_role_rule
{
	uint32_t rule_kind;
	sepol_id_t src;	
	sepol_id_t tgt;
	/* TODO CDS this should match whatever cil_avrule does */
	sepol_id_t obj;
	uint32_t perms;	
};

struct cil_sens
{
	symtab_datum_t sens;
};

struct cil_sens_dominates
{
	struct cil_list_item *sens;
};

struct cil_cat
{
	symtab_datum_t cat;
};

struct cil_level
{
	sepol_id_t sens;
	struct cil_list_item *cats;	
};

struct cil_transform_interface
{
	symtab_datum_t interface;
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
	symtab_datum_t inherit_to;
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
	symtab_datum_t path;
	struct cil_context context;
};

struct cil_portcon
{
	symtab_datum_t port_range; 
	struct cil_context context;
	sepol_id_t proto;
};

struct cil_netifcon
{
	symtab_datum_t netif;
	struct cil_context if_context;
	struct cil_context packet_context;
};

/* There is no fs declaration, but we will create a cil_fs on demand when the cil_fscon or cil_fs_use statements need one */
struct cil_fs
{
	symtab_datum_t fs;
};

struct cil_fscon
{
	sepol_id_t fs;
	char *path;
	struct cil_context context;
};

#define CIL_FS_USE_XATTR 1
#define CIL_FS_USE_TASK 2
#define CIL_FS_USE_TRANS 3
struct cil_fs_use
{
	uint32_t flavor;
	sepol_id_t fs;
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

struct cil_db * cil_db_init();
struct cil_stack * cil_stack_init();
void cil_stack_push(struct cil_stack *, void *);
void * cil_stack_pop(struct cil_stack *);
char* cil_get_namespace_str(struct cil_stack *);

struct cil_block * cil_gen_block(struct cil_db *, struct cil_stack *, struct cil_tree_node *, struct cil_tree_node *, uint16_t, uint16_t, char*);
struct cil_class * cil_gen_class(struct cil_db *, char *, struct cil_tree_node*);
struct cil_perm * cil_gen_perm(struct cil_db *, char *, struct cil_tree_node*);
struct cil_common * cil_gen_common(struct cil_db *, char *, struct cil_tree_node*);
struct cil_sid * cil_gen_sid(struct cil_db *, char *, struct cil_tree_node*);
struct cil_avrule * cil_gen_avrule(struct cil_db *, char *, struct cil_tree_node *, uint32_t);
struct cil_type * cil_gen_type(struct cil_db *, char *, struct cil_tree_node *, uint32_t);
struct cil_role * cil_gen_role(struct cil_db *, char *, struct cil_tree_node*);
struct cil_bool * cil_gen_bool(struct cil_db *, char *, struct cil_tree_node*);
struct cil_typealias * cil_gen_typealias(struct cil_db *, char *, struct cil_tree_node*);

#endif
