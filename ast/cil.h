#define CIL_TYPE_TYPE 0
#define CIL_TYPE_ATTRIB 1
#define CIL_TYPE_ALIAS 2

#define CIL_AVRULE_ALLOWED     1
#define CIL_AVRULE_AUDITALLOW  2
#define CIL_AVRULE_AUDITDENY   4
#define CIL_AVRULE_DONTAUDIT   8
#define CIL_AVRULE_NEVERALLOW 128
#define CIL_AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT | AVRULE_NEVERALLOW)

#define CIL_TYPERULE_TRANSITION 16
#define CIL_TYPERULE_MEMBER     32
#define CIL_TYPERULE_CHANGE     64
#define CIL_TYPERULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)

typedef uint16_t sepol_id_t;

struct sepol_symtab_datum 
{
	sepol_id_t value;
};

const char* sepol_symtab_datum_id_to_name(struct sepol_symtab *symtab, sepol_id_t id);

struct cil_tree
{
	struct cil_tree_node *data;
};

struct cil_tree_node
{
	struct cil_tree_node *next;
	struct cil_tree *children;
	struct cil_tree_node *parent;
	uint32_t node_class;
	void *data;
};

struct cil_list
{
	struct cil_list_item *data;
};

struct cil_list_item
{
	struct cil_list_item *next;
	uint32_t item_class;
	void *data;
};

struct cil_module
{
	char *name;
};

struct cil_block
{
	char *name;
	uint32_t line_num;
};

struct cil_av
{
	sepol_symtab_datum datum;
	cil_list *av;
};

struct cil_av cil_common;
struct cil_av cil_class;

struct cil_sid
{
	sepol_symtab_datum sid;
};

struct cil_user
{
	sepol_symtab_datum user;
};

struct cil_type
{
	sepol_symtab_datum type;
	uint32_t flavor;
	uint32_t line_num;
};

struct cil_typeattribute
{
	sepol_id_t type;
	sepol_id_t attrib;
	uint32_t line_num;
};

struct cil_role
{
	sepol_symtab_datum role;
	uint32_t line_num;
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

struct cil_bool
{
	sepol_id_t bool;
	uint32_t value;
};

struct cil_rule
{
	uint32_t rule_kind;
	sepol_id_t src;	
	sepol_id_t tgt;
	sepol_id_t obj;
	uint32_t perms;	
	uint32_t line_num;
};

struct cil_rule cil_avrule;
struct cil_rule cil_role_rule;

struct cil_sens
{
	sepol_id_t sens;
};

struct cil_sens_dominates
{
	cil_list *sens;
};

struct cil_cat
{
	sepol_id_t cat;
};

struct cil_level
{
	sepol_id_t sens;
	struct cil_list *cats;	
};

struct cil_filecontext 
{
	sepol_id_t user;
	sepol_id_t role;
	sepol_id_t type;
	struct cil_level level; 
	char * path;
};


//interfaces, templates, classes, conditionals?

struct cil_index_node
{
	struct cil_tree_node *attr;
	struct cil_index_node* next;
};

struct cil_index_node *attr_type_index;

