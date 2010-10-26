#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sepol/policydb/symtab.h>
#include <sepol/policydb/policydb.h>
#include "CuTest.h"
#include "../../src/cil_tree.h"
#include "../../src/cil_lexer.h"
#include "../../src/cil.h"
#include "../../src/cil_mem.h"
#include "../../src/cil_symtab.h"
#include "../../src/cil_ast.h"
#include "../../src/cil_parser.h"

// TODO Check more in the data structures
struct cil_file_data {
	char *buffer;
	uint32_t file_size;
};

void set_cil_file_data(struct cil_file_data **data) {
	struct cil_file_data *new_data = malloc(sizeof(struct cil_file_data));
	FILE *file;
	struct stat filedata;
	uint32_t file_size;
	char *buffer;

	file = fopen("testing/test.txt", "r");
	if (!file) {
	    fprintf(stderr, "Could not open file\n");
	    exit(1);
	}
	if (stat("testing/test.txt", &filedata) == -1) {
	    printf("Could not stat file\n");
	    exit(1);
	}
	file_size = filedata.st_size;

	buffer = malloc(file_size + 2);
	fread(buffer, file_size, 1, file);
	memset(buffer+file_size, 0, 2);
	fclose(file);


	new_data->buffer = buffer;
	new_data->file_size = file_size;

	*data = new_data;

}

void gen_test_tree(struct cil_tree **test_root, char *line[]) {
	struct cil_tree *new_tree = malloc(sizeof(struct cil_tree));
	struct cil_tree_node *node, *item, *current;

	cil_tree_init(&new_tree);
	new_tree->root->flavor = CIL_ROOT;
	current = new_tree->root;
	
	char **i = line;
	do {
	    if (*i == (char*)"(") {
	        cil_tree_node_init(&node);
	        node->parent = current;
	        node->flavor = CIL_PARSER;
	        node->line = 0;
	        if (current->cl_head == NULL)
	            current->cl_head = node;
	        else
	            current->cl_tail->next = node;
	        current->cl_tail = node;
	        current = node;
	    }
	    else if (*i == (char*)")")
	        current = current->parent;
	    else {
	        cil_tree_node_init(&item);
	        item->parent = current;
	        item->data = cil_strdup(*i);
	        item->flavor = CIL_PARSER;
	        item->line = 0;
	        if (current->cl_head == NULL) {
	            current->cl_head = item;
	        }
	        else {
	            current->cl_tail->next = item;
	        }
	        current->cl_tail = item;
	    }
	    i++;
	} while(*i != NULL);

	*test_root = new_tree;
}

void test_cil_tree_node_init(CuTest *tc) {
   struct cil_tree_node *test_node;

   int rc = cil_tree_node_init(&test_node);

   CuAssertIntEquals(tc, SEPOL_OK, rc);
   CuAssertPtrNotNull(tc, test_node);
   CuAssertPtrEquals(tc, NULL, test_node->cl_head);
   CuAssertPtrEquals(tc, NULL, test_node->cl_tail);
   CuAssertPtrEquals(tc, NULL, test_node->parent);
   CuAssertPtrEquals(tc, NULL, test_node->data);
   CuAssertPtrEquals(tc, NULL, test_node->next);
   CuAssertIntEquals(tc, 0, test_node->flavor);
   CuAssertIntEquals(tc, 0, test_node->line);

   free(test_node);
}

void test_cil_tree_init(CuTest *tc) {
	struct cil_tree *test_tree;

	int rc = cil_tree_init(&test_tree);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_tree);
	CuAssertPtrEquals(tc, NULL, test_tree->root->cl_head);
	CuAssertPtrEquals(tc, NULL, test_tree->root->cl_tail);
	CuAssertPtrEquals(tc, NULL, test_tree->root->parent);
	CuAssertPtrEquals(tc, NULL, test_tree->root->data);
	CuAssertPtrEquals(tc, NULL, test_tree->root->next);
	CuAssertIntEquals(tc, 0, test_tree->root->flavor);
	CuAssertIntEquals(tc, 0, test_tree->root->line);

	free(test_tree);
}

void test_symtab_init(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	uint32_t rc = 0, i =0;
	
	for (i=0; i<CIL_SYM_GLOBAL_NUM; i++) {
	    rc = symtab_init(&test_new_db->global_symtab[i], CIL_SYM_SIZE);
	    CuAssertIntEquals(tc, 0, rc);
	    // TODO CDS add checks to make sure the symtab looks correct
	}

	free(test_new_db);
}

void test_symtab_init_no_table_neg(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	int rc = symtab_init(&test_new_db->global_symtab[0], (uint32_t)SIZE_MAX);
	CuAssertIntEquals(tc, -1, rc);

	free(test_new_db);
}

void test_cil_symtab_array_init(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	int rc = cil_symtab_array_init(test_new_db->global_symtab, CIL_SYM_GLOBAL_NUM);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_new_db->global_symtab);

	free(test_new_db);
}

// TODO: Reach SEPOL_ERR return in cil_symtab_array_init ( currently can't produce a method to do so )
void test_cil_symtab_array_init_null_symtab_neg(CuTest *tc) {
	symtab_t *test_symtab = NULL;

	int rc = cil_symtab_array_init(test_symtab, 1);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_db_init(CuTest *tc) {
	struct cil_db *test_db;

	int rc = cil_db_init(&test_db);

	CuAssertIntEquals(tc, 0, rc);
	CuAssertPtrNotNull(tc, test_db->ast);
	CuAssertPtrNotNull(tc, test_db->global_symtab);
	CuAssertPtrNotNull(tc, test_db->local_symtab);
}

// TODO: Reach SEPOL_ERR return in cil_db_init ( currently can't produce a method to do so )

// TODO rewrite to use the gen_tree function
void test_cil_parser(CuTest *tc) {
	int rc = 0;
	struct cil_file_data *data;

	struct cil_tree *test_parse_root;
	cil_tree_init(&test_parse_root);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	set_cil_file_data(&data);

	rc = cil_parser(data->buffer, data->file_size + 2, &test_parse_root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_parse_root);
	// TODO add checking of the parse tree that is returned
}

void test_cil_lexer_setup(CuTest *tc) {
   char *test_str = "(test \"qstring\");comment\n";
   uint32_t str_size = strlen(test_str);
   char *buffer = malloc(str_size + 2);

   memset(buffer+str_size, 0, 2);
   strncpy(buffer, test_str, str_size);

   int rc = cil_lexer_setup(buffer, str_size + 2);
   CuAssertIntEquals(tc, SEPOL_OK, rc);

   free(buffer);
}

void test_cil_lexer_next(CuTest *tc) {
   char *test_str = "(test \"qstring\") ;comment\n";
   uint32_t str_size = strlen(test_str);
   char *buffer = malloc(str_size + 2);

   memset(buffer+str_size, 0, 2);
   strcpy(buffer, test_str);

   cil_lexer_setup(buffer, str_size + 2);

   struct token *test_tok;

   int rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);

   CuAssertIntEquals(tc, OPAREN, test_tok->type);
   CuAssertStrEquals(tc, "(", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, SYMBOL, test_tok->type);
   CuAssertStrEquals(tc, "test", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, QSTRING, test_tok->type);
   CuAssertStrEquals(tc, "\"qstring\"", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, CPAREN, test_tok->type);
   CuAssertStrEquals(tc, ")", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
  
   CuAssertIntEquals(tc, COMMENT, test_tok->type);
   CuAssertStrEquals(tc, ";comment", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   free(buffer);
}

void test_cil_get_parent_symtab_block(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_BLOCK;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_class(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_CLASS;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_root(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_ROOT;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_other_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = 1234567;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

void test_cil_get_parent_symtab_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

void test_cil_get_parent_symtab_node_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
	CuAssertPtrEquals(tc, test_ast_node, NULL);
}

void test_cil_get_parent_symtab_parent_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

void test_cil_symtab_insert(CuTest *tc) {
	symtab_t *test_symtab = NULL;
	char* test_name = "test";
	struct cil_block *test_block = malloc(sizeof(struct cil_block));

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);   

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_array_init(test_block->symtab, CIL_SYM_LOCAL_NUM);

	test_block->is_abstract = 0;
	test_block->is_optional = 0;
	test_block->condition = NULL;

	cil_get_parent_symtab(test_db, test_ast_node, &test_symtab, CIL_SYM_LOCAL_BLOCKS);

	int rc = cil_symtab_insert(test_symtab, (hashtab_key_t)test_name, (struct cil_symtab_datum*)test_block, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_block*)test_ast_node->data)->is_abstract, 0);
	CuAssertIntEquals(tc, ((struct cil_block*)test_ast_node->data)->is_optional, 0);
	CuAssertPtrEquals(tc, ((struct cil_block*)test_ast_node->data)->condition, NULL);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BLOCK);
}

void test_cil_gen_block_noname_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_treenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	tree->root->cl_head->cl_head = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodeparentnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_destroy_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);

	cil_destroy_block((struct cil_block*)test_ast_node->data);
	CuAssertPtrEquals(tc, NULL,test_ast_node->data);
}

void test_cil_gen_perm(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	while(test_current_perm != NULL) {
	    cil_tree_node_init(&test_new_ast);
	    test_new_ast->parent = test_ast_node;
	    test_new_ast->line = test_current_perm->line;

	    rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	    CuAssertIntEquals(tc, SEPOL_OK, rc);
	    CuAssertPtrNotNull(tc, test_new_ast->data);
	    CuAssertIntEquals(tc, test_new_ast->flavor, CIL_PERM);
	    
	    test_current_perm = test_current_perm->next;

	    if (test_ast_node->cl_head == NULL)
	        test_ast_node->cl_head = test_new_ast;
	    else
	        test_ast_node->cl_tail->next = test_new_ast;

	    test_ast_node->cl_tail = test_new_ast;
	}
}

void test_cil_gen_perm_dbnull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_currnull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = NULL; 

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_permexists_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	struct cil_perm *test_perm = malloc(sizeof(struct cil_perm));
	symtab_t *test_symtab = NULL;
	cil_get_parent_symtab(test_db, test_ast_node, &test_symtab, CIL_SYM_LOCAL_PERMS);
	cil_symtab_insert(test_symtab, (hashtab_key_t)"read", (struct cil_symtab_datum*)test_perm, test_new_ast);

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_gen_perm_nodenull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodes(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->global_symtab[CIL_SYM_GLOBAL_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_perm_nodes_failgen_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	//symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->global_symtab[CIL_SYM_GLOBAL_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class(CuTest *tc) { 
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->cl_tail);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_CLASS);
}

void test_cil_gen_class_noname_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	tree->root->cl_head->cl_head = NULL;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_noclass_neg(CuTest *tc) { 
	char *line[] = {"(", "test", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_failgen_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->cl_tail);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_CLASS);

}

void test_cil_gen_perm_noname_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	while(test_current_perm != NULL) {
	    cil_tree_node_init(&test_new_ast);
	    test_new_ast->parent = test_ast_node;
	    test_new_ast->line = test_current_perm->line;

	    rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	    CuAssertIntEquals(tc, SEPOL_ERR, rc);
	    
	    test_current_perm = test_current_perm->next;

	    if (test_ast_node->cl_head == NULL)
	        test_ast_node->cl_head = test_new_ast;
	    else
	        test_ast_node->cl_tail->next = test_new_ast;

	    test_ast_node->cl_tail = test_new_ast;
	}
}

void test_cil_list_init(CuTest *tc) {
	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));

	int rc = cil_list_init(&test_avrule->perms_str);
	CuAssertIntEquals(tc, SEPOL_OK, rc);

	free(test_avrule);   
}

// First seen in cil_gen_common
void test_cil_parse_to_list(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	cil_list_init(&test_avrule->perms_str);

	test_current = test_current->next->next->next->next->cl_head;

	int rc = cil_parse_to_list(test_current, &test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_OK, rc);

	free(test_avrule->perms_str);
	test_avrule->perms_str = NULL;
	free(test_avrule);
}

void test_cil_parse_to_list_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	cil_list_init(&test_avrule->perms_str);

	test_current = NULL;

	int rc = cil_parse_to_list(test_current, &test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

	free(test_avrule->perms_str);
	test_avrule->perms_str = NULL;
	free(test_avrule);
}

void test_cil_parse_to_list_listnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	test_current = test_current->next->next->next->next->cl_head;

	int rc = cil_parse_to_list(test_current, &test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

	free(test_avrule);
}

void test_cil_gen_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_common(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_COMMON);
}

void test_cil_gen_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SID);
}

void test_cil_gen_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE);
}

void test_cil_gen_type_attr(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ATTR);
}

void test_cil_gen_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_typealias*)test_ast_node->data)->type_str, tree->root->cl_head->cl_head->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPEALIAS);
}

void test_cil_gen_typealias_incomplete_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_incomplete_neg2(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_role(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLE);
}

void test_cil_gen_bool_true(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 1);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_false(CuTest *tc) {
	char *line[] = {"(", "bool", "bar", "false", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 0);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_none_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_notbool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "bar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->src_str, test_current->next->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->tgt_str, test_current->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->obj_str, test_current->next->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_AVRULE);
	CuAssertPtrNotNull(tc, ((struct cil_avrule*)test_ast_node->data)->perms_str);

	struct cil_list_item *test_list = ((struct cil_avrule*)test_ast_node->data)->perms_str->list;
	test_current = test_current->next->next->next->next->cl_head;

	while(test_list != NULL) {
	    CuAssertIntEquals(tc, test_list->flavor, CIL_AST_STR);
	    CuAssertStrEquals(tc, test_list->data, test_current->data );
	    test_list = test_list->next;
	    test_current = test_current->next;
	}
}

void test_cil_gen_avrule_notlist_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "write", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, CIL_USER, test_ast_node->flavor);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertPtrEquals(tc, test_ast_node, ((struct cil_symtab_datum*)test_ast_node->data)->node);
	CuAssertStrEquals(tc, tree->root->cl_head->cl_head->next->data, ((struct cil_symtab_datum*)test_ast_node->data)->name);
}

void test_cil_gen_user_nouser_neg(CuTest *tc) {
	char *line[] = {"(", "user", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_xsinfo_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", "xsinfo", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *null_db = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(null_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_suberr_neg(CuTest *tc) {
	char *line[] = {"(", "block", "test", "(", "block", "(", "type", "log", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_treenull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_block(CuTest *tc) {
	char *line[] = {"(", "block", "test", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_block_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

}

void test_cil_build_ast_class(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_class_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_common_neg(CuTest *tc) {
	char *line[] = {"(", "common", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_sid_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "(", "blah", "blah", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_neg(CuTest *tc) {
	char *line[] = {"(", "type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_typeattr(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_typeattr_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_typealias_notype_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_role_neg(CuTest *tc) {
	char *line[] = {"(", "role", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_avrule_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_bool(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_bool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_name(CuTest *tc) {
	char *line[] = { "(", "block", "foo", "(", "typealias", "test", "type_t", ")", "(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	struct cil_tree_node *test_curr = test_db->ast->root->cl_head->cl_head;
	struct cil_typealias *test_alias = (struct cil_typealias*)test_curr->data;
	struct cil_tree_node *type_node = NULL;

	int rc = cil_resolve_name(test_db, test_curr, test_alias->type_str, CIL_SYM_LOCAL_TYPES, &type_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_name_invalid_type_neg(CuTest *tc) {
	char *line[] = { "(", "block", "foo", "(", "typealias", "foo.test2", "type_t", ")", "(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	struct cil_tree_node *test_curr = test_db->ast->root->cl_head->cl_head;
	struct cil_typealias *test_alias = (struct cil_typealias*)test_curr->data;
	struct cil_tree_node *type_node = NULL;

	int rc = cil_resolve_name(test_db, test_curr, test_alias->type_str, CIL_SYM_LOCAL_TYPES, &type_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_typealias(CuTest *tc) {
	char *line[] = { "(", "block", "foo", "(", "typealias", ".foo.test", "type_t", ")", "(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_typealias(test_db, test_db->ast->root->cl_head->cl_head);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_typealias(CuTest *tc) {
	char *line[] = { "(", "block", "foo", "(", "typealias", ".foo.test", "type_t", ")", "(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_typealias_notype_neg(CuTest *tc) {
	char *line[] = {"(", "block", "bar", "(", "typealias", ".bar.test", "type_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_curr_null_neg(CuTest *tc) {
	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_avrule(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", \
	                "(", "type", "test", ")", "(", "type", "foo", ")", \
	                "(", "allow", "test", "foo", "bar", "(", "read", "write", \
	                ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_avrule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_avrule(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", \
	                "(", "type", "test", ")", "(", "type", "foo", ")", \
	                "(", "allow", "test", "foo", "bar", "(", "read", "write", \
	                ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_avrule_src_nores_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_avrule_tgt_nores_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", "(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_avrule_class_nores_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", "(", "type", "foo", ")", "(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_avrule_datum_null_neg(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", \
	                "(", "type", "test", ")", "(", "type", "foo", ")", \
	                "(", "allow", "test", "foo", "bar", "(","fake", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

CuSuite* CilTreeGetSuite() {
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, test_cil_tree_node_init);
	SUITE_ADD_TEST(suite, test_cil_tree_init);
	SUITE_ADD_TEST(suite, test_cil_lexer_setup);
	SUITE_ADD_TEST(suite, test_cil_lexer_next);
	SUITE_ADD_TEST(suite, test_symtab_init);
	SUITE_ADD_TEST(suite, test_symtab_init_no_table_neg);
	SUITE_ADD_TEST(suite, test_cil_symtab_array_init);
//  Cannot get symtab_init to fail
//	SUITE_ADD_TEST(suite, test_cil_symtab_array_init_null_symtab_neg);
	SUITE_ADD_TEST(suite, test_cil_db_init);
	SUITE_ADD_TEST(suite, test_cil_parser);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_block);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_class);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_root);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_other_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_null_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_node_null_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_parent_null_neg);
	SUITE_ADD_TEST(suite, test_cil_symtab_insert);
	SUITE_ADD_TEST(suite, test_cil_gen_block);
	SUITE_ADD_TEST(suite, test_cil_gen_block_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_treenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_nodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_nodeparentnull_neg);
//  Not setting pointers to NULL, unable to verify
//	SUITE_ADD_TEST(suite, test_cil_destroy_block);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodes);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodes_failgen_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class);
	SUITE_ADD_TEST(suite, test_cil_gen_class_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_nodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_noclass_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_permexists_neg);
//  Causes a segfault
//	SUITE_ADD_TEST(suite, test_cil_gen_perm_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_list_init);
	SUITE_ADD_TEST(suite, test_cil_parse_to_list);
	SUITE_ADD_TEST(suite, test_cil_parse_to_list_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_parse_to_list_listnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common);
	SUITE_ADD_TEST(suite, test_cil_gen_sid);
	SUITE_ADD_TEST(suite, test_cil_gen_type);
	SUITE_ADD_TEST(suite, test_cil_gen_type_attr);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_incomplete_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_incomplete_neg2);
	SUITE_ADD_TEST(suite, test_cil_gen_role);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_true);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_false);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_none_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_notbool_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_notlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user);
	SUITE_ADD_TEST(suite, test_cil_gen_user_nouser_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user_xsinfo_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast);
	SUITE_ADD_TEST(suite, test_cil_build_ast_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_treenull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_suberr_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_block);
	SUITE_ADD_TEST(suite, test_cil_build_ast_block_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_class);
	SUITE_ADD_TEST(suite, test_cil_build_ast_class_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_common);
	SUITE_ADD_TEST(suite, test_cil_build_ast_common_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_sid);
//	Causes a segfault
//	SUITE_ADD_TEST(suite, test_cil_build_ast_sid_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_type);
	SUITE_ADD_TEST(suite, test_cil_build_ast_type_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_typeattr);
	SUITE_ADD_TEST(suite, test_cil_build_ast_typeattr_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_typealias);
	SUITE_ADD_TEST(suite, test_cil_build_ast_typealias_notype_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_role);
	SUITE_ADD_TEST(suite, test_cil_build_ast_role_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_bool);
	SUITE_ADD_TEST(suite, test_cil_build_ast_bool_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_avrule);
	SUITE_ADD_TEST(suite, test_cil_build_ast_avrule_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_name);
	SUITE_ADD_TEST(suite, test_cil_resolve_name_invalid_type_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_typealias);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_typealias);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_curr_null_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_typealias_notype_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_avrule);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_avrule);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_avrule_src_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_avrule_tgt_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_avrule_class_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_avrule_datum_null_neg);

	return suite;
}
