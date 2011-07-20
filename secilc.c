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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>

#include "src/cil.h"
#include "src/cil_tree.h"
#include "src/cil_lexer.h"
#include "src/cil_parser.h"
#include "src/cil_build_ast.h"
#include "src/cil_resolve_ast.h"
#include "src/cil_fqn.h"
#include "src/cil_binary.h"
#include "src/cil_policy.h"
#include "src/cil_post.h"

#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

void usage(char *prog)
{
	printf("Usage: %s [-t|--target=<type>] [-M|--mls] [-c|--policyvers=<ver>] <files>...\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc = SEPOL_ERR;
	struct stat filedata;
	policydb_t pdb;
	uint32_t file_size;
	char *buffer;
	FILE *file;
	char output[10];
	struct cil_tree *parse_tree;
	struct cil_db *db;
	int target = SEPOL_TARGET_SELINUX;
	int mls = 0;
	int policyvers = POLICYDB_VERSION_MAX;
	int opt_char;
	int opt_index = 0;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"target", required_argument, 0, 't'},
		{"mls", no_argument, 0, 'M'},
		{"policyversion", required_argument, 0, 'c'},
		{0, 0, 0, 0}
	};
	int i;
	
	while (1) {
		opt_char = getopt_long(argc, argv, "ht:Mc:", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
			case 't':
				if (!strcmp(optarg, "selinux")) {
					target = SEPOL_TARGET_SELINUX;
				} else if (!strcmp(optarg, "xen")) {
					target = SEPOL_TARGET_XEN;
				} else {
					fprintf(stderr, "Unknown target: %s\n", optarg);
					usage(argv[0]);
				}
				break;
			case 'M':
				mls = 1;
				break;
			case 'c': {
				char *endptr = NULL;
				errno = 0;
				policyvers = strtol(optarg, &endptr, 10);
				if (errno != 0 || endptr == optarg || *endptr != '\0') {
					fprintf(stderr, "Bad policy version: %s\n", optarg);
					usage(argv[0]);
				}
				if (policyvers > POLICYDB_VERSION_MAX || policyvers < POLICYDB_VERSION_MIN) {
					fprintf(stderr, "Policy version must be between %d and %d\n",
					       POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
					usage(argv[0]);
				}
				break;
			}
			case 'h':
				usage(argv[0]);
			case '?':
				break;
			default:
				fprintf(stderr, "Unsupported option: %s\n", optarg);
				usage(argv[0]);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No cil files specified\n");
		usage(argv[0]);
	}
	
	cil_tree_init(&parse_tree);

	for (i = optind; i < argc; i++) {
		file = fopen(argv[i], "r");
		if (!file) {
			fprintf(stderr, "Could not open file: %s\n", argv[i]);
			goto exit;
		}
		if (stat(argv[i], &filedata) == -1) {
			fprintf(stderr, "Could not stat file: %s\n", argv[i]);
			goto exit;
		}
		file_size = filedata.st_size;	

		buffer = cil_malloc(file_size + 2);
		rc = fread(buffer, file_size, 1, file);
		if (rc != 1) {
			fprintf(stderr, "Failure reading file: %s\n", argv[i]);
			goto exit;
		}
		memset(buffer+file_size, 0, 2);
		fclose(file);
		file = NULL;

		printf("Building Parse Tree...\n");
		if (cil_parser(buffer, file_size + 2, &parse_tree)) {
			fprintf(stderr, "Failed to parse CIL policy, exiting\n");
			goto exit;
		}

		free(buffer);
		buffer = NULL;

#ifdef DEBUG
		cil_tree_print(parse_tree->root, 0);
#endif
	}
	
	cil_db_init(&db);

	printf("Building AST from Parse Tree...\n");
	if (cil_build_ast(db, parse_tree->root, db->ast->root)) {
		fprintf(stderr, "Failed to build ast, exiting\n");
		goto exit;
	}
#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif	
	printf("Destroying Parse Tree...\n");
	cil_tree_destroy(&parse_tree);

	printf("Resolving AST...\n");
	if (cil_resolve_ast(db, db->ast->root)) {
		fprintf(stderr, "Failed to resolve ast, exiting\n");
		goto exit;
	}

#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Destroying AST Symtabs...\n");
	if (cil_destroy_ast_symtabs(db->ast->root)) {
		fprintf(stderr, "Failed to destroy ast symtabs, exiting\n");
		goto exit;
	}

	printf("Qualifying Names...\n");
	if (cil_fqn_qualify(db->ast->root)) {
		fprintf(stderr, "Failed to qualify names, exiting\n");
		goto exit;
	}

	printf("Post process...\n");
	if (cil_post_process(db)) {
		fprintf(stderr, "Post process failed, exiting\n");
		goto exit;
	}

#ifdef DEBUG
	rc = cil_gen_policy(db);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to print to policy.conf file\n");
		goto exit;
	}
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Generating Binary...\n");
	policydb_init(&pdb);
	sepol_set_policydb(&pdb);
	pdb.policy_type = POLICY_KERN;
	pdb.policyvers = policyvers;
	pdb.mls = mls;
	rc = policydb_set_target_platform(&pdb, target);
	if (rc != 0) {
		fprintf(stderr, "Failed to set target platform: %d\n", rc);
		goto exit;
	}
	snprintf(output, 10, "policy.%d", policyvers);
	if (cil_binary_create(db, &pdb, output)) {
		fprintf(stderr, "Failed to generate binary, exiting\n");
		goto exit;
	}

	printf("Destroying DB...\n");
	policydb_destroy(&pdb);
	cil_db_destroy(&db);

	return SEPOL_OK;

exit:
	if (file != NULL) {
		fclose(file);
	}
	free(buffer);
	return SEPOL_ERR;
}
