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
#include <string.h>
#include <getopt.h>

#include <cil/cil.h>
#include <sepol/policydb.h>

void usage(char *prog)
{
	printf("Usage: %s [-v|--verbose] [-t|--target=<type>] [-M|--mls] [-c|--policyvers=<ver>] [-U|--handle-unknown]<files>...\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc = SEPOL_ERR;
	sepol_policydb_t *pdb = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *binary = NULL;
	FILE *file_contexts;
	char output[10];
	struct cil_db *db = NULL;
	int target = SEPOL_TARGET_SELINUX;
	int mls = 0;
	int handle_unknown = SEPOL_DENY_UNKNOWN;
	int policyvers = POLICYDB_VERSION_MAX;
	int opt_char;
	int opt_index = 0;
	char *fc_buf = NULL;
	size_t fc_size;
	enum cil_log_level log_level = CIL_ERR;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"log", required_argument, 0, 'l'},
		{"target", required_argument, 0, 't'},
		{"mls", no_argument, 0, 'M'},
		{"policyversion", required_argument, 0, 'c'},
		{"handle-unknown", required_argument, 0, 'U'},
		{0, 0, 0, 0}
	};

	while (1) {
		opt_char = getopt_long(argc, argv, "hvt:Mc:", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
			case 'v':
				log_level++;
				break;
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
			case 'U':
				if (!strcasecmp(optarg, "deny")) {
					handle_unknown = SEPOL_DENY_UNKNOWN;
				} else if (!strcasecmp(optarg, "allow")) {
					handle_unknown = SEPOL_ALLOW_UNKNOWN;
				} else if (!strcasecmp(optarg, "reject")) {
					handle_unknown = SEPOL_REJECT_UNKNOWN;
				} else {
					usage(argv[0]);
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

	cil_set_log_level(log_level);

	cil_db_init(&db);

	rc = cil_parse_files(db, argv + optind, argc - optind);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to parse files\n");
		goto exit;
	}

	sepol_policydb_create(&pdb);
	pdb->p.policy_type = POLICY_KERN;
	pdb->p.mls = mls;
	pdb->p.target_platform = target;
	
	rc = sepol_policydb_set_vers(pdb, policyvers);
	if (rc != 0) {
		fprintf(stderr, "Failed to set policy version: %d\n", rc);
		goto exit;
	}

	rc = sepol_policydb_set_handle_unknown(pdb, handle_unknown);
	if (rc != 0) {
		fprintf(stderr, "Failed to set handle unknown: %d\n", rc);
		goto exit;
	}

	rc = cil_db_to_sepol_policydb(db, pdb);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to build policydb\n");
		goto exit;
	}

	if (log_level >= CIL_INFO) {
		fprintf(stderr, "Writing Binary: %s...\n", output);
	}

	snprintf(output, 10, "policy.%d", policyvers);
	binary = fopen(output, "w");
	if (binary == NULL) {
		fprintf(stderr, "Failure opening binary file for writing\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = sepol_policy_file_create(&pf);
	if (rc != 0) {
		fprintf(stderr, "Failed to create policy file: %d\n", rc);
		goto exit;
	}

	sepol_policy_file_set_fp(pf, binary);

	rc = sepol_policydb_write(pdb, pf);
	if (rc != 0) {
		fprintf(stderr, "Failed to write binary policy: %d\n", rc);
		goto exit;
	}

	fclose(binary);
	binary = NULL;

	if (log_level >= CIL_INFO) {
		fprintf(stderr, "Writing File Contexts\n");
	}
	
	rc = cil_filecons_to_string(db, pdb, &fc_buf, &fc_size);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to get file context data\n");
		goto exit;
	}

	file_contexts = fopen("file_contexts", "w+");
	if (file_contexts == NULL) {
		fprintf(stderr, "Failed to open file_contexts file\n");
		goto exit;
	}
	
	if (fwrite(fc_buf, sizeof(char), fc_size, file_contexts) != fc_size) {
		fprintf(stderr, "Failed to write file_contexts file\n");
		goto exit;
	}

	fclose(file_contexts);
	
	rc = SEPOL_OK;

exit:
	if (binary != NULL) {
		fclose(binary);
	}
	cil_db_destroy(&db);
	sepol_policydb_free(pdb);
	sepol_policy_file_free(pf);
	free(fc_buf);
	return rc;
}
