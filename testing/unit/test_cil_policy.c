#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_policy.h"

#include "../../src/cil_policy.h"
#include "../../src/cil.h"

void test_cil_filecon_compare_meta_a_not_b(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = "ba.r";
	afilecon->path_str = "foo";
	
	bfilecon->root_str = "barr";
	bfilecon->path_str = "foo";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_filecon_compare_meta_b_not_a(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = "bar";
	afilecon->path_str = "foo";
	
	bfilecon->root_str = "ba.rr";
	bfilecon->path_str = "foo";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_filecon_compare_meta_a_and_b_strlen_a_greater_b(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = ".\\$";
	afilecon->path_str = ".$({";
	
	bfilecon->root_str = ".?";
	bfilecon->path_str = ".";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_filecon_compare_type_atype_greater_btype(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = ".\\$";
	afilecon->path_str = ".$({";
	afilecon->type = CIL_FILECON_CHAR;
	
	bfilecon->root_str = ".\\$";
	bfilecon->path_str = ".$({";
	bfilecon->type = CIL_FILECON_DIR;
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_filecon_compare_type_btype_greater_atype(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = ".\\$";
	afilecon->path_str = ".$({";
	afilecon->type = CIL_FILECON_DIR;
	
	bfilecon->root_str = ".\\$";
	bfilecon->path_str = ".$({";
	bfilecon->type = CIL_FILECON_CHAR;
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_filecon_compare_meta_a_and_b_strlen_b_greater_a(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = ".";
	afilecon->path_str = ".";
	
	bfilecon->root_str = ".*+|[({";
	bfilecon->path_str = ".";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_filecon_compare_stemlen_a_greater_b(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = "bar";
	afilecon->path_str = "foo";
	
	bfilecon->root_str = "barr";
	bfilecon->path_str = "foo";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_filecon_compare_stemlen_b_greater_a(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = "barre";
	afilecon->path_str = "foo";
	
	bfilecon->root_str = "barr";
	bfilecon->path_str = "foo";
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_filecon_compare_equal(CuTest *tc) {
	struct cil_filecon *afilecon;
	cil_filecon_init(&afilecon);

	struct cil_filecon *bfilecon;
	cil_filecon_init(&bfilecon);

	afilecon->root_str = ".\\$";
	afilecon->path_str = ".$({";
	afilecon->type = CIL_FILECON_DIR;
	
	bfilecon->root_str = ".\\$";
	bfilecon->path_str = ".$({";
	bfilecon->type = CIL_FILECON_DIR;
	
	
	int rc = cil_filecon_compare(&afilecon, &bfilecon);
	CuAssertIntEquals(tc, 0, rc);
}

void test_cil_portcon_compare_atotal_greater_btotal(CuTest *tc) {
	struct cil_portcon *aportcon;
	cil_portcon_init(&aportcon);

	struct cil_portcon *bportcon;
	cil_portcon_init(&bportcon);

	aportcon->port_low = 15;
	aportcon->port_high = 30;
	
	bportcon->port_low = 10;
	bportcon->port_high = 11;
	
	int rc = cil_portcon_compare(&aportcon, &bportcon);
	CuAssertTrue(tc, rc > 0);
}

void test_cil_portcon_compare_btotal_greater_atotal(CuTest *tc) {
	struct cil_portcon *aportcon;
	cil_portcon_init(&aportcon);

	struct cil_portcon *bportcon;
	cil_portcon_init(&bportcon);

	aportcon->port_low = 5;
	aportcon->port_high = 5;
	
	bportcon->port_low = 11;
	bportcon->port_high = 20;
	
	int rc = cil_portcon_compare(&aportcon, &bportcon);
	CuAssertTrue(tc, rc < 0);
}

void test_cil_portcon_compare_aportlow_greater_bportlow(CuTest *tc) {
	struct cil_portcon *aportcon;
	cil_portcon_init(&aportcon);

	struct cil_portcon *bportcon;
	cil_portcon_init(&bportcon);

	aportcon->port_low = 30;
	aportcon->port_high = 33;
	
	bportcon->port_low = 17;
	bportcon->port_high = 20;
	
	int rc = cil_portcon_compare(&aportcon, &bportcon);
	CuAssertTrue(tc, rc > 0);
}

void test_cil_portcon_compare_bportlow_greater_aportlow(CuTest *tc) {
	struct cil_portcon *aportcon;
	cil_portcon_init(&aportcon);

	struct cil_portcon *bportcon;
	cil_portcon_init(&bportcon);

	aportcon->port_low = 5;
	aportcon->port_high = 8;
	
	bportcon->port_low = 17;
	bportcon->port_high = 20;
	
	int rc = cil_portcon_compare(&aportcon, &bportcon);
	CuAssertTrue(tc, rc < 0);
}

void test_cil_portcon_compare_equal(CuTest *tc) {
	struct cil_portcon *aportcon;
	cil_portcon_init(&aportcon);

	struct cil_portcon *bportcon;
	cil_portcon_init(&bportcon);

	aportcon->port_low = 17;
	aportcon->port_high = 20;
	
	bportcon->port_low = 17;
	bportcon->port_high = 20;
	
	int rc = cil_portcon_compare(&aportcon, &bportcon);
	CuAssertTrue(tc, rc == 0);
}

void test_cil_genfscon_compare_atypestr_greater_btypestr(CuTest *tc) {
	struct cil_genfscon *agenfscon;
	cil_genfscon_init(&agenfscon);
	agenfscon->type_str = "aaaa";

	struct cil_genfscon *bgenfscon;
	cil_genfscon_init(&bgenfscon);
	bgenfscon->type_str = "bbbb";

	int rc = cil_genfscon_compare(&agenfscon, &bgenfscon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_genfscon_compare_btypestr_greater_atypestr(CuTest *tc) {
	struct cil_genfscon *agenfscon;
	cil_genfscon_init(&agenfscon);
	agenfscon->type_str = "bbbb";

	struct cil_genfscon *bgenfscon;
	cil_genfscon_init(&bgenfscon);
	bgenfscon->type_str = "aaaa";

	int rc = cil_genfscon_compare(&agenfscon, &bgenfscon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_genfscon_compare_apathstr_greater_bpathstr(CuTest *tc) {
	struct cil_genfscon *agenfscon;
	cil_genfscon_init(&agenfscon);
	agenfscon->type_str = "aaaa";
	agenfscon->path_str = "ff";

	struct cil_genfscon *bgenfscon;
	cil_genfscon_init(&bgenfscon);
	bgenfscon->type_str = "aaaa";
	bgenfscon->type_str = "gg";

	int rc = cil_genfscon_compare(&agenfscon, &bgenfscon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_genfscon_compare_bpathstr_greater_apathstr(CuTest *tc) {
	struct cil_genfscon *agenfscon;
	cil_genfscon_init(&agenfscon);
	agenfscon->type_str = "bbbb";
	agenfscon->path_str = "cccc";

	struct cil_genfscon *bgenfscon;
	cil_genfscon_init(&bgenfscon);
	bgenfscon->type_str = "bbbb";
	bgenfscon->path_str = "aaaa";

	int rc = cil_genfscon_compare(&agenfscon, &bgenfscon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_genfscon_compare_equal(CuTest *tc) {
	struct cil_genfscon *agenfscon;
	cil_genfscon_init(&agenfscon);
	agenfscon->type_str = "bbbb";
	agenfscon->path_str = "cccc";

	struct cil_genfscon *bgenfscon;
	cil_genfscon_init(&bgenfscon);
	bgenfscon->type_str = "bbbb";
	bgenfscon->path_str = "cccc";

	int rc = cil_genfscon_compare(&agenfscon, &bgenfscon);
	CuAssertIntEquals(tc, 0, rc);
}

void test_cil_netifcon_compare_a_greater_b(CuTest *tc) {
	struct cil_netifcon *anetifcon;
	cil_netifcon_init(&anetifcon);
	anetifcon->interface_str = "aaa";

	struct cil_netifcon *bnetifcon;
	cil_netifcon_init(&bnetifcon);
	bnetifcon->interface_str = "bbb";
	
	int rc = cil_netifcon_compare(&anetifcon, &bnetifcon);
	CuAssertTrue(tc, rc < 0);
}

void test_cil_netifcon_compare_b_greater_a(CuTest *tc) {
	struct cil_netifcon *anetifcon;
	cil_netifcon_init(&anetifcon);
	anetifcon->interface_str = "bbb";

	struct cil_netifcon *bnetifcon;
	cil_netifcon_init(&bnetifcon);
	bnetifcon->interface_str = "aaa";
	
	int rc = cil_netifcon_compare(&anetifcon, &bnetifcon);
	CuAssertTrue(tc, rc > 0);
}

void test_cil_netifcon_compare_equal(CuTest *tc) {
	struct cil_netifcon *anetifcon;
	cil_netifcon_init(&anetifcon);
	anetifcon->interface_str = "aaa";

	struct cil_netifcon *bnetifcon;
	cil_netifcon_init(&bnetifcon);
	bnetifcon->interface_str = "aaa";
	
	int rc = cil_netifcon_compare(&anetifcon, &bnetifcon);
	CuAssertTrue(tc, rc == 0);
}

void test_cil_nodecon_compare_aipv4_bipv6(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 103;
	anodecon->mask->ip.v4.s_addr = 100;
	anodecon->addr->family = AF_INET;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET6;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_nodecon_compare_aipv6_bipv4(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 103;
	anodecon->mask->ip.v4.s_addr = 100;
	anodecon->addr->family = AF_INET6;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_nodecon_compare_aipv4_greaterthan_bipv4(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 103;
	anodecon->mask->ip.v4.s_addr = 100;
	anodecon->addr->family = AF_INET;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_nodecon_compare_aipv4_lessthan_bipv4(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 99;
	anodecon->mask->ip.v4.s_addr = 100;
	anodecon->addr->family = AF_INET;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_nodecon_compare_amaskipv4_greaterthan_bmaskipv4(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 103;
	anodecon->mask->ip.v4.s_addr = 101;
	anodecon->addr->family = AF_INET;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_nodecon_compare_amaskipv4_lessthan_bmaskipv4(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v4.s_addr = 99;
	anodecon->mask->ip.v4.s_addr = 99;
	anodecon->addr->family = AF_INET;
	
	bnodecon->addr->ip.v4.s_addr = 100;
	bnodecon->mask->ip.v4.s_addr = 100;
	bnodecon->addr->family = AF_INET;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_nodecon_compare_aipv6_greaterthan_bipv6(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v6.s6_addr[0] = '5';
	anodecon->mask->ip.v6.s6_addr[0] = '9';
	anodecon->addr->family = AF_INET6;
	
	bnodecon->addr->ip.v6.s6_addr[0] = '3';
	bnodecon->mask->ip.v6.s6_addr[0] = '9';
	bnodecon->addr->family = AF_INET6;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, 1, rc);
}

void test_cil_nodecon_compare_aipv6_lessthan_bipv6(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v6.s6_addr[0] = '3';
	anodecon->mask->ip.v6.s6_addr[0] = '1';
	anodecon->addr->family = AF_INET6;
	
	bnodecon->addr->ip.v6.s6_addr[0] = '5';
	bnodecon->mask->ip.v6.s6_addr[0] = '1';
	bnodecon->addr->family = AF_INET6;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_nodecon_compare_amaskipv6_greaterthan_bmaskipv6(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v6.s6_addr[0] = '1';
	anodecon->mask->ip.v6.s6_addr[0] = '4';
	anodecon->addr->family = AF_INET6;
	
	bnodecon->addr->ip.v6.s6_addr[0] = '1';
	bnodecon->mask->ip.v6.s6_addr[0] = '3';
	bnodecon->addr->family = AF_INET6;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, -1, rc);
}

void test_cil_nodecon_compare_amaskipv6_lessthan_bmaskipv6(CuTest *tc) {
	struct cil_nodecon *anodecon;
	cil_nodecon_init(&anodecon);
	cil_ipaddr_init(&anodecon->addr);
	cil_ipaddr_init(&anodecon->mask);

	struct cil_nodecon *bnodecon;
	cil_nodecon_init(&bnodecon);
	cil_ipaddr_init(&bnodecon->addr);
	cil_ipaddr_init(&bnodecon->mask);

	anodecon->addr->ip.v6.s6_addr[0] = '5';
	anodecon->mask->ip.v6.s6_addr[0] = '1';
	anodecon->addr->family = AF_INET6;
	
	bnodecon->addr->ip.v6.s6_addr[0] = '5';
	bnodecon->mask->ip.v6.s6_addr[0] = '6';
	bnodecon->addr->family = AF_INET6;
	
	int rc = cil_nodecon_compare(&anodecon, &bnodecon);
	CuAssertIntEquals(tc, 1, rc);
}

