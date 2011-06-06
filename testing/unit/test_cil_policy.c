#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_policy.h"

#include "../../src/cil_policy.h"
#include "../../src/cil.h"

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

