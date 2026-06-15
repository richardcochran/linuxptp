#include <check.h>
#include <stdlib.h>
#include <string.h>

/* Include the pmc_common header for pmc_create and pmc_destroy */
#include "pmc_common.h"

START_TEST(test_pmc_create_null_safety)
{
    /* Invariant: pmc_create must either return a valid pointer or NULL,
       never crash due to unchecked allocation failures. */

    /* Adversarial inputs: invalid/boundary transport types and domain numbers */
    struct {
        const char *iface;
        int domain;
        int transport;
        int zero_prio1;
    } cases[] = {
        { NULL,           0,    0,    0 },   /* NULL interface - boundary */
        { "",             0,    0,    0 },   /* Empty interface */
        { "/dev/null",    255,  99,   0 },   /* Invalid transport type */
        { "eth0",         0,    1,    0 },   /* Plausible valid input */
    };
    int num_cases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < num_cases; i++) {
        /*
         * Call pmc_create with adversarial parameters.
         * The function must not crash (segfault from NULL deref).
         * It may return NULL on failure, which is acceptable.
         */
        struct pmc *pmc = pmc_create(NULL, cases[i].iface,
                                     cases[i].domain,
                                     cases[i].transport,
                                     cases[i].zero_prio1);
        /* If allocation succeeded, we can destroy it cleanly */
        if (pmc != NULL) {
            pmc_destroy(pmc);
        }
        /* Reaching here without crash means the invariant holds */
        ck_assert_msg(1, "pmc_create must not crash on case %d", i);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_pmc_create_null_safety);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}