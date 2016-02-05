/*
 * test.c
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2016 Brett Sheffield <brett@gladserv.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "args_test.h"

#ifndef _NAUTH
#include "auth_test.h"
#endif

#include "config_test.h"

#ifndef _NGLADDB
#include "db_test.h"
#endif

#include "handler_test.h"
#include "http_test.h"
#include "string_test.h"
#include "xml_test.h"
#include "test.h"

int tests_run = 0;

static void printline(char *c, int len)
{
        for (; len > 1; len--)
                printf("%s", c);
        printf("\n");
}

static char * all_tests()
{
        /* run the tests */
        printline("*", 80);
        printf("Running tests\n");
        printline("*", 80);
        //mu_run_test(test_handler_upload);
        mu_run_test(test_http_insert_header);
        mu_run_test(test_http_accept_encoding);
        mu_run_test(test_config_skip_comment);
        mu_run_test(test_config_skip_blank);
        mu_run_test(test_config_invalid_line);
        mu_run_test(test_config_defaults);
        mu_run_test(test_config_open_fail);
        mu_run_test(test_config_open_success);
        mu_run_test(test_config_set);
        mu_run_test(test_config_read_url);
        mu_run_test(test_config_read_sql);
        mu_run_test(test_args);
#ifndef _NAUTH
        mu_run_test(test_config_read_auth);
        mu_run_test(test_auth_default);
        mu_run_test(test_auth_deny);
        mu_run_test(test_auth_require);
        mu_run_test(test_auth_allow);
#endif /* _NAUTH */
        mu_run_test(test_config_add_acl_invalid);
        mu_run_test(test_config_acl_allow_all);
        mu_run_test(test_config_db);
#ifndef _NGLADDB
        //mu_run_test(test_dbs);
#endif /* _NGLADDB */
#ifndef _NXML /* skip xml tests */
        mu_run_test(test_xml_doc);
#endif /* _NXML */
        mu_run_test(test_string_trimstr);
        mu_run_test(test_http_read_request_get);
        mu_run_test(test_http_readline);
        mu_run_test(test_http_read_request_post);
        mu_run_test(test_http_read_request_data);
        mu_run_test(test_http_postdata_invalid);
        mu_run_test(test_http_postdata_checks);
        //mu_run_test(test_http_proxy_request);
        //mu_run_test(test_http_rewrite_request);
        mu_run_test(test_string_replace);
        mu_run_test(test_config_multiline);
        mu_run_test(test_xml_to_sql);
        mu_run_test(test_http_read_request_post_xml);
        mu_run_test(test_string_tokenize);
        mu_run_test(test_xml_replacevars);
        mu_run_test(test_config_read_users);
        mu_run_test(test_config_read_groups);
        free_config();
#ifndef _NAUTH
        mu_run_test(test_auth_patterns);
        mu_run_test(test_auth_groups_00);
        mu_run_test(test_auth_groups_01);
        mu_run_test(test_auth_groups_02);
        mu_run_test(test_auth_goto);
#endif /* _NAUTH */
        mu_run_test(test_http_read_request_post_large);
        //mu_run_test(test_handler_plugin);
        printline("*", 80);
        return 0;
}

int main(int argc, char **argv)
{
        char *result = all_tests();
        if (result != 0) {
                printline("*", 80);
                printf("FIXME: %s\n", result);
                printline("*", 80);
        }
        else {
                printf("ALL TESTS PASSED\n");
        }
        printf("Tests run: %d\n", tests_run);

        return result != 0;
}
