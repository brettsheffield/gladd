/* 
 * config_test.h
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012, 2013, 2017 Brett Sheffield <brett@gladserv.com>
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

#ifndef __GLADD_CONFIG_TEST_H__
#define __GLADD_CONFIG_TEST_H__ 1

#include "config.h"

char *test_config_skip_comment();
char *test_config_skip_blank();
char *test_config_invalid_line();
char *test_config_open_success();
char *test_config_open_fail();
char *test_config_defaults();
char *test_config_set();
char *test_config_read_url();
char *test_config_read_template();
char *test_config_read_sql();
char *test_config_add_acl_invalid();
char *test_config_acl_allow_all();
char *test_config_db();
char *test_config_read_auth();
char *test_config_read_users();
char *test_config_read_groups();
char *test_config_multiline();

#endif /* __GLADD_CONFIG_TEST_H__ */
