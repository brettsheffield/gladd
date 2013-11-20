/* 
 * auth.h - authentication functions
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012, 2013 Brett Sheffield <brett@gladserv.com>
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

#ifndef __GLADD_AUTH_H__
#define __GLADD_AUTH_H__ 1

#include "http.h"

int check_auth(http_request_t *r);
int check_auth_alias(char *alias, http_request_t *r);
int check_auth_group(char *user, char *group);
int check_auth_pam(char *service, char *username, char *password);
int check_auth_require(char *alias, http_request_t *r);
int check_auth_sufficient(char *alias, http_request_t *r);
int ingroup(char *user, char *group);

#endif /* __GLADD_AUTH_H__ */
