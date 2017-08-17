/* 
 * errors.c
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2017 Brett Sheffield <brett@gladserv.com>
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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "log.h"
#include "errors.h"

int error_log(int level, int e)
{
	logmsg(level, "%s", error_msg(e));
	return e;
}

char *error_msg(int e)
{
	switch (e) {
		ERROR_CODES(ERROR_MSG)
	}
	return "Unknown error";
}

void print_error(int e, int errsv, char *errstr)
{
	char buf[LINE_MAX];
	if (errsv != 0) {
		strerror_r(errsv, buf, sizeof(buf));
		logmsg(LVL_SEVERE, "%s: %s", errstr, buf);
	}
	else if (e != 0) {
		logmsg(LVL_SEVERE, "%s: %s", errstr, error_msg(e));
	}
}
