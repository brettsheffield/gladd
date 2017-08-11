/* 
 * log.c
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

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "config.h"
#include "log.h"
#include "misc.h"

int log_sysloglvl(int loglevel)
{
	switch (loglevel) {
		LOG_LEVELS(LOG_SYSLOGLVL)
	}
	return LOG_DEBUG;
}

void logmsg(int level, char *msg, ...)
{
	va_list argp;
	int loglevel = config->loglevel;

	if ((loglevel & level) != level)
		return;

	va_start(argp, msg);
	if (config->daemon == 0)
		vsyslog(log_sysloglvl(level), msg, argp);
	else
		vfprintf(stderr, "%s\n", argp);
	va_end(argp);
}
