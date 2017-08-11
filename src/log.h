/* 
 * log.h
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

#ifndef __GLADD_LOG_H__
#define __GLADD_LOG_H__ 1

#include <syslog.h>

#define LOG_LEVELS(X) \
	X(0,    LVL_NONE,       "none",      LOG_EMERG)                 \
	X(1,    LVL_SEVERE,     "severe",    LOG_ALERT)                 \
	X(2,    LVL_ERROR,      "error",     LOG_ERR)                   \
	X(4,    LVL_WARNING,    "warning",   LOG_WARNING)               \
	X(8,    LVL_INFO,       "info",      LOG_INFO)                  \
	X(16,   LVL_TRACE,      "trace",     LOG_DEBUG)                 \
	X(32,   LVL_FULLTRACE,  "fulltrace", LOG_DEBUG)                 \
	X(64,   LVL_DEBUG,      "debug",     LOG_DEBUG)
#undef X

#define LOG_ENUM(id, name, desc, syslog) name = id,
#define LOG_SYSLOGLVL(id, name, desc, syslog) case id: return syslog;
enum {
	LOG_LEVELS(LOG_ENUM)
};

extern unsigned int LOG_LEVEL;

/* map log levels to syslog log levels */
int log_sysloglvl(int loglevel);

/* log a message by the appropriate means */
void logmsg(int level, char *msg, ...);

#endif /* __GLADD_LOG_H__ */
