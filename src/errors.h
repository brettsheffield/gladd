/* 
 * errors.h
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

#ifndef __GLADD_ERRORS_H__
#define __GLADD_ERRORS_H__ 1

#include <errno.h>

#define ERROR_CODES(X)                                                        \
	X(0, ERROR_SUCCESS,             "Success")                            \
	X(1, ERROR_FAILURE,             "Failure")                            \
	X(2, ERROR_WEBSOCKET_RSVBITSET, "Reserved bit set")                   \
	X(3, ERROR_WEBSOCKET_BAD_OPCODE, "Bad opcode")                        \
	X(4, ERROR_WEBSOCKET_UNMASKED_DATA, "Unmasked client data")           \
	X(5, ERROR_WEBSOCKET_CLOSE_CONNECTION, "Connection close requested")


#define ERROR_MSG(code, name, msg) case code: return msg;
#define ERROR_ENUM(code, name, msg) name = code,
enum {
	ERROR_CODES(ERROR_ENUM)
};

/* return human readable error message for e */
char *error_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void print_error(int e, int errsv, char *errstr);

#endif /* __GLADD_ERRORS_H__ */
