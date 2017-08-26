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

#define ERROR_CODES(X)                                                         \
	X(0, ERROR_SUCCESS,                       "Success")                   \
	X(1, ERROR_FAILURE,                       "Failure")                   \
	X(2, ERROR_NOT_IMPLEMENTED,               "Not implemented")           \
	X(3, ERROR_MALLOC,                        "Unable to allocate memory") \
	X(4, ERROR_WEBSOCKET_RSVBITSET,           "(websocket) Reserved bit set")          \
	X(5, ERROR_WEBSOCKET_BAD_OPCODE,          "(websocket) Bad opcode")                \
	X(6, ERROR_WEBSOCKET_UNMASKED_DATA,       "(websocket) Unmasked client data")      \
	X(7, ERROR_WEBSOCKET_CLOSE_CONNECTION,    "(websocket) Connection close requested") \
	X(8, ERROR_WEBSOCKET_FRAGMENTED_CONTROL,  "(websocket) Fragmented control frame") \
	X(9, ERROR_WEBSOCKET_UNEXPECTED_CONTINUE, "(websocket) Unexpected continuation frame") \
	X(10, ERROR_WEBSOCKET_UNEXPECTED_PONG,     "(websocket) Unexpected pong frame") \
	X(11, ERROR_LIBRECAST_CONTEXT_NULL,        "(librecast) Operation on null context") \
	X(12, ERROR_LIBRECAST_CHANNEL_NOT_EXIST,  "(librecast) No such channel") \
	X(13, ERROR_LIBRECAST_CHANNEL_NOT_SELECTED, "(librecast) No channel selected") \
	X(14, ERROR_LIBRECAST_CHANNEL_NOT_CREATED, "(librecast) Unable to create channel") \
	X(15, ERROR_LIBRECAST_CHANNEL_NOT_JOINED, "(librecast) Unable to join channel") \
	X(16, ERROR_LIBRECAST_LISTEN_FAIL,        "(librecast) Listen failed on socket") \
	X(17, ERROR_LIBRECAST_NO_SOCKET,          "(librecast) No socket") \
	X(18, ERROR_LIBRECAST_OPCODE_INVALID,     "(librecast) Invalid opcode") \
	X(19, ERROR_LIBRECAST_SOCKET_NOT_CREATED, "(librecast) Unable to create socket") \
	X(20, ERROR_LIBRECAST_INVALID_SOCKET_ID,  "(librecast) Invalid socket id")
#undef X

#define ERROR_MSG(code, name, msg) case code: return msg;
#define ERROR_ENUM(code, name, msg) name = code,
enum {
	ERROR_CODES(ERROR_ENUM)
};

/* log message and return code */
int error_log(int level, int e);

/* return human readable error message for e */
char *error_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void print_error(int e, int errsv, char *errstr);

#endif /* __GLADD_ERRORS_H__ */
