/* 
 * librecast.h
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

#ifndef __LIBRECAST_H__
#define __LIBRECAST_H__ 1

#include "websocket.h"

#include <librecast.h>
#include <stdint.h>

typedef struct lcast_frame_t {
	uint8_t opcode;
	uint32_t len;
	uint32_t id;
	uint32_t id2;
	uint32_t token;
} __attribute__((__packed__)) lcast_frame_t;

#define LCAST_OPCODES(X) \
	X(0x01, LCAST_OP_NOOP,           "NOOP",           lcast_cmd_noop) \
	X(0x02, LCAST_OP_SETOPT,         "SETOPT",         lcast_cmd_noop) \
	X(0x03, LCAST_OP_SOCKET_NEW,     "SOCKET_NEW",     lcast_cmd_socket_new) \
	X(0x04, LCAST_OP_SOCKET_GETOPT,  "SOCKET_GETOPT",  lcast_cmd_socket_getopt) \
	X(0x05, LCAST_OP_SOCKET_SETOPT,  "SOCKET_SETOPT",  lcast_cmd_socket_setopt) \
	X(0x06, LCAST_OP_SOCKET_LISTEN,  "SOCKET_LISTEN",  lcast_cmd_socket_listen) \
	X(0x07, LCAST_OP_SOCKET_IGNORE,  "SOCKET_IGNORE",  lcast_cmd_socket_ignore) \
	X(0x08, LCAST_OP_SOCKET_CLOSE,   "SOCKET_CLOSE",   lcast_cmd_socket_close) \
	X(0x09, LCAST_OP_SOCKET_MSG,     "SOCKET_MSG",     lcast_cmd_noop) \
	X(0x0a, LCAST_OP_CHANNEL_NEW,    "CHANNEL_NEW",    lcast_cmd_channel_new) \
	X(0x0b, LCAST_OP_CHANNEL_GETMSG, "CHANNEL_GETMSG", lcast_cmd_channel_getmsg) \
	X(0x0c, LCAST_OP_CHANNEL_GETOPT, "CHANNEL_GETOPT", lcast_cmd_channel_getop) \
	X(0x0d, LCAST_OP_CHANNEL_SETOPT, "CHANNEL_SETOPT", lcast_cmd_channel_setop) \
	X(0x0e, LCAST_OP_CHANNEL_GETVAL, "CHANNEL_GETVAL", lcast_cmd_channel_getval) \
	X(0x0f, LCAST_OP_CHANNEL_SETVAL, "CHANNEL_SETVAL", lcast_cmd_channel_setval) \
	X(0x10, LCAST_OP_CHANNEL_BIND,   "CHANNEL_BIND",   lcast_cmd_channel_bind) \
	X(0x11, LCAST_OP_CHANNEL_UNBIND, "CHANNEL_UNBIND", lcast_cmd_channel_unbind) \
	X(0x12, LCAST_OP_CHANNEL_JOIN,   "CHANNEL_JOIN",   lcast_cmd_channel_join) \
	X(0x13, LCAST_OP_CHANNEL_PART,   "CHANNEL_PART",   lcast_cmd_channel_part) \
	X(0x14, LCAST_OP_CHANNEL_SEND,   "CHANNEL_SEND",   lcast_cmd_channel_send)
#undef X

#define LCAST_TEXT_CMD(code, name, cmd, fun) if (strncmp(f->data, cmd, strlen(cmd))==0) return fun(sock, f, f->data + strlen(cmd));
#define LCAST_OP_CODE(code, name, cmd, fun) if (name == opcode) return cmd;
#define LCAST_OP_FUN(code, name, cmd, fun) case code: logmsg(LVL_DEBUG, "%s", cmd); fun(sock, req, payload); break;
#define LCAST_OPCODES_ENUM(code, name, text, fun) name = code,

typedef enum {
	LCAST_OPCODES(LCAST_OPCODES_ENUM)
} lcast_opcode_t;

#define LCAST_KEEPALIVE_INTERVAL 15
//#define LCAST_DEBUG_LOG_PAYLOAD 1

/* return cmd name from opcode */
char *lcast_cmd_name(lcast_opcode_t opcode);

/* debug logs */
void lcast_cmd_debug(lcast_frame_t *req, char *payload);

int lcast_cmd_noop(int sock, lcast_frame_t *req, char *payload);
/* channel commands */
int lcast_cmd_channel_bind(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_join(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_new(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_part(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_send(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_getmsg(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_getop(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_setop(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_getval(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_setval(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_channel_unbind(int sock, lcast_frame_t *req, char *payload);

/* socket commands */
int lcast_cmd_socket_close(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_socket_ignore(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_socket_listen(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_socket_new(int sock, lcast_frame_t *req, char *payload);
int lcast_cmd_socket_setopt(int sock, lcast_frame_t *req, char *payload);

/* process client command */
int lcast_cmd_handler(int sock, ws_frame_t *f);

/* deal with incoming client data frames */
int lcast_handle_client_data(int sock, ws_frame_t *f);

/* initialize librecast context and socket */
void lcast_init();

#endif /* __LIBRECAST_H__ */
