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

typedef enum {
	LCAST_OP_NOOP                   = 0x01,
	LCAST_OP_SETOPT                 = 0x02,
	LCAST_OP_SOCKET_NEW             = 0x03,
	LCAST_OP_SOCKET_SETOPT          = 0x04,
	LCAST_OP_SOCKET_LISTEN          = 0x05,
	LCAST_OP_SOCKET_IGNORE          = 0x06,
	LCAST_OP_SOCKET_CLOSE           = 0x07,
	LCAST_OP_SOCKET_MSG             = 0x08,
	LCAST_OP_CHANNEL_NEW            = 0x09,
	LCAST_OP_CHANNEL_SETOPT         = 0x0a,
	LCAST_OP_CHANNEL_BIND           = 0x0b,
	LCAST_OP_CHANNEL_UNBIND         = 0x0c,
	LCAST_OP_CHANNEL_JOIN           = 0x0d,
	LCAST_OP_CHANNEL_PART           = 0x0e,
	LCAST_OP_CHANNEL_SEND           = 0x0f
} lcast_opcode_t;

#define LCAST_OPCODES(X) \
	X(LCAST_OP_NOOP,           "NOOP",           lcast_cmd_noop) \
	X(LCAST_OP_SETOPT,         "SETOPT",         lcast_cmd_noop) \
	X(LCAST_OP_SOCKET_NEW,     "SOCKET_NEW",     lcast_cmd_socket_new) \
	X(LCAST_OP_SOCKET_SETOPT,  "SOCKET_SETOPT",  lcast_cmd_socket_setopt) \
	X(LCAST_OP_SOCKET_LISTEN,  "SOCKET_LISTEN",  lcast_cmd_socket_listen) \
	X(LCAST_OP_SOCKET_IGNORE,  "SOCKET_IGNORE",  lcast_cmd_socket_ignore) \
	X(LCAST_OP_SOCKET_CLOSE,   "SOCKET_CLOSE",   lcast_cmd_socket_close) \
	X(LCAST_OP_SOCKET_MSG,     "SOCKET_MSG",     lcast_cmd_noop) \
	X(LCAST_OP_CHANNEL_NEW,    "CHANNEL_NEW",    lcast_cmd_channel_new) \
	X(LCAST_OP_CHANNEL_SETOPT, "CHANNEL_SETOPT", lcast_cmd_channel_setop) \
	X(LCAST_OP_CHANNEL_BIND,   "CHANNEL_BIND",   lcast_cmd_channel_bind) \
	X(LCAST_OP_CHANNEL_UNBIND, "CHANNEL_UNBIND", lcast_cmd_channel_unbind) \
	X(LCAST_OP_CHANNEL_JOIN,   "CHANNEL_JOIN",   lcast_cmd_channel_join) \
	X(LCAST_OP_CHANNEL_PART,   "CHANNEL_PART",   lcast_cmd_channel_part) \
	X(LCAST_OP_CHANNEL_SEND,   "CHANNEL_SEND",   lcast_cmd_channel_send)
#undef X

#define LCAST_TEXT_CMD(code, cmd, fun) if (strncmp(f->data, cmd, strlen(cmd))==0) return fun(sock, f, f->data + strlen(cmd));

#define LCAST_OP_CODE(code, cmd, fun) if (code == opcode) return cmd;
#define LCAST_OP_FUN(code, cmd, fun) case code: logmsg(LVL_DEBUG, "%s", cmd); fun(sock, req, payload); break;

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
int lcast_cmd_channel_setop(int sock, lcast_frame_t *req, char *payload);
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
