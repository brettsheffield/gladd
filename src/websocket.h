/* 
 * websocket.h
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

#ifndef __WEBSOCKETS_H__
#define __WEBSOCKETS_H__ 1

#include "http.h"
#include <stdint.h>

/* network to host byte order for uint64_t */
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#define WS_PROTOCOL_INVALID -1
typedef enum {
	WS_PROTOCOL_NONE = 0,
	WS_PROTOCOL_LIBRECAST = 1
} ws_protocol_t;

typedef struct ws_frame_t {
	uint8_t fin:1;
	uint8_t rsv1:1;
	uint8_t rsv2:1;
	uint8_t rsv3:1;
	uint8_t opcode:4;
	uint8_t mask:1;
	uint64_t len;
	uint32_t maskkey;
	void *data;
} ws_frame_t;

#define WS_PROTOCOLS(X) \
	X("none", WS_PROTOCOL_NONE) \
	X("librecast", WS_PROTOCOL_LIBRECAST)
#undef X

#define WS_PROTOCOL(k, proto) case proto: return k;
#define WS_PROTOCOL_SELECT(k, proto) if (strcmp(protos[i], k) == 0) return proto;

typedef enum {
	WS_OPCODE_NONCONTROL,
	WS_OPCODE_CONTROL
} ws_opcode_type_t;

typedef enum {
	WS_OPCODE_CONTINUE = 0x0,
	WS_OPCODE_TEXT = 0x1,
	WS_OPCODE_BINARY = 0x2,
	WS_OPCODE_CLOSE = 0x8,
	WS_OPCODE_PING = 0x9,
	WS_OPCODE_PONG = 0xa
} ws_opcode_t;

#define WS_OPCODES(X) \
	X(WS_OPCODE_CONTINUE, WS_OPCODE_NONCONTROL, "continuation frame", ws_do_data) \
	X(WS_OPCODE_TEXT, WS_OPCODE_NONCONTROL, "text frame", ws_do_data) \
	X(WS_OPCODE_BINARY, WS_OPCODE_NONCONTROL, "binary frame", ws_do_data) \
	/* %x3-7 are reserved for further non-control frames */ \
	X(WS_OPCODE_CLOSE, WS_OPCODE_CONTROL, "connection close", ws_do_close) \
	X(WS_OPCODE_PING, WS_OPCODE_CONTROL, "ping", ws_do_ping) \
	X(WS_OPCODE_PONG, WS_OPCODE_CONTROL, "pong", ws_do_pong)
	/* %xB-F are reserved for further control frames */
#undef X

#define WS_OPCODE_DESC(code, type, desc, f) case code: return desc;
#define WS_OPCODE_FUN(code, type, desc, fun) case code: err = fun(sock, f); break;

extern int ws_proto;

/* close websocket */
int ws_do_close(int sock, ws_frame_t *f);

/* handle data frames */
int ws_do_data(int sock, ws_frame_t *f);

/* do nothing, successfully */
int ws_do_noop(int sock, ws_frame_t *f);

/* handle ping opcode */
int ws_do_ping(int sock, ws_frame_t *f);

/* handle pong reply */
int ws_do_pong(int sock, ws_frame_t *f);

/* websocket request handler */
int ws_handle_request(int sock);

/* return protocol name from number */
char *ws_protocol_name(ws_protocol_t proto);

/* read websocket framing protocol */
int ws_read_request(int sock, ws_frame_t **f);

/* return the first matching protocol we support */
int ws_select_protocol(char *header);

#endif /* __WEBSOCKETS_H__ */
