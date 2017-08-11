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

#define WS_PROTOCOLS(X) \
	X("none", WS_PROTOCOL_NONE) \
	X("librecast", WS_PROTOCOL_LIBRECAST)
#undef X

#define WS_PROTOCOL(k, proto) case proto: return k;
#define WS_PROTOCOL_SELECT(k, proto) if (strcmp(protos[i], k) == 0) return proto;

/* websocket request handler */
int ws_handle_request(int sock);

/* return protocol name from number */
char *ws_protocol_name(ws_protocol_t proto);

/* read websocket framing protocol */
int ws_read_request(int sock);

/* return the first matching protocol we support */
int ws_select_protocol(char *header);

#endif /* __WEBSOCKETS_H__ */
