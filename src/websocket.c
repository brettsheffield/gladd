/* 
 * websocket.c
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

#include "errors.h"
#include "log.h"
#include "string.h"
#include "websocket.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct ws_frame_header_t {
	uint8_t f1;
	uint8_t f2;
} ws_frame_header_t;

int ws_handle_request(int sock)
{
	int err;
	void *payload = NULL;

	err = ws_read_request(sock, payload);

	return err;
}

char *ws_protocol_name(ws_protocol_t proto)
{
	switch (proto) {
		WS_PROTOCOLS(WS_PROTOCOL)
	};
	return WS_PROTOCOL_NONE;
}

int ws_read_request(int sock, void *payload)
{
	ws_frame_header_t *f;
	ssize_t len;
	uint8_t mask, tmp;
	uint8_t masked, unmasked;
	uint16_t opcode = 0;
	uint32_t maskkey = 0;
	uint32_t i;
	uint64_t paylen = 0;
	void *data;

	/* read websocket header */
	f = calloc(1, sizeof(struct ws_frame_header_t));
	len = read(sock, f, 2);
	logmsg(LVL_DEBUG, "(websocket) %i bytes read (header)", (int)len);

	/* check some bit flags */
	if (f->f1 & 0x80)
		logmsg(LVL_DEBUG, "(websocket) FIN");
	/* TODO: handle fragmentation */
	/* TODO: ensure control frames aren't fragmented */
	/* TODO: handle control frames */
	/* TODO: connection states */
	/* TODO: closing connection & closure codes */
	/* TODO: write to socket */

	if (f->f1 & 0x40) {
		logmsg(LVL_DEBUG, "(websocket) RSV1");
		return ERROR_WEBSOCKET_RSVBITSET;
	}

	if (f->f1 & 0x20) {
		logmsg(LVL_DEBUG, "(websocket) RSV2");
		return ERROR_WEBSOCKET_RSVBITSET;
	}

	if (f->f1 & 0x10) {
		logmsg(LVL_DEBUG, "(websocket) RSV3");
		return ERROR_WEBSOCKET_RSVBITSET;
	}

	/* read the opcode */
	opcode |= (f->f1 & 0xf);
        switch (opcode) {
        case 0x0:
                logmsg(LVL_DEBUG, "(websocket) opcode 0x0: continuation frame");
                break;
        case 0x1:
                logmsg(LVL_DEBUG, "(websocket) opcode 0x1: text frame");
                break;
        case 0x2:
                logmsg(LVL_DEBUG, "(websocket) opcode 0x2: binary frame");
                break;
        /* %x3-7 are reserved for further non-control frames */
        case 0x8:
                logmsg(LVL_DEBUG, "(websocket) opcode 0x8: connection close");
                break;
        case 0x9:
                logmsg(LVL_DEBUG, "(websocket) opcode 0x9: ping");
                break;
        case 0xa:
                logmsg(LVL_DEBUG, "(websocket) opcode 0xa: pong");
                break;
        /* %xB-F are reserved for further control frames */
        default:
                logmsg(LVL_DEBUG, "(websocket) unknown opcode %#x received", opcode);
		return ERROR_WEBSOCKET_BAD_OPCODE;
                break;
        }

	if (f->f2 & 0x80)
		logmsg(LVL_DEBUG, "(websocket) MASK");
	else
		return ERROR_WEBSOCKET_UNMASKED_DATA;

	/* get payload length */
	paylen |= (f->f2 & 0x7f);
	if (paylen == 126) {
		/* 16 bit extended payload length */
		len = read(sock, &paylen, 2);
		logmsg(LVL_DEBUG, "(websocket) %li bytes read (length)", len);
		paylen = ntohs(paylen);
	}
	else if (paylen == 127) {
		/* 64 bit extra specially extended payload length of great wonderfulness */
		len = read(sock, &paylen, 8);
		logmsg(LVL_DEBUG, "(websocket) %li bytes read (length)", len);
		paylen = ntohll(paylen);
	}
	logmsg(LVL_DEBUG, "(websocket) length: %u", (unsigned int)paylen);

	/* get payload mask */
	len = read(sock, &maskkey, 4);
	logmsg(LVL_DEBUG, "(websocket) %i bytes read (mask)", (int)len);
	logmsg(LVL_DEBUG, "(websocket) mask: %02x", ntohl(maskkey));

	/* read payload */
	data = calloc(1, paylen + 1);
	len = read(sock, data, paylen);
	logmsg(LVL_DEBUG, "(websocket) %i bytes read (payload)", (int)len);

	/* unmask payload */
	payload = calloc(1, paylen + 1);
	for (i = 0; i < paylen; i++) {
		tmp = maskkey >> ((i % 4) * 8);
		bcopy(&tmp, &mask, 1);
		bcopy(data + i, &masked, 1);
		unmasked = mask ^ masked;
		bcopy(&unmasked, payload + i, 1);
	}

	/* TODO: process payload */

	free(payload);
	free(data);
	free(f);

	return 0;
}

int ws_select_protocol(char *header)
{
	int i = 0;
	int j = 0;
	char *keys = strdup(header);
	char **protos;

	/* return the first matching protocol we support */
	protos = tokenize(&j, &keys, ",");
	for (i = 0; i < j; i++) {
		logmsg(LVL_DEBUG, "Trying protocol: %s", protos[i]);
		WS_PROTOCOLS(WS_PROTOCOL_SELECT)
	}
	free(keys);

	return WS_PROTOCOL_INVALID;
}
