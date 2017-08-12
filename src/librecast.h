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

typedef enum {
	LC_TEXT_CMD_JOIN = 1,
	LC_TEXT_CMD_PART = 2,
	LC_TEXT_CMD_SEND = 3
} lcast_text_cmd_t;

#define LCAST_TEXT_CMDS(X) \
	X(LCAST_TEXT_CMD_JOIN, "/join ", lcast_cmd_join) \
	X(LCAST_TEXT_CMD_PART, "/part ", lcast_cmd_part) \
	X(LCAST_TEXT_CMD_SEND, "/send ", lcast_cmd_send)
#undef X

#define LCAST_TEXT_CMD(code, cmd, fun) if (strncmp(f->data, cmd, strlen(cmd))==0) return fun(sock, f, f->data + strlen(cmd));

/* join librecast channel */
int lcast_cmd_join(int sock, ws_frame_t *f, void *data);

/* leave librecast channel */
int lcast_cmd_part(int sock, ws_frame_t *f, void *data);

/* send message */
int lcast_cmd_send(int sock, ws_frame_t *f, void *data);

/* process client command */
int lcast_do_cmd(int sock, ws_frame_t *f);

/* deal with incoming client data frames */
int lcast_handle_client_data(int sock, ws_frame_t *f);

/* initialize librecast context and socket */
void lcast_init();

#endif /* __LIBRECAST_H__ */
