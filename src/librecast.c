/* 
 * librecast.c
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
#include "handler.h"
#include "librecast.h"
#include "log.h"
#include "string.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int lc_handle_client_data(int sock, ws_frame_t *f)
{
	logmsg(LVL_DEBUG, "lc_handle_client_data()");

        switch (f->opcode) {
        case 0x0:
                logmsg(LVL_DEBUG, "(websocket) DATA (continuation frame)");
                return ERROR_WEBSOCKET_UNEXPECTED_CONTINUE;
        case 0x1:
                logmsg(LVL_DEBUG, "(websocket) DATA (text)");
		ws_send(sock, WS_OPCODE_PING, f->data, f->len);
                break;
        case 0x2:
                logmsg(LVL_DEBUG, "(websocket) DATA (binary)");
                break;
        default:
                logmsg(LVL_DEBUG, "opcode 0x%x not valid for data frame", f->opcode);
                break;
        }

	return 0;
}
