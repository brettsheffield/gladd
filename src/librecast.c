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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct lcast_chan_t {
        lc_channel_t *chan;
        char *name;
        struct lcast_chan_t *next;
} lcast_chan_t;

int websock = 0;
lc_ctx_t *lctx = NULL;
lc_socket_t *lsock = NULL;
lcast_chan_t *lchan = NULL;
lcast_chan_t *chan_selected = NULL;

lcast_chan_t *lcast_channel_byname(char *name);
lcast_chan_t *lcast_channel_new(char *name);
void lcast_recv(char *msg, ssize_t len);
void lcast_recv_err(int err);

/* fetch channel by name */
lcast_chan_t *lcast_channel_byname(char *name)
{
	lcast_chan_t *p = lchan;

	while (p) {
		if (strcmp(p->name, name) == 0)
			return p;
		p = p->next;
	}

	return NULL;
}

void lcast_channel_free(char *name)
{
	lcast_chan_t *p = lchan;
	while (p) {
		if (strcmp(p->name, name) == 0)
			break;
		p = p->next;
	}
	if (p) {
		lc_channel_free(p->chan);
		free(p->name);
		free(p);
	}
}

/* create or fetch channel */
lcast_chan_t *lcast_channel_new(char *name)
{
	lcast_chan_t *chan = NULL;
	lcast_chan_t *p = lchan;

	lcast_init();

	/* check for existing channel */
	while (p) {
		chan = p;
		if (strcmp(p->name, name) == 0)
			return p;
		p = p->next;
	}
	p = chan;

	/* no such channel, create it */
	logmsg(LVL_DEBUG, "(librecast) CREATE channel '%s'", name);
	chan = calloc(1, sizeof(struct lcast_chan_t));
	chan->chan = lc_channel_new(lctx, name);
	chan->name = strdup(name);

	if (p)
		p->next = chan;

	if (lchan == NULL)
		lchan = chan;

	if (lc_channel_bind(lsock, lchan->chan) != 0) {
		free(chan);
		return NULL;
	}

	return chan;
}

int lcast_cmd_join(int sock, ws_frame_t *f, void *data)
{
	lcast_chan_t *chan;

	logmsg(LVL_DEBUG, "(librecast) JOIN channel '%s'", (char *)data);
	chan = lcast_channel_new((char *) data);
	if (chan == NULL)
		return error_log(LVL_ERROR, ERROR_LIBRECAST_CHANNEL_NOT_CREATED);
	lc_channel_join(chan->chan);

	/* set as default channel if no other selected */
	if (chan_selected == NULL)
		chan_selected = chan;

	if (sock == 0)
		return error_log(LVL_ERROR, ERROR_LIBRECAST_NO_SOCKET);

	websock = sock;
	lc_socket_listen(lc_channel_socket(chan->chan), lcast_recv, lcast_recv_err);

	return 0;
}

int lcast_cmd_part(int sock, ws_frame_t *f, void *data)
{
	lcast_chan_t *chan;

	logmsg(LVL_DEBUG, "(librecast) PART channel '%s'", (char *)data);
	if (lctx == NULL)
		return error_log(LVL_ERROR, ERROR_LIBRECAST_CONTEXT_NULL);

	chan = lcast_channel_byname((char *)data);
	if (chan == NULL) {
		return error_log(LVL_ERROR, ERROR_LIBRECAST_CHANNEL_NOT_EXIST);
	}
	lc_channel_leave(chan->chan);
	lcast_channel_free((char *)data);

	return 0;
}

int lcast_cmd_send(int sock, ws_frame_t *f, void *data)
{
	if (chan_selected == NULL)
		return error_log(LVL_ERROR, ERROR_LIBRECAST_CHANNEL_NOT_SELECTED);
	logmsg(LVL_DEBUG, "(librecast) SEND");
	lc_msg_send(chan_selected->chan, (char *)data, strlen((char *)data));

	return 0;
}

int lcast_do_cmd(int sock, ws_frame_t *f)
{
	/* match commands */
	LCAST_TEXT_CMDS(LCAST_TEXT_CMD)

	/* send message */
	lcast_cmd_send(sock, f, f->data);

	return 0;
}

int lcast_handle_client_data(int sock, ws_frame_t *f)
{
	logmsg(LVL_DEBUG, "lc_handle_client_data() has opcode 0x%x", f->opcode);

        switch (f->opcode) {
        case 0x0:
                logmsg(LVL_DEBUG, "(librecast) DATA (continuation frame)");
		return error_log(LVL_ERROR, ERROR_WEBSOCKET_UNEXPECTED_CONTINUE);
        case 0x1:
                logmsg(LVL_DEBUG, "(librecast) DATA (text)");
                return lcast_do_cmd(sock, f);
        case 0x2:
                logmsg(LVL_DEBUG, "(librecast) DATA (binary)");
		return error_log(LVL_ERROR, ERROR_NOT_IMPLEMENTED);
        default:
                logmsg(LVL_DEBUG, "opcode 0x%x not valid for data frame", f->opcode);
                break;
        }

	return 0;
}

void lcast_init()
{
	if (lctx == NULL)
		lctx = lc_ctx_new();
	if (lsock == NULL) {
		lsock = lc_socket_new(lctx);
		logmsg(LVL_DEBUG, "setting socket in lcast_init to %i", lc_socket_raw(lsock));
	}
}

void lcast_recv(char *msg, ssize_t len)
{
	logmsg(LVL_DEBUG, "lcast_recv: %s", msg);
	ws_send(websock, WS_OPCODE_TEXT, msg, len);
}

void lcast_recv_err(int err)
{
	/* TODO: fetch error from librecast */
	logmsg(LVL_DEBUG, "lcast_recv_err(): %i", err);
}
