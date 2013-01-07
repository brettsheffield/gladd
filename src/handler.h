/* 
 * handler.h
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012, 2013 Brett Sheffield <brett@gladserv.com>
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

#ifndef __GLADD_HANDLER_H__
#define __GLADD_HANDLER_H__ 1


/* TEMP */
#define RESPONSE_200 "HTTP/1.1 200 OK\nServer: gladd\nConnection: close\nContent-Type: %s\n\n%s"

#include <sys/socket.h>

void *get_in_addr(struct sockaddr *sa);
void handle_connection(int sock, struct sockaddr_storage their_addr);
int prepare_response(char resource[], char **xml, char *query);
int send_file(int sock, char *path);

#endif /* __GLADD_HANDLER_H__ */
