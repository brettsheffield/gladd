/*
 * server.c - entry point for gladd httpd
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2014, 2018 Brett Sheffield <brett@gladserv.com>
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

#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "args.h"
#include "config.h"
#include "handler.h"
#include "main.h"
#include "server.h"
#include "signals.h"

int hits = 0;

int get_socket(struct addrinfo *p)
{
        int sock;
        int yes=1;

        /* get a socket */
        if ((sock = socket(p->ai_family, p->ai_socktype,
                                        p->ai_protocol)) == -1) {
                perror("socket() error");
		syslog(LOG_ERR, "socket() error");
                return -1;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)
                                ) == -1) {
                perror("setsockopt() error");
		syslog(LOG_ERR, "setsockopt() error");
                close(sock);
                return -1;
        }

        if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
                perror("bind() error");
		syslog(LOG_ERR, "bind() error");
                close(sock);
                freeaddrinfo(p);
                return -1;
        }

        return sock;
}

/* getaddrinfo() returns 0.0.0.0 before :: which is not the order we want
   So, first we try AF_INET6, falling back to AF_INET only if that fails. */
void get_addresses(struct addrinfo **servinfo)
{
        struct addrinfo hints;
        char tcpport[5];
        int status;

        /* set up hints */
        memset(&hints, 0, sizeof hints);           /* zero memory */
        hints.ai_family = AF_INET6;                /* try ipv6 first */
        hints.ai_socktype = SOCK_STREAM;           /* TCP stream sockets */
        hints.ai_flags = AI_PASSIVE;               /* ips we can bind to */

        /* set up addrinfo */
        snprintf(tcpport, 5, "%li", config->port);
        status = getaddrinfo(NULL, tcpport, &hints, servinfo);
        if (status != 0) {
                hints.ai_family = AF_INET;         /* try ipv4 as a last resort */
                status = getaddrinfo(NULL, tcpport, &hints, servinfo);
        }
        if (status != 0) {
                fprintf(stderr, "getaddrinfo error: %s\n",
                        gai_strerror(status));
                _exit(EXIT_FAILURE);
        }
}

int server_start(int lockfd)
{
        int errsv;
        int new_fd;
        int sock;
        pid_t pid;
        socklen_t addr_size;
        struct addrinfo *p = NULL;
        struct sockaddr_storage their_addr;
        char address[NI_MAXHOST];
        char buf[sizeof(long)];

        /* get addresses */
        get_addresses(&p);

        /* attempt bind to each address */
        do {
                getnameinfo(p->ai_addr, p->ai_addrlen, address, NI_MAXHOST,
                        NULL, 0, NI_NUMERICSERV);
                syslog(LOG_DEBUG, "Binding to %s", address);
                sock = get_socket(p); /* get a socket and bind */
                if (sock != -1) break;
                p = p->ai_next;
        } while (p != NULL);

        freeaddrinfo(p);

        if (sock == -1) {
                syslog(LOG_ERR, "Failed to bind.  Exiting");
                _exit(EXIT_FAILURE);
        }

        /* listening */
        if (listen(sock, BACKLOG) == 0) {
                syslog(LOG_INFO, "Listening on [%s]:%li", address,config->port);
        }
        else {
                errsv = errno;
                fprintf(stderr, "ERROR: %s\n", strerror(errsv));
                syslog(LOG_ERR, "Failed to listen on [%s]:%li  Exiting.",
                                address, config->port);
                free_config();
                _exit(EXIT_FAILURE);
        }

        /* drop privileges */
        if (config->dropprivs) {
                gid_t newgid = getgid();
                setgroups(1, &newgid);
                if (setuid(getuid()) != 0) {
                        fprintf(stderr,
                        "ERROR: Failed to drop root privileges.  Exiting.\n");
                        exit(EXIT_FAILURE);
                }
                /* verify privileges cannot be restored */
                if (setuid(0) != -1) {
                        fprintf(stderr,
                        "ERROR: Regained root privileges.  Exiting.\n");
                        exit(EXIT_FAILURE);
                }
        }

        addr_size = sizeof their_addr;

        /* daemonize */
        if (config->daemon == 0) {
                if (daemon(0, 0) == -1) {
                        errsv = errno;
                        fprintf(stderr, "ERROR: %s\n", strerror(errsv));
                        syslog(LOG_ERR, "Failed to daemonize. Exiting.");
                        free_config();
                        exit(EXIT_FAILURE);
                }
        }

        /* write pid to lockfile */
        snprintf(buf, sizeof(long), "%ld\n", (long) getpid());
        if (write(lockfd, buf, strlen(buf)) != strlen(buf)) {
                fprintf(stderr, "Error writing to pidfile\n");
                exit(EXIT_FAILURE);
        }

        /* install exit handler to kill child procs */
        atexit(killhandlerprocs);

        for (;;) {
                /* incoming! */
                ++hits;
                new_fd = accept(sock, (struct sockaddr *)&their_addr,
                                &addr_size);
                pid = fork(); /* fork new process to handle connection */
                if (pid == -1) {
                        /* fork failed */
                        close(new_fd);
                        close(sock);
                        return -1;
                }
                else if (pid == 0) {
                        /* let the children play */
                        close(sock); /* children never listen */
                        handle_connection(new_fd, their_addr);
                }
                else {
                        /* parent can close connection */
                        handler_procs++;
                        close(new_fd);
                }
        }
}

int get_hits()
{
        return hits;
}
