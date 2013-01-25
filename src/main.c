/*
 * main.c - entry point for gladd httpd
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

#define _GNU_SOURCE

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "main.h"
#include "config.h"
#include "handler.h"
#include "signals.h"
#include "args.h"

int main (int argc, char **argv)
{
        int getaddrinfo(const char *node,
                        const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res);

        int concounter = 0;
        int errsv;
        int lockfd;
        int new_fd;
        int status;
        int yes=1;
        pid_t pid;
        socklen_t addr_size;
        struct addrinfo *servinfo;
        struct addrinfo hints;
        struct sockaddr_storage their_addr;
        char tcpport[5];
        char *errmsg;
        char buf[sizeof(long)];

        /* check commandline args */
        if (argc > 1) {
                process_args(argc, argv);
        }

        /* obtain lockfile */
        //lockfd = creat(LOCKFILE, 0644);
        lockfd = open(LOCKFILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (lockfd == -1) {
                printf("Failed to open lockfile %s\n", LOCKFILE);
                exit(EXIT_FAILURE);
        }
        if (flock(lockfd, LOCK_EX|LOCK_NB) != 0) {
                if (g_signal != 0) {
                        /* signal (SIGHUP, SIGTERM etc.) requested */
                        exit(signal_gladd(lockfd));
                }
                printf("%s already running\n", PROGRAM);
                exit(EXIT_FAILURE);
        }

        /* open syslogger */
        openlog(PROGRAM, LOG_CONS|LOG_PID, LOG_DAEMON);

        syslog(LOG_INFO, "Starting up.");

        /* read config */
        if (read_config(DEFAULT_CONFIG) != 0) {
                asprintf(&errmsg,"Failed to read config on startup. Exiting.");
                syslog(LOG_ERR, "%s", errmsg);
                fprintf(stderr, "%s\n", errmsg);
                free(errmsg);
                exit(EXIT_FAILURE);
        }

        memset(&hints, 0, sizeof hints);           /* zero memory */
        hints.ai_family = AF_UNSPEC;               /* ipv4/ipv6 agnostic */
        hints.ai_socktype = SOCK_STREAM;           /* TCP stream sockets */
        hints.ai_flags = AI_PASSIVE;               /* get my ip */
        snprintf(tcpport, 5, "%li", config->port); /* tcp port to listen on */

        if ((status = getaddrinfo(NULL, tcpport, &hints, &servinfo)) != 0){
                fprintf(stderr, "getaddrinfo error: %s\n",
                                gai_strerror(status));
                free_config();
                exit(EXIT_FAILURE);
        }

        /* get a socket */
        sockme = socket(servinfo->ai_family, servinfo->ai_socktype,
                        servinfo->ai_protocol);

        /* reuse socket if already in use */
        setsockopt(sockme, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        /* bind to a port */
        bind(sockme, servinfo->ai_addr, servinfo->ai_addrlen);

        freeaddrinfo(servinfo);

        /* listening */
        if (listen(sockme, BACKLOG) == 0) {
                syslog(LOG_INFO, "Listening on port %li", config->port);
        }
        else {
                errsv = errno;
                fprintf(stderr, "ERROR: %s\n", strerror(errsv));
                syslog(LOG_ERR, "Failed to listen on port %li. Exiting.", 
                                                                config->port);
                free_config();
                exit(EXIT_FAILURE);
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

        /* set up child signal handler */
        signal(SIGCHLD, sigchld_handler);

        /* catch SIGINT for cleanup */
        signal(SIGINT, sigint_handler);

        /* catch SIGTERM for cleanup */
        signal(SIGTERM, sigterm_handler);

        /* catch HUP signal for config reload */
        signal(SIGHUP, sighup_handler);

        for (;;) {
                /* incoming! */
                ++concounter;
                new_fd = accept(sockme, (struct sockaddr *)&their_addr,
                                &addr_size);
                pid = fork(); /* fork new process to handle connection */
                if (pid == -1) {
                        /* fork failed */
                        return -1;
                }
                else if (pid == 0) {
                        /* let the children play */
                        close(sockme); /* children never listen */
                        handle_connection(new_fd, their_addr);
                }
                else {
                        /* parent can close connection */
                        close(new_fd);
                }
        }
}
