/*
 * args.c - handle commandline arguments
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012, 2013, 2017 Brett Sheffield <brett@gladserv.com>
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

#include "config.h"
#include "help.h"
#include "main.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

int g_signal = 0;

int argue(int argc, char *arg)
{
        if (argc) {
                if (strcmp(arg, "start") == 0) {
                        return 0;
                }
                else if (strcmp(arg, "reload") == 0) {
	                if (argc > 2) goto argue_solo;
                        g_signal = SIGHUP;
                        return 0;
                }
                else if ((strcmp(arg, "shutdown") == 0)
                       ||(strcmp(arg, "stop") == 0)) 
                {
	                if (argc > 2) goto argue_solo;
                        g_signal = SIGTERM;
                        return 0;
                }
                else if (strcmp(arg, "status") == 0) {
                        g_signal = SIGUSR1;
                        return 0;
                }
                else if ((strcmp(arg, "--version") == 0) ||
                         (strcmp(arg, "-V") == 0))
                {
	                help();
	                return 0;
		}
                else if ((strcmp(arg, "--version") == 0) ||
                         (strcmp(arg, "-V") == 0))
                {
                        printf("%s\n", VERSION);
                }
                else {
                        help();
                        return -1;
                }
        }
argue_solo:
        fprintf(stderr, "%s must be a solo argument\n", arg);
        return -1;
}

int process_args(int argc, char **argv)
{
        int i;

        if (argc == 1) {
                help();
                return -1;
        }

        for (i = 1; i < argc; i++) {
                if (argue(argc, argv[i]) != 0) {
                        return -1;
                }
        }

        return 0;
}
