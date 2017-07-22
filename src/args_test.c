/* 
 * args_test.c - unit tests for args.c
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

#define _GNU_SOURCE
#include "args.h"
#include "args_test.h"
#include "minunit.h"
#include <string.h>
#include <stdlib.h>

char *test_args()
{
        char *argv[2] = {"invalid", "junk"};
        
        mu_assert("Ensure process_args() returns -1 when args invalid", 
                process_args(2 , argv) == -1);
        mu_assert("Ensure argue() accepts reload", argue(2, "reload") == 0);
        mu_assert("Ensure argue() only accepts reload as a solo argument",
                argue(3, "reload") != 0);
        mu_assert("Ensure argue() accepts shutdown",argue(2, "shutdown") == 0);
        mu_assert("Ensure argue() only accepts shutdown as a solo argument",
                argue(3, "shutdown") != 0);
        mu_assert("Ensure argue() accepts stop",argue(2, "stop") == 0);
        mu_assert("Ensure argue() accepts start",argue(2, "start") == 0);

        return 0;
}
