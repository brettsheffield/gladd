/*
 * string_test.c - handy string functions
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
#include <string.h>
#include <stdlib.h>
#include "minunit.h"
#include "string_test.h"

char *test_string_trimstr()
{
        char *s;
        char *left = "Clowns to the left of me";
        char *right = "Jokers to the right";
        char *middle = "Here I am, stuck in the middle with you";
        char *desc;

        asprintf(&s, "    %s", left);
        asprintf(&desc, "lstrip() \"%s\"", left);
        mu_assert(desc, strcmp(lstrip(s), left) == 0);
        free(s);
        free(desc);

        asprintf(&s, "%s   ", right);
        asprintf(&desc, "rstrip() \"%s\"", right);
        mu_assert(desc, strcmp(rstrip(s), right) == 0);
        free(s);
        free(desc);

        asprintf(&s, "   %s   ", middle);
        asprintf(&desc, "strip()  \"%s\"", middle);
        mu_assert(desc, strcmp(strip(s), middle) == 0);
        free(s);
        free(desc);
        
        return 0;
}

char *test_string_replace()
{
        char *str;

        str = replace("This is wrong\n", "right", "correct");
        mu_assert("Test string replacement (search string not in target)",
                strcmp(str, "This is wrong\n") == 0);
        free(str);

        str = replace("This is right\n", "right", "correct");
        mu_assert("Test string replacement",
                strcmp(str, "This is correct\n") == 0);
        free(str);

        str = replaceall("oogie! oogie! oogie!", "oogie", "oi");
        mu_assert("Test multiple string replacement",
                strcmp(str, "oi! oi! oi!") == 0);

        free(str);

        return 0;
}

char *test_string_tokenize()
{
        char *teststring;
        char **tokens;
        int toknum;
        
        asprintf(&teststring, "/instance/business/collection/element");
        tokens = tokenize(&toknum, &teststring, "/");
        mu_assert("Test string tokenizer - count tokens", toknum == 5);
        mu_assert("Test string tokenizer - token #0",
                strcmp(tokens[0], "") == 0);
        mu_assert("Test string tokenizer - token #1",
                strcmp(tokens[1], "instance") == 0);
        mu_assert("Test string tokenizer - token #2",
                strcmp(tokens[2], "business") == 0);
        mu_assert("Test string tokenizer - token #3",
                strcmp(tokens[3], "collection") == 0);
        mu_assert("Test string tokenizer - token #4",
                strcmp(tokens[4], "element") == 0);

        free(tokens);
        free(teststring);

        /* multiple character delimiter */
        toknum = 0;
        asprintf(&teststring, "split***with***multichar***delimiter");
        tokens = tokenize(&toknum, &teststring, "***");
        mu_assert("Test string tokenizer (multicharacter delimiter)" \
                " - count tokens", toknum == 4);
        mu_assert("Test string tokenizer (multicharacter delimiter)" \
                " - token #0", strcmp(tokens[0], "split") == 0);
        mu_assert("Test string tokenizer (multicharacter delimiter)" \
                " - token #1", strcmp(tokens[1], "with") == 0);
        mu_assert("Test string tokenizer (multicharacter delimiter)" \
                " - token #2", strcmp(tokens[2], "multichar") == 0);
        mu_assert("Test string tokenizer (multicharacter delimiter)" \
                " - token #3", strcmp(tokens[3], "delimiter") == 0);

        free(tokens);
        free(teststring);

        return 0;
}
