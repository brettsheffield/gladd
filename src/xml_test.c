/*
 * xml_test.c - tests for xml.c
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
#include "xml_test.h"
#include "xml.h"
#include "config.h"
#include "http.h"
#include "minunit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *test_xml_doc()
{
        char *xmldoc;

        request = http_init_request();
        asprintf(&request->res, "/myinstance/mybusiness/collection/element");

        mu_assert("Beginning test_xml_doc", buildxml(&xmldoc) == 0);
        mu_assert("Verify XML content", 
                strcmp(xmldoc,
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<resources/>\n")
                == 0);
        free(xmldoc);

#ifndef _NPG /* skip the following tests that require postgres */
        db_t *db;
        char *sql;
        char *xmltst = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<resources><row><id>0</id><name>boris</name></row><row><id>5</id><name>ivan</name></row><row><id>66</id><name>Boris</name></row></resources>\n";

        db = config->dbs->next;
        fprintf(stderr, "Switching to db %s (%s)\n", db->alias, db->type);
        asprintf(&sql, "SELECT * FROM test;");
        mu_assert("sqltoxml()", sqltoxml(db, sql, NULL, &xmldoc, 0) == 0);
        free(sql);
        fprintf(stderr, "%s\n", xmldoc);
        mu_assert("sqltoxml() - check xml", strcmp(xmldoc, xmltst) == 0);
        free(xmldoc);
#endif /* _NPG */

        free_request(&request);

        return 0;
}

char *test_xml_to_sql()
{
        char *schema = "test.xsd";
        char *xslt = "test.xsl";
        char *badxml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><journal transactdate=\"2013-02-08\" description=\"My First Journal Entry\"><debit account=\"1100\">100.00</debit><credit account=\"4000\">100.00</credit></journal>";
        char *goodxml = "<?xml version=\"1.0\" encoding=\"utf-8\"?> <request><data><journal transactdate=\"2013-02-08\" description=\"My First Journal Entry\"> <debit account=\"1100\" amount=\"120.00\" /> <credit account=\"2222\" amount=\"20.00\" /> <credit account=\"4000\" amount=\"100.00\" /> </journal></data></request>";
        char *sql;
        char *sqlout = "BEGIN;INSERT INTO journal (transactdate, description, authuser, clientip) VALUES ('2013-02-08','My First Journal Entry','testuser','::1');INSERT INTO ledger (journal, account, debit) VALUES (currval(pg_get_serial_sequence('journal','id')),'1100','120.00');INSERT INTO ledger (journal, account, credit) VALUES (currval(pg_get_serial_sequence('journal','id')),'2222','20.00');INSERT INTO ledger (journal, account, credit) VALUES (currval(pg_get_serial_sequence('journal','id')),'4000','100.00');COMMIT;";
        
        mu_assert("Validate some broken xml",
                xml_validate(schema, badxml) == -1);

        mu_assert("Validate some good xml",
                xml_validate(schema, goodxml) == 0);

        request = http_init_request();
        asprintf(&request->authuser, "testuser");
        asprintf(&request->clientip, "::1");
        mu_assert("Transform XML using XSLT",
                xmltransform(xslt, goodxml, &sql, NULL) == 0);

        fprintf(stderr, "%s\n", sql);

        mu_assert("Verify sql output from xslt", strcmp(sql, sqlout) == 0);

        free(sql);

        free_request(&request);

        return 0;
}

char *test_xml_replacevars()
{
        char *sql;

        request = http_init_request();
        asprintf(&request->res, "/myinstance/mybusiness/collection/element");
        asprintf(&sql, "SELECT * FROM $1.$0.myview");
        replacevars(&sql, request->res);
        printf("sql: %s\n", sql);
        mu_assert("sql variable subsitution",
                strcmp(sql,
                "SELECT * FROM mybusiness.myinstance.myview") == 0);


        free(sql);
        free_request(&request);
        request = NULL;

        return 0;
}
