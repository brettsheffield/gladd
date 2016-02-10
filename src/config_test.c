/* 
 * config_test.c - unit tests for config.c
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2015 Brett Sheffield <brett@gladserv.com>
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

#include "config_test.h"
#include "main.h"
#include "minunit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* process_config_line() must return 1 if line is a comment */
char *test_config_skip_comment()
{
        mu_assert("Ensure comments are skipped by config parser",
                process_config_line("# This line is a comment\n") == 1);
        return 0;
}

/* process_config_line() must return 1 if line is blank */
char *test_config_skip_blank()
{
        mu_assert("Ensure blank lines are skipped by config parser",
                process_config_line(" \t \n") == 1);
        return 0;
}

/* process_config_line() must return -1 if line is invalid */
char *test_config_invalid_line()
{
        mu_assert("Ensure invalid lines return error",
                process_config_line("gibberish") == -1);
        return 0;
}

/* test opening config file */
char *test_config_open_success()
{
        FILE *fd;

        fd = open_config("test.conf");
        mu_assert("Open test.conf for reading", fd != NULL);
        fclose(fd);
        return 0;
}

/* ensure failing to open config returns 0 (not an error) */
char *test_config_open_fail()
{
        mu_assert("Ensure failure to open file returns zero",
                read_config("fake.conf") == 0);
        return 0;
}

/* test default value of debug = 0 */
char *test_config_defaults()
{
        set_config_defaults();
        mu_assert("Ensure default debug=0", config->debug == 0);
        mu_assert("Ensure default port=8080", config->port == 8080);
        mu_assert("Ensure default daemon=0", config->daemon == 0);
        mu_assert("Ensure default pipelining=1", config->pipelining == 1);
        mu_assert("Ensure default keepalive=115", config->keepalive == 115);
        char *tmp;
        asprintf(&tmp, "%s v%s", PROGRAM, VERSION);
        mu_assert("Ensure default serverstring=PROGRAM vVERSION",
                strcmp(config->serverstring, tmp) == 0);
        free(tmp);
        mu_assert("Ensure default sessiontimeout=300",
                config->sessiontimeout == 300);
        mu_assert("Ensure default ssl=0", config->ssl == 0);
        mu_assert("Ensure default authrealm=gladd", 
                strncmp(config->authrealm, "gladd", 5) == 0);
        mu_assert("Ensure default encoding=UTF-8", 
                strncmp(config->encoding, "UTF-8", 5) == 0);
        mu_assert("Ensure default uploadmax=0", config->uploadmax == 0);
        mu_assert("Ensure default url_default=index.html", 
                strcmp(config->urldefault, "index.html") == 0);
        mu_assert("Ensure default x-forward=0", config->xforward == 0);
        return 0;
}

/* ensure config values are read from file */ 
char *test_config_set()
{
        read_config("test.conf");
        mu_assert("Ensure debug is set from config", config->debug == 1);
        mu_assert("Ensure port is set from config", config->port == 3000);
        mu_assert("Ensure daemon is set from config", config->daemon == 1);
        mu_assert("Ensure pipelining is set from config",
                config->pipelining == 0);
        mu_assert("Ensure keepalive is set from config",
                config->keepalive == 180);
        mu_assert("Ensure serverstring is set from config",
                strcmp(config->serverstring, "A server!") == 0);
        mu_assert("Ensure sessiontimeout is set from config",
                config->sessiontimeout == 600);
        mu_assert("Ensure ssl is set from config", config->ssl == 1);
        mu_assert("Ensure encoding is set from config", 
                strcmp(config->encoding, "ISO-8859-1") == 0);
        mu_assert("Ensure sslca is set from config", 
            strcmp(config->sslca, "/etc/ssl/certs/ca-certificates.crt") == 0);
        mu_assert("Ensure sslkey is set from config", 
                strcmp(config->sslkey, "/path/to/ssl.key") == 0);
        mu_assert("Ensure sslcert is set from config", 
                strcmp(config->sslcert, "/path/to/ssl.crt") == 0);
        mu_assert("Ensure sslcrl is set from config", 
                strcmp(config->sslcrl, "/path/to/crl.pem") == 0);
        mu_assert("Ensure uploadmax is set from config",
                config->uploadmax == 5);
        mu_assert("Ensure xmlpath is set from config", 
                strcmp(config->xmlpath,
                "/home/bacs/dev/gladbooksd/static/xml/") == 0);
        mu_assert("Ensure url_default is read from config",
                strcmp(config->urldefault, "/path/to/index.html") == 0);
        mu_assert("Ensure xforward is set from config", config->xforward == 1);
        return 0;
}

/* tests for reading auth lines in config */
#ifndef _NAUTH
char *test_config_read_auth()
{
        auth_t *a;

        mu_assert("Ensure auth lines are read from config",
                config->auth != NULL);
        mu_assert("Reading 1st auth from config", a = config->auth);
        mu_assert("Check 1st auth->type", strcmp(a->type, "ldap") == 0);
        mu_assert("Check 1st auth->db", strcmp(a->db, "ldap1") == 0);
        mu_assert("Check 1st auth->sql", strcmp(a->sql, "ld_auth") == 0);
        mu_assert("Check 1st auth->bind", strcmp(a->bind, "uid") == 0);
        mu_assert("Reading 2nd auth from config", a = a->next);
        mu_assert("Check 2nd auth->type", strcmp(a->type, "user") == 0);
        mu_assert("Reading 3rd auth from config", a = a->next);
        mu_assert("Check 2nd auth->type", strcmp(a->type, "pam") == 0);
        mu_assert("Skip fake auth type", a = a->next);
        mu_assert("Ensure final auth->next returns NULL", a->next == NULL);
        mu_assert("getauth()", getauth("ldap"));

        return 0;
}
#endif

char *test_config_read_users()
{
        user_t *u;

        mu_assert("Ensure user lines are read from config", 
                config->users != NULL);
        mu_assert("Reading 1st user from config", u = config->users);
        mu_assert("Check 1st user->username",
                strcmp(u->username, "alpha") == 0);
        mu_assert("Check 1st user->password",
                strcmp(u->password, "alphasecret") == 0);
        mu_assert("Reading 2nd user from config", u = u->next);
        mu_assert("Check 2nd user->username",
                strcmp(u->username, "bravo") == 0);
        mu_assert("Check 2nd user->password",
                strcmp(u->password, "bravosecret") == 0);
        mu_assert("Reading 3rd user from config", u = u->next);
        mu_assert("Check 3rd user->username",
                strcmp(u->username, "charlie") == 0);
        mu_assert("Check 3rd user->password",
                strcmp(u->password, "charliesecret") == 0);
        mu_assert("Ensure final users->next returns NULL", u->next == NULL);
        mu_assert("Fetch user by username and check password", 
                strcmp(getuser("bravo")->password, "bravosecret") == 0);

        return 0;
}

char *test_config_read_groups()
{
        group_t *g;

        mu_assert("Ensure group lines are read from config", 
                config->groups != NULL);

        mu_assert("Fetch group by name", g = getgroup("test1"));
        mu_assert("Check group member #1",
                strcmp(g->members->username, "alpha") == 0);
        mu_assert("Check group member #2",
                strcmp(g->members->next->username, "bravo") == 0);

        mu_assert("Fetch next group by name", g = getgroup("test2"));
        mu_assert("Check group member #1",
                strcmp(g->members->username, "bravo") == 0);
        mu_assert("Check group member #2",
                strcmp(g->members->next->username, "charlie") == 0);


        return 0;
}

/* test successive reads of url->next */
char *test_config_read_url()
{
        url_t *u;

        mu_assert("Ensure urls are read from config", config->urls != NULL);
        mu_assert("Ensure urls are read from config", 
                        strcmp(config->urls->type, "static") == 0);

        mu_assert("Reading 1st url from config", u = config->urls);
        mu_assert("Checking 1st url from config", 
                        strcmp(u->url, "/static/") == 0);
        mu_assert("Checking 1st url method from config", 
                        strcmp(u->method, "GET") == 0);
        mu_assert("Reading 2nd url from config", u = u->next);
        mu_assert("Checking 2nd url from config", 
                        strcmp(u->url, "/static2/") == 0);
        mu_assert("Checking 2nd url method from config", 
                        strcmp(u->method, "GET") == 0);
        mu_assert("Reading 3rd url from config", u = u->next);
        mu_assert("Checking 3rd url from config", 
                        strcmp(u->url, "/static3/") == 0);
        mu_assert("Checking 3rd url method from config", 
                        strcmp(u->method, "GET") == 0);
        mu_assert("Reading 4th url from config", u = u->next);
        mu_assert("Checking 4th url from config ... url", 
                        strcmp(u->url, "/sqlview/") == 0);
        mu_assert("... method", strcmp(u->method, "GET") == 0);
        mu_assert("... db", strcmp(u->db, "db1") == 0);
        mu_assert("... view", strcmp(u->view, "sql1") == 0);
        mu_assert("Reading 5th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "POST") == 0);
        mu_assert("... db", strcmp(u->db, "db1") == 0);
        mu_assert("... view", strcmp(u->view, "test") == 0);
        mu_assert("Reading 6th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "POST") == 0);
        mu_assert("... db", strcmp(u->db, "db1") == 0);
        mu_assert("... view", strcmp(u->view, "xmlpost") == 0);
        mu_assert("Reading 7th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "POST") == 0);
        mu_assert("... db", strcmp(u->db, "db1") == 0);
        mu_assert("... view", strcmp(u->view, "journal") == 0);
        mu_assert("Reading 8th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "GET") == 0);
        mu_assert("... db", strcmp(u->db, "db1") == 0);
        mu_assert("... view", strcmp(u->view, "someview") == 0);
        mu_assert("Reading 9th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "POST") == 0);
        mu_assert("... url", strcmp(u->url, "/filestore/") == 0);
        mu_assert("... path", strcmp(u->path, "/tmp/filestore/") == 0);
        mu_assert("Reading 10th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "GET") == 0);
        mu_assert("... url", strcmp(u->url, "/plugin1/") == 0);
        mu_assert("... path", strcmp(u->path, "echo \"1234\" | md5sum") == 0);
        mu_assert("Reading 11th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "POST") == 0);
        mu_assert("... url", strcmp(u->url, "/plugin2/") == 0);
        mu_assert("... path", strcmp(u->path, "/usr/bin/sort") == 0);
        mu_assert("Reading 12th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "GET") == 0);
        mu_assert("... url", strcmp(u->url, "/report/*") == 0);
        mu_assert("... path", strcmp(u->path, "http://192.168.0.1/") == 0);
        mu_assert("Reading 13th url from config", u = u->next);
        mu_assert("... method", strcmp(u->method, "GET") == 0);
        mu_assert("... url", strcmp(u->url, "/report2/*/*/") == 0);
        mu_assert("... path", strcmp(u->path, "http://192.168.0.1/$1") == 0);

        mu_assert("Ensure final url->next returns NULL", u->next == NULL);

        return 0;
}

/* test reading sql from config */
char *test_config_read_sql()
{
        sql_t *s;

        mu_assert("Ensure sql statements are read from config", 
                config->sql !=NULL);

        mu_assert("Reading 1st sql from config", s = config->sql);
        mu_assert("Check 1st sql alias", strcmp(s->alias, "sql1") == 0);
        mu_assert("Check 1st sql statement",
                strcmp(s->sql, "SELECT * FROM test") == 0);
        mu_assert("Reading 2nd sql from config", s = s->next);
        mu_assert("Check 2nd sql alias", strcmp(s->alias, "sql2") == 0);
        mu_assert("Check 2nd sql statement",
                strcmp(s->sql, "SELECT * FROM test ORDER BY name DESC") == 0);

        /* skip a few */
        mu_assert("Reading 3rd sql from config", s = s->next);
        mu_assert("Reading 4th sql from config", s = s->next);
        mu_assert("Reading 5th sql from config", s = s->next);
        mu_assert("Reading 6th sql from config", s = s->next);
        mu_assert("Reading 7th sql from config", s = s->next);
        mu_assert("Reading 8th sql from config", s = s->next);
        mu_assert("Reading 9th sql from config", s = s->next);
        
        mu_assert("Ensure final sql->next returns NULL", s->next == NULL);

        mu_assert("Get sql from config", strcmp(getsql("sql2"), 
                "SELECT * FROM test ORDER BY name DESC") == 0);

        return 0;
}

/* ensure add_acl() rejects junk */
char *test_config_add_acl_invalid()
{
        mu_assert("ensure add_acl() rejects junk", add_acl("invalid junk"));
        return 0;
}

/* test acl can be read from config */
char *test_config_acl_allow_all()
{
        acl_t *acl;

        /* read and check first acl */
        acl = config->acls;
        mu_assert("test 1st acl->method is read from config",
                strncmp(acl->method, "GET", strlen(acl->method)) == 0);
        mu_assert("test 1st acl->url is read from config", 
                strncmp(acl->url, "/static/secret.html",
                strlen(acl->url)) == 0);
        mu_assert("test 1st acl->type is read from config", 
                strncmp(acl->type, "require", strlen(acl->type)) == 0);
        mu_assert("test 1st acl->auth is read from config", 
                strncmp(acl->auth, "*", strlen(acl->auth)) == 0);
        /* check second acl */
        acl = acl->next;
        mu_assert("test 2nd acl->method is read from config",
                strncmp(acl->method, "GET", strlen(acl->method)) == 0);
        mu_assert("test 2nd acl->url is read from config", 
                strncmp(acl->url, "/static/*", strlen(acl->url)) == 0);
        mu_assert("test 2nd acl->type is read from config", 
                strncmp(acl->type, "allow", strlen(acl->type)) == 0);
        mu_assert("test 2nd acl->auth is read from config", 
                strncmp(acl->auth, "*", strlen(acl->auth)) == 0);

        /* check third acl */
        acl = acl->next;
        mu_assert("test 3rd acl->method is read from config",
                strncmp(acl->method, "GET", strlen(acl->method)) == 0);
        mu_assert("test 3rd acl->url is read from config", 
                strncmp(acl->url, "/sqlview/", strlen(acl->url)) == 0);
        mu_assert("test 3rd acl->type is read from config", 
                strncmp(acl->type, "allow", strlen(acl->type)) == 0);
        mu_assert("test 3rd acl->auth is read from config", 
                strncmp(acl->auth, "*", strlen(acl->auth)) == 0);

        acl = acl->next;
        mu_assert("test 4th acl->method is read from config",
                strncmp(acl->method, "POST", strlen(acl->method)) == 0);
        mu_assert("test 4th acl->url is read from config", 
                strncmp(acl->url, "/sqlview/", strlen(acl->url)) == 0);
        mu_assert("test 4th acl->type is read from config", 
                strncmp(acl->type, "allow", strlen(acl->type)) == 0);
        mu_assert("test 4th acl->auth is read from config", 
                strncmp(acl->auth, "*", strlen(acl->auth)) == 0);

        acl = acl->next;
        mu_assert("test 5th acl->method is read from config",
                strncmp(acl->method, "GET", strlen(acl->method)) == 0);
        mu_assert("test 5th acl->url is read from config", 
                strncmp(acl->url, "/", strlen(acl->url)) == 0);
        mu_assert("test 5th acl->type is read from config", 
                strncmp(acl->type, "deny", strlen(acl->type)) == 0);
        mu_assert("test 5th acl->auth is read from config", 
                strncmp(acl->auth, "*", strlen(acl->auth)) == 0);

        /* ensure no more acls */
        mu_assert("Ensure final acl->next returns NULL", acl->next == NULL);

        return 0;
}

char *test_config_db()
{
        db_t *db;

        mu_assert("Ensure dbs are read from config", config->dbs != NULL);

        /* read and check first database */
        db = config->dbs;

        mu_assert("Check 1st db->alias", strcmp(db->alias, "db_fake") == 0);
        mu_assert("Check 1st db->type", strcmp(db->type, "pg") == 0);
        mu_assert("Check 1st db->host", strcmp(db->host, "localhost") == 0);
        mu_assert("Check 1st db->db", strcmp(db->db, "gladd_fake") == 0);

        /* check next (postgres) db */
        mu_assert("Test reading postgres db from config", db = db->next);
        mu_assert("Check 2nd db->alias", strcmp(db->alias, "db_test") == 0);
        mu_assert("Check 2nd db->type", strcmp(db->type, "pg") == 0);
        mu_assert("Check 2nd db->host", strcmp(db->host, "localhost") == 0);
        mu_assert("Check 2nd db->db", strcmp(db->db, "gladd_test") == 0);

        /* check next (mysql) db */
        mu_assert("Test reading mysql db from config", db = db->next);
        mu_assert("Check 2nd db->alias", strcmp(db->alias, "db_test_my") == 0);
        mu_assert("Check 2nd db->type", strcmp(db->type, "my") == 0);
        mu_assert("Check 2nd db->host", strcmp(db->host, "localhost") == 0);
        mu_assert("Check 2nd db->db", strcmp(db->db, "gladd_test") == 0);
        mu_assert("Check 2nd db->user", strcmp(db->user, "myuser") == 0);
        mu_assert("Check 2nd db->pass", strcmp(db->pass, "mypass") == 0);

        /* check next (ldap) db */
        mu_assert("Test reading ldap db from config", db = db->next);
        mu_assert("Check 3rd db->alias", strcmp(db->alias, "ldap1") == 0);
        mu_assert("Check 3rd db->type", strcmp(db->type, "ldap") == 0);
        mu_assert("Check 3rd db->host",
                        strcmp(db->host, "ldap://ldaptestserver") == 0);
        mu_assert("Check 3rd db->db",
                                strcmp(db->db, "dc=gladserv,dc=com") == 0);

        /* check next (ldap with username and password) db */
        mu_assert("Test reading next ldap db from config", db = db->next);
        mu_assert("Check 4th db->alias", strcmp(db->alias, "ldap2") == 0);
        mu_assert("Check 4th db->type", strcmp(db->type, "ldap") == 0);
        mu_assert("Check 4th db->host",
                        strcmp(db->host, "ldap://ldap.example.com") == 0);
        mu_assert("Check 4th db->db",
                                strcmp(db->db, "dc=example,dc=com") == 0);
        mu_assert("Check 4th db->user", strcmp(db->user, "myuser") == 0);
        mu_assert("Check 4th db->pass", strcmp(db->pass, "mypass") == 0);

        /* check next (tds db) */
        mu_assert("Test reading next db (tdb) from config", db = db->next);

        /* ensure no more dbs */
        mu_assert("Ensure final db->next returns NULL", db->next == NULL);

        /* fetch db by alias */
        mu_assert("getdb() - fetch db by alias",
                strcmp(getdb("db_test")->db, "gladd_test") == 0);

        return 0;
}

char *test_config_multiline()
{
        char *sql;

        mu_assert("Fetch multi-line sql", sql = getsql("createaccount"));
        mu_assert("Check multi-line sql is read correctly from config",
                strcmp(getsql("createaccount"),
                "INSERT INTO account (id, name) VALUES (0, 'Boris')") == 0);

        return 0;
}
