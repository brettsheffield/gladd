/* 
 * config.h
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2016 Brett Sheffield <brett@gladserv.com>
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

#ifndef __GLADD_CONFIG_H__
#define __GLADD_CONFIG_H__ 1

#include <stdio.h>
#ifndef _NGLADDB
#include "gladdb/db.h"
#endif
#include <openssl/blowfish.h>

#define DEFAULT_CONFIG "/etc/gladd.conf"

typedef struct acl_t {
        char *type; /* allow or deny */
        char *method;
        char *url;
        char *auth;
        char *params;
        char *skipon;
        char *full;
        int  skip;
        struct acl_t *next;
} acl_t;

typedef struct auth_t {
        char *alias;
        char *type;
        char *db;
        char *sql;
        char *bind;     /* field to bind as */
        struct auth_t *next;
} auth_t;

typedef struct config_t {
        char *authrealm;
        long daemon;         /* 0 = daemonise (default), 1 = don't detach */
        long debug;
        char *encoding;      /* encoding to use - default UTF-8 */
        long dropprivs;      /* 1 = drop root privileges (default), 0=don't */
        long port;
        long pipelining;     /* 1 = allow http pipelining(default), 0=disable*/
        long keepalive;      /* inactivity timeout on tcp connections (s) */
        long sessiontimeout; /* session timeout (s) */
        char *serverstring;
        long ssl;            /* 0 = disable ssl (default), 1 = enable ssl */
        char *sslca;
        char *sslkey;
        char *sslcert;
        char *sslcrl;
        char *secretkey;     /* secret key used for en/decrypting cookies */
        BF_KEY ctx;          /* blowfish context */
        long uploadmax;      /* Max size of upload files (MB) 0=unlimited */
        char *urldefault;
        long xforward;
        char *xmlpath;       /* path to xml, xsl and xsd files */
        struct acl_t *acls;
        struct auth_t *auth;
        struct db_t *dbs;
        struct sql_t *sql;
        struct url_t *urls;
        struct user_t *users;
        struct group_t *groups;
} config_t;

typedef struct group_t {
        char *name;
        struct user_t *members;
        struct group_t *next;
} group_t;

#ifdef _NGLADDB
typedef struct db_t {
        char *alias; /* a convenient handle to refer to this db by */
        char *type;  /* type of database: pg, my, ldap, tds */
        char *host;  /* hostname or ip for this database eg. "localhost" */
        char *db;    /* name of the database */
        char *user;  /* username (mysql) */
        char *pass;  /* password (mysql) */
        void *conn;  /* pointer to open db connection */
        struct db_t *next; /* pointer to next db so we can loop through them */
} db_t;

typedef struct keyval_t {
        char *key;
        char *value;
        struct keyval_t *next;
} keyval_t;

typedef struct field_t {
        char *fname;
        char *fvalue;
        struct field_t *next;
} field_t;
#endif

typedef struct sql_t {
        char *alias;
        char *sql;
        struct sql_t *next;
} sql_t;

typedef struct url_t {
        char *type;
        char *method;
        char *url;
        char *domain;
        char *path;
        char *db;
        char *view;
        struct url_t *next;
} url_t;

typedef struct user_t {
        char *username;
        char *password;
        struct user_t *next;
} user_t;

extern config_t *config;
extern int g_signal;
extern int sockme;

int     add_acl (char *value);
int     add_auth (char *value);
int     add_db (char *value);
int     add_group (char *value);
int     add_sql (char *value);
int     add_url_handler(char *value);
int     add_user (char *value);
void    free_acls();
void    free_auth();
void    free_config();
void    free_db(db_t *db);
void    free_dbs();
void    free_groups(group_t *g);
void    free_keyval(keyval_t *h);
db_t   *getdb(char *alias);
void    free_sql();
void    free_urls(url_t *u);
void    free_users(user_t *u);
#ifndef _NAUTH
auth_t *getauth(char *alias);
#endif
char   *getsql(char *alias);
user_t *getuser(char *username);
group_t *getgroup(char *name);
FILE   *open_config(char *configfile);
int     process_config_file(char *configfile);
int     process_config_line(char *line);
int     read_config(char *configfile);
int     set_config_defaults();
int     set_config_long(long *confset, char *keyname, long i, long min,
                long max);
int     set_domain (char *value);
int     set_docroot (char *value);
int     set_encoding(char *value);
int     set_ssl(char *key, char *value);
int     set_xmlpath(char *value);

#endif /* __GLADD_CONFIG_H__ */
