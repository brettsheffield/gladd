/* 
 * config.c
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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "main.h"
#include "config.h"
#include "string.h"

void    handle_url_static(char *type, char params[LINE_MAX]);
void    handle_url_dynamic(char *type, char params[LINE_MAX]);

/* set config defaults */
config_t config_default = {
        .authrealm      = "gladd",
        .daemon         = 0,
        .debug          = 0,
        .dropprivs      = 1,
        .encoding       = "UTF-8",
        .xmlpath        = ".",
        .port           = 8080,
        .pipelining     = 1,
        .keepalive      = 115,
        .sessiontimeout = 300,
        .ssl            = 0,
        .xforward       = 0,
        .uploadmax      = 0,
        .urldefault     = "index.html"
};

config_t *config;
config_t *config_new;

/* current domain being processed in config, default = '*' */
char *domain;
char *docroot;          /* default = '/' */

acl_t  *prevacl;        /* pointer to last acl */
auth_t *prevauth;       /* pointer to last auth */
db_t   *prevdb;         /* pointer to last db  */
sql_t  *prevsql;        /* pointer to last sql */
url_t  *prevurl;        /* pointer to last url */
user_t *prevuser;       /* pointer to last user */
group_t *prevgroup;     /* pointer to last group */

/* add acl */
int add_acl (char *value)
{
        acl_t *newacl;
        char method[LINE_MAX] = "";
        char url[LINE_MAX] = "";
        char type[LINE_MAX] = "";
        char auth[LINE_MAX] = "";
        char authtype[LINE_MAX] = "";
        int skip = 0;

        if ((sscanf(value, "%s %s %s %s", 
                method, url, type, auth) != 4) &&
        (sscanf(value, "%s %s %s %s %s", 
                method, url, type, auth, authtype) != 5))
        {
                /* config line didn't match expected patterns */
                return -1;
        }

        /* check for [{success,fail}=2] in type */
        char tmp[LINE_MAX] = "";
        char skipon[LINE_MAX] = "";
        if (sscanf(type, "%[^[]%*c%[^=]%*c%i]", tmp, skipon, &skip) == 3) {
                strcpy(type, tmp);
        }

        newacl = malloc(sizeof(struct acl_t));
        if ((strcmp(type, "allow") == 0) ||
            (strcmp(type, "deny") == 0))
        {
                newacl->method = strndup(method, LINE_MAX);
                newacl->url = strndup(url, LINE_MAX);
                newacl->type = strndup(type, LINE_MAX);
                newacl->auth = strndup(auth, LINE_MAX);
                newacl->params = NULL;
                newacl->skipon = strndup(skipon, LINE_MAX);
                newacl->skip = skip;
                newacl->full = strdup(value);
                newacl->next = NULL;
        }
        else if ((strcmp(type, "require") == 0) ||
                 (strcmp(type, "sufficient") == 0) ||
                 (strcmp(type, "optional") == 0) ||
                 (strcmp(type, "params") == 0)) 
        {
                newacl->method = strndup(method, LINE_MAX);
                newacl->url = strndup(url, LINE_MAX);
                newacl->type = strndup(type, LINE_MAX);
                newacl->auth = strndup(auth, LINE_MAX);
                newacl->params = strndup(authtype, LINE_MAX);
                newacl->skipon = strndup(skipon, LINE_MAX);
                newacl->skip = skip;
                newacl->full = strdup(value);
                newacl->next = NULL;
        }
        else {
                fprintf(stderr, "Invalid acl type: %s\n", type);
                return -1;
        }
        if (prevacl != NULL) {
                /* update ->next ptr in previous acl
                 * to point to new */
                prevacl->next = newacl;
        }
        else {
                /* no previous acl, 
                 * so set first ptr in config */
                config_new->acls = newacl;
        }
        prevacl = newacl;
        return 0;
}

int add_auth (char *value)
{
        auth_t *newauth;
        char alias[LINE_MAX] = "";
        char type[LINE_MAX] = "";
        char db[LINE_MAX] = "";
        char sql[LINE_MAX] = "";
        char bind[LINE_MAX] = "";

        if (sscanf(value, "%s %s %s %s %s", alias, type, db, sql, bind) != 5) {
                /* config line didn't match expected patterns */
                return -1;
        }
        newauth = malloc(sizeof(struct auth_t));
        if (strcmp(type, "ldap") == 0) {
                newauth->alias = strdup(alias);
                newauth->type = strdup(type);
                newauth->db = strdup(db);
                newauth->sql = strdup(sql);
                newauth->bind = strdup(bind);
                newauth->next = NULL;
        }
        else if (strcmp(type, "user") == 0) {
                newauth->alias = strdup(alias);
                newauth->type = strdup(type);
                newauth->db = strdup(db);
                newauth->sql = strdup(sql);
                newauth->bind = strdup(bind);
                newauth->next = NULL;
        }
        else if (strcmp(type, "pam") == 0) {
                newauth->alias = strdup(alias);
                newauth->type = strdup(type);
                newauth->db = strdup(db);
                newauth->sql = strdup(sql);
                newauth->bind = strdup(bind);
                newauth->next = NULL;
        }
        else if (strcmp(type, "group") == 0) {
                newauth->alias = strdup(alias);
                newauth->type = strdup(type);
                newauth->db = strdup(db);
                newauth->sql = strdup(sql);
                newauth->bind = strdup(bind);
                newauth->next = NULL;
        }
        else if (strcmp(type, "cookie") == 0) {
                newauth->alias = strdup(alias);
                newauth->type = strdup(type);
                newauth->db = strdup(db);
                newauth->sql = strdup(sql);
                newauth->bind = strdup(bind);
                newauth->next = NULL;
        }
        else {
                free(newauth);
                fprintf(stderr, "Invalid auth type\n");
                return -1;
        }
        if (prevauth != NULL) {
                /* update ->next ptr in previous auth
                 * to point to new */
                prevauth->next = newauth;
        }
        else {
                /* no previous auth, 
                 * so set first ptr in config */
                config_new->auth = newauth;
        }
        prevauth = newauth;
        return 0;
}

/* store database config */
int add_db (char *value)
{
        db_t *newdb;
        char alias[LINE_MAX] = "";
        char type[LINE_MAX] = "";
        char host[LINE_MAX] = "";
        char db[LINE_MAX] = "";
        char user[LINE_MAX] = "";
        char pass[LINE_MAX] = "";

        /* mysql/ldap config lines may have 6 args, postgres has 4 */
        if (sscanf(value, "%s %s %s %s %s %s", alias, type, host, db,
                                                            user, pass) != 6)
        {
                if (sscanf(value, "%s %s %s %s", alias, type, host, db) != 4) {
                        /* config line didn't match expected patterns */
                        return -1;
                }
        }

        newdb = malloc(sizeof(struct db_t));

        if (strcmp(type, "pg") == 0) {
                newdb->alias = strndup(alias, LINE_MAX);
                newdb->type = strndup(type, LINE_MAX);
                newdb->host = strndup(host, LINE_MAX);
                newdb->db = strndup(db, LINE_MAX);
                newdb->user=NULL;
                newdb->pass=NULL;
                newdb->conn=NULL;
                newdb->next=NULL;
        }
        else if (strcmp(type, "my") == 0) {
                newdb->alias = strndup(alias, LINE_MAX);
                newdb->type = strndup(type, LINE_MAX);
                newdb->host = strndup(host, LINE_MAX);
                newdb->db = strndup(db, LINE_MAX);
                newdb->user = strndup(user, LINE_MAX);
                newdb->pass = strndup(pass, LINE_MAX);
                newdb->conn=NULL;
                newdb->next=NULL;
        }
        else if (strcmp(type, "tds") == 0) {
                newdb->alias = strndup(alias, LINE_MAX);
                newdb->type = strndup(type, LINE_MAX);
                newdb->host = strndup(host, LINE_MAX);
                newdb->db = strndup(db, LINE_MAX);
                newdb->user = strndup(user, LINE_MAX);
                newdb->pass = strndup(pass, LINE_MAX);
                newdb->conn=NULL;
                newdb->next=NULL;
        }
        else if (strcmp(type, "ldap") == 0) {
                newdb->alias = strndup(alias, LINE_MAX);
                newdb->type = strndup(type, LINE_MAX);
                newdb->host = strndup(host, LINE_MAX);
                newdb->db = strndup(db, LINE_MAX);
                newdb->user = strlen(user) == 0 ? NULL:strndup(user,LINE_MAX);
                newdb->pass = strlen(pass) == 0 ? NULL:strndup(pass,LINE_MAX);
                newdb->conn=NULL;
                newdb->next=NULL;
        }
        else {
                fprintf(stderr, "Invalid database type\n");
                return -1;
        }

        if (prevdb != NULL) {
                /* update ->next ptr in previous db
                 * to point to new */
                prevdb->next = newdb;
        }
        else {
                /* no previous db, 
                 * so set first ptr in config */
                config_new->dbs = newdb;
        }
        prevdb = newdb;
        return 0;
}

/* store group in config */
int add_group(char *value)
{
        group_t *new;
        char name[LINE_MAX] = "";
        char *users = NULL;
        char **members;
        int i, j;
        user_t *u, *tmp;

        users = malloc(LINE_MAX);
        if (sscanf(value, "%s %[^\n]", name, users) != 2) {
                free(users);
                return -1;
        }

        new = malloc(sizeof(struct group_t));

        new->name = strndup(name, LINE_MAX);

        /* group members */
        members = tokenize(&i, &users, ",");
        for (j=0; j<i; j++) {
                u = malloc(sizeof(user_t));
                u->username = strdup(strip(members[j]));
                u->password = NULL;
                u->next = NULL;
                if (j == 0) {
                        new->members = u;
                }
                else {
                        tmp->next = u;
                }
                tmp = u;
                u = NULL;
        }
        new->next = NULL;

        free(users);
        free(members);

        if (prevgroup != NULL)
                prevgroup->next = new;
        else
                config_new->groups = new;
        prevgroup = new;

        return 0;
}

/* store sql in config */
int add_sql(char *value)
{
        sql_t *newsql;
        char alias[LINE_MAX] = "";
        char *sql = calloc(1, strlen(value) + 1);

        if (sscanf(value, "%s %[^\n]", alias, sql) != 2) {
                free(sql);
                return -1;
        }

        newsql = malloc(sizeof(struct sql_t));
        if (newsql == NULL) {
                syslog(LOG_ERR, "malloc() failed");
                free(sql);
                return -1;
        }

        newsql->alias = strndup(alias, LINE_MAX);
        newsql->sql = sql;
        newsql->next = NULL;

        if (prevsql != NULL)
                prevsql->next = newsql;
        else
                config_new->sql = newsql;
        prevsql = newsql;

        return 0;
}

/* add url handler */
int add_url_handler(char *value)
{
        char type[LINE_MAX];
        char params[LINE_MAX];

        /* TODO: refactor this */
        if (sscanf(value, "%s %[^\n]", type, params) == 2) {
                if (strcmp(type, "static") == 0) {
                        handle_url_static("static", params);
                }
#ifdef _GIT
		else if (strcmp(type, "git") == 0) {
                        handle_url_dynamic("git", params);
                }
#endif /* _GIT */
                else if (strcmp(type, "ldif") == 0) {
                        handle_url_dynamic("ldif", params);
                }
                else if (strcmp(type, "sqlview") == 0) {
                        handle_url_dynamic("sqlview", params);
                }
                else if (strcmp(type, "sqlexec") == 0) {
                        handle_url_dynamic("sqlexec", params);
                }
                else if (strcmp(type, "xmlpost") == 0) {
                        handle_url_dynamic("xmlpost", params);
                }
                else if (strcmp(type, "xslpost") == 0) {
                        handle_url_dynamic("xslpost", params);
                }
                else if (strcmp(type, "xslt") == 0) {
                        handle_url_dynamic("xslt", params);
                }
                else if (strcmp(type, "upload") == 0) {
                        handle_url_static("upload", params);
                }
                else if (strcmp(type, "plugin") == 0) {
                        handle_url_static("plugin", params);
                }
                else if (strcmp(type, "proxy") == 0) {
                        handle_url_static("proxy", params);
                }
                else if (strcmp(type, "rewrite") == 0) {
                        handle_url_static("rewrite", params);
                }
                else {
                        fprintf(stderr, "skipping unhandled url type '%s'\n", 
                                                                        type);
                        return -1;
                }
        }
        else {
                return -1;
        }

        return 0;
}

/* store user in config */
int add_user(char *value)
{
        user_t *newuser;
        char username[LINE_MAX] = "";
        char password[LINE_MAX] = "";

        if (sscanf(value, "%s %[^\n]", username, password) != 2) {
                return -1;
        }

        newuser = malloc(sizeof(struct user_t));

        newuser->username = strndup(username, strlen(username));
        newuser->password = strndup(password, strlen(password));
        newuser->next = NULL;

        if (prevuser != NULL)
                prevuser->next = newuser;
        else
                config_new->users = newuser;
        prevuser = newuser;

        return 0;
}


/* clean up config->acls memory */
void free_acls()
{
        acl_t *a;
        acl_t *tmp;

        a = config->acls;
        while (a != NULL) {
                free(a->method);
                free(a->url);
                free(a->type);
                free(a->auth);
                free(a->params);
                free(a->skipon);
                free(a->full);
                tmp = a;
                a = a->next;
                free(tmp);
        }
        config->acls = NULL;
}

/* free auth structs */
void free_auth()
{
        auth_t *a;
        auth_t *tmp;

        a = config->auth;
        while (a != NULL) {
                free(a->alias);
                free(a->type);
                free(a->db);
                free(a->sql);
                free(a->bind);
                tmp = a;
                a = a->next;
                free(tmp);
        }
        config->auth = NULL;
}

/* free config memory */
void free_config()
{
        free(config->encoding);
        config->encoding = NULL;
        free(config->urldefault);
        config->urldefault = NULL;
        free(config->xmlpath);
        config->xmlpath = NULL;
        free(config->sslca);
        config->sslca = NULL;
        free(config->sslkey);
        config->sslkey = NULL;
        free(config->sslcert);
        config->sslcert = NULL;
        free(config->sslcrl);
        config->sslcrl = NULL;
        free(config->secretkey);
        config->sslciphers = NULL;
        free(config->sslciphers);
        config->secretkey = NULL;
        free(config->serverstring);
        config->serverstring = NULL;
        free_acls();
        free_auth();
        free_dbs();
        free_sql();
        free_urls(config->urls);
        free_users(config->users);
        free_groups(config->groups);
        free(docroot);

        config_new = NULL;
        prevacl = NULL;
        prevauth = NULL;
        prevdb = NULL;
        prevsql = NULL;
        prevurl = NULL;
        prevuser = NULL;
        prevgroup = NULL;
}

/* free database struct */
void free_db(db_t *d)
{
        if (d == NULL) return;
        free(d->alias);
        free(d->type);
        free(d->host);
        free(d->db);
        free(d->user);
        free(d->pass);
        free(d);
        d = NULL;
}

/* free database structs in config */
void free_dbs()
{
        db_t *d;
        db_t *tmp;

        d = config->dbs;
        while (d != NULL) {
                free(d->alias);
                free(d->type);
                free(d->host);
                free(d->db);
                free(d->user);
                free(d->pass);
                tmp = d;
                d = d->next;
                free(tmp);
        }
        config->dbs = NULL;
}

/* clean up config->groups memory */
void free_groups(group_t *g)
{
        group_t *tmp;

        while (g != NULL) {
                free(g->name);
                free_users(g->members);
                tmp = g;
                g = g->next;
                free(tmp);
        }
}

/* free keyvalue struct */
void free_keyval(keyval_t *h)
{
        keyval_t *tmp;

        while (h != NULL) {
                free(h->key);
                free(h->value);
                tmp = h;
                h = h->next;
                free(tmp);
        }
}

/* free sql structs */
void free_sql()
{
        sql_t *s;
        sql_t *tmp;

        s = config->sql;
        while (s != NULL) {
                free(s->alias);
                free(s->sql);
                tmp = s;
                s = s->next;
                free(tmp);
        }
        config->sql = NULL;
}

/* clean up config->urls memory */
void free_urls(url_t *u)
{
        url_t *tmp;

        while (u != NULL) {
                free(u->method);
                free(u->url);
                free(u->domain);
                free(u->path);
                free(u->db);
                free(u->view);
                tmp = u;
                u = u->next;
                free(tmp);
        }
        config->urls = NULL;
}

/* clean up config->users memory */
void free_users(user_t *u)
{
        user_t *tmp;

        while (u != NULL) {
                free(u->username);
                free(u->password);
                tmp = u;
                u = u->next;
                free(tmp);
        }
}

/* return the auth_t pointer for this alias */
auth_t *getauth(char *alias)
{
        auth_t *a;

        a = config->auth;
        while (a != NULL) {
                if (strcmp(alias, a->alias) == 0)
                        return a;
                a = a->next;
        }

        return NULL; /* not found */
}

/* return the db_t pointer for this db alias */
db_t *getdb(char *alias)
{
        db_t *db;

        db = config->dbs;
        while (db != NULL) {
                if (strcmp(alias, db->alias) == 0)
                        return db;
                db = db->next;
        }

        return NULL; /* db not found */
}

/* fetch sql from config by alias */
char *getsql(char *alias)
{
        sql_t *s;

        s = config->sql;
        while (s != NULL) {
                if (strcmp(alias, s->alias) == 0)
                        return s->sql;
                s = s->next;
        }

        return NULL;
}

/* fetch user from config by username */
user_t *getuser(char *username)
{
        user_t *u;

        u = config->users;
        while (u != NULL) {
                if (strcmp(username, u->username) == 0)
                        return u;
                u = u->next;
        }

        return NULL;
}

/* fetch group from config by group name */
group_t *getgroup(char *name)
{
        group_t *g;

        g = config->groups;
        while (g != NULL) {
                if (strcmp(name, g->name) == 0)
                        return g;
                g = g->next;
        }

        return NULL;
}

/* static url handler */
void handle_url_static(char *type, char params[LINE_MAX])
{
        url_t *newurl;
        char url[LINE_MAX];
        char method[LINE_MAX];
        char path[LINE_MAX];

        newurl = malloc(sizeof(struct url_t));

        if (sscanf(params, "%s %s %[^\n]", method, url, path) == 3) {
                newurl->type = type;
                newurl->method = strdup(method);
                /* if url starts with //, use first segment as domain */
                if (strncmp(url, "//", 2) == 0) {
                        int segs = 0;
                        char *s = strdup(url);
                        char **toks = tokenize(&segs, &s, "/");
                        newurl->domain = strdup(toks[2]);
                        free(s);
                        newurl->url = strdup(url + strlen(newurl->domain) + 2);
                }
                else {
                        newurl->url = strdup(url);
                        newurl->domain = strdup(domain);
                }
                if (strcmp(type, "rewrite") == 0) {
                        asprintf(&newurl->path, "%s", path);
                } else {
                        asprintf(&newurl->path, "%s/%s", docroot, path);
                }
                newurl->db = NULL;
                newurl->view = NULL;
                newurl->next = NULL;
                if (prevurl != NULL) {
                        /* update ->next ptr in previous url
                         * to point to new */
                        prevurl->next = newurl;
                }
                else {
                        /* no previous url, 
                         * so set first ptr in config */
                        config_new->urls = newurl;
                }
                prevurl = newurl;
        }
}

/* handle dynamic type urls */
void handle_url_dynamic(char *type, char params[LINE_MAX])
{
        url_t *newurl;
        char method[LINE_MAX];
        char url[LINE_MAX];
        char db[LINE_MAX];
        char view[LINE_MAX];

        newurl = malloc(sizeof(struct url_t));

        if (sscanf(params, "%s %s %s %s", method, url, db, view) == 4) {
                newurl->type = type;
                newurl->method = strdup(method);
                newurl->url = strdup(url);
                newurl->db = strdup(db);
                newurl->view = strdup(view);
                newurl->domain = strdup(domain);
                newurl->path = NULL;
                newurl->next = NULL;
                if (prevurl != NULL) {
                        /* update ->next ptr in previous url
                         * to point to new */
                        prevurl->next = newurl;
                }
                else {
                        /* no previous url, 
                         * so set first ptr in config */
                        config_new->urls = newurl;
                }
                prevurl = newurl;
        }
}

/* open config file for reading */
FILE *open_config(char *configfile)
{
        FILE *fd;

        fd = fopen(configfile, "r");
        if (fd == NULL) {
                int errsv = errno;
                syslog(LOG_ERR, "ERROR: %s", strerror(errsv));
        }
        return fd;
}

/* check config line and handle appropriately */
int process_config_line(char *line)
{
        long i = -1;
        char key[LINE_MAX] = "";
        char *value = malloc(strlen(line) + 1);
        static char *multi = NULL;
        char *tmp = NULL;

        if (line[0] == '#')
                i = 1; /* skipping comment */

        if (multi != NULL) {
                /* we're processing a multi-line config here */
                if (strncmp(line, "end", 3) == 0) {
                        tmp = strdup(multi);
                        free(multi);
                        multi = NULL;
                        i = process_config_line(tmp);
                        free(tmp);
                }
                else {
                        /* another bit; tack it on */
                        tmp = strdup(multi);
                        free(multi);
                        asprintf(&multi, "%s%s", tmp, line);
                        free(tmp);
                        *(multi + strlen(multi) - 1) = '\0';
                        i = 0;
                }
        }
        else if (sscanf(line, "%[a-zA-Z0-9]", value) == 0) {
                /* skipping blank line */
                i = 1;
        }
        else if (sscanf(line, "%s %li", key, &i) == 2) {
                /* process long integer config values */
                if (strcmp(key, "debug") == 0) {
                        i = set_config_long(&config_new->debug,
                                                "debug", i, 0, 1);
                }
                else if (strcmp(key, "port") == 0) {
                        i = set_config_long(&config_new->port,
                                                "port", i, 1, 65535);
                }
                else if (strcmp(key, "dropprivs") == 0) {
                        i = set_config_long(&config_new->dropprivs,
                                                "dropprivs", i, 0, 1);
                }
                else if (strcmp(key, "daemon") == 0) {
                        i = set_config_long(&config_new->daemon,
                                                "daemon", i, 0, 1);
                }
                else if (strcmp(key, "pipelining") == 0) {
                        i = set_config_long(&config_new->pipelining,
                                                "pipelining", i, 0, 1);
                }
                else if (strcmp(key, "keepalive") == 0) {
                        i = set_config_long(&config_new->keepalive,
                                                "keepalive", i, 0, LONG_MAX);
                }
                else if (strcmp(key, "session_timeout") == 0) {
                        i = set_config_long(&config_new->sessiontimeout,
                                        "sessiontimeout", i, 0, LONG_MAX);
                }
                else if (strcmp(key, "ssl") == 0) {
                        i = set_config_long(&config_new->ssl,
                                                "ssl", i, 0, 5);
                }
                else if (strcmp(key, "uploadmax") == 0) {
                        i = set_config_long(&config_new->uploadmax,
                                                "uploadmax", i, 0, LONG_MAX);
                }
                else if (strcmp(key, "x-forward") == 0) {
                        i = set_config_long(&config_new->xforward,
                                                "x-forward", i, 0, 1);
                }
        }
        else if (sscanf(line, "%s %[^\n]", key, value) == 2) {
                if (strcmp(key, "domain") == 0) {
                        i = set_domain(value);
                }
		else if (strcmp(key, "document_root") == 0) {
                        i = set_docroot(value);
                }
                else if (strcmp(key, "encoding") == 0) {
                        i = set_encoding(value);
                }
                else if (strcmp(key, "include") == 0) {
                        /* read and process another config file here */
                        i = process_config_file(value);
                }
                else if (strcmp(key, "url_default") == 0) {
                        i = asprintf(&config->urldefault, "%s", value);
                }
                else if (strcmp(key, "url") == 0) {
                        i = add_url_handler(value);
                }
                else if (strcmp(key, "user") == 0) {
                        i = add_user(value);
                }
                else if (strcmp(key, "group") == 0) {
                        i = add_group(value);
                }
                else if (strcmp(key, "acl") == 0) {
                        i = add_acl(value);
                }
                else if (strcmp(key, "auth") == 0) {
                        i = add_auth(value);
                }
                else if (strncmp(key, "begin", 5) == 0) {
                        /* multi-line config - cat the bits together and
                         * call this function again */
                        asprintf(&multi, "%s ", value);
                        i = 0;
                }
                else if (strcmp(key, "db") == 0) {
                        i = add_db(value);
                }
                else if (strcmp(key, "serverstring") == 0) {
                        free(config->serverstring);
                        i = asprintf(&config->serverstring, "%s", value);
                }
                else if (strcmp(key, "sql") == 0) {
                        i = add_sql(value);
                }
                else if (strcmp(key, "ssl-ca") == 0) {
                        i = set_ssl(key, value);
                }
                else if (strcmp(key, "ssl-key") == 0) {
                        i = set_ssl(key, value);
                }
                else if (strcmp(key, "ssl-cert") == 0) {
                        i = set_ssl(key, value);
                }
                else if (strcmp(key, "ssl-crl") == 0) {
                        i = set_ssl(key, value);
                }
                else if (strcmp(key, "ssl-ciphers") == 0) {
                        free(config->sslciphers);
                        i = asprintf(&config->sslciphers, "%s", value);
                }
                else if (strcmp(key, "secretkey") == 0) {
                        i = asprintf(&config->secretkey, "%s", value);
                }
                else if (strcmp(key, "xmlpath") == 0) {
                        i = set_xmlpath(value);
                }
                else {
                        fprintf(stderr, "unknown config directive '%s'\n", key);
                }
        }
        free(value);
        return i;
}

/* read config file into memory */
int process_config_file(char *configfile)
{
        FILE *fd;
        char line[LINE_MAX];
        int lc = 0;
        int ret = 1;

        syslog(LOG_DEBUG, "processing config: %s", configfile);

        /* open file for reading */
        fd = open_config(configfile);
        if (fd == NULL)
                return 0;

        /* read in config */
        while (fgets(line, LINE_MAX, fd) != NULL) {
                lc++;
                if (process_config_line(line) < 0) {
                        printf("Error in line %i of %s.\n", lc, configfile);
                        ret = -1;
                }
        }

        /* close file */
        fclose(fd);
        return ret;
}

int read_config(char *configfile)
{
        FILE *fd;
        int i;
        int retval = 0;

        /* reset list pointers */
        prevacl = NULL;
        prevauth = NULL;
        prevdb = NULL;
        prevsql = NULL;
        prevurl = NULL;
        prevuser = NULL;
        prevgroup = NULL;

        set_config_defaults();
        config_new = &config_default;

        prevurl = NULL;

	asprintf(&domain, "*");
	asprintf(&docroot, "/");

        if (process_config_file(configfile) < 0)
                return 1;

        /* generate random secretkey if none set */
        if (!config_new->secretkey) {
                syslog(LOG_DEBUG, "Generating random secret key...");
                config_new->secretkey = calloc(129, sizeof (char));
                fd = fopen("/dev/urandom", "r");
                for (i=0; i<127; i++) {
                        fread(&config_new->secretkey[i],sizeof (char),1,fd);
                }
                fclose(fd);
                syslog(LOG_DEBUG, "Key generation complete.");
        }
        /* Initialize Blowfish */
        BF_set_key(&config_new->ctx, strlen(config_new->secretkey),
                (const unsigned char*)config_new->secretkey);

        /* if config parsed okay, make active */
        if (retval == 0)
                config = config_new;

        /* set syslog mask */
        setlogmask(LOG_UPTO((config->debug) ? LOG_DEBUG : LOG_INFO));

        return retval;
}

/* set config defaults if they haven't been set already */
/* FIXME: defaults not malloc()'d, so free_config() has errors */
int set_config_defaults()
{
        config = &config_default;

        asprintf(&config->serverstring, "%s v%s", PROGRAM, VERSION);
        asprintf(&config->sslciphers, "%s", SSLCIPHERS_DEFAULT);

        config->acls = NULL;
        config->auth = NULL;
        config->dbs = NULL;
        config->sql = NULL;
        config->urls = NULL;
        config->users = NULL;
        config->groups = NULL;

        return 0;
}

/* set config value if long integer is between min and max */
int set_config_long(long *confset, char *keyname, long i, long min, long max)
{
        if ((i >= min) && (i <= max)) {
                *confset = i;
        }
        else {
                fprintf(stderr,"ERROR: invalid %s value\n", keyname);
                return -1;
        }
        return 0;
}

int set_domain(char *value)
{
        free(domain);
        domain = strdup(value);
        return (domain == NULL) ? 0 : 1;
}

int set_docroot(char *value)
{
        free(docroot);
        docroot = strdup(value);
        return (docroot == NULL) ? 0 : 1;
}

int set_encoding(char *value)
{
        if (strcmp(value, "UTF-8") == 0 || (strcmp(value, "ISO-8859-1") == 0)){
                asprintf(&config->encoding, "%s", value);
                return 0;
        }
        else {
                fprintf(stderr, "Ignoring invalid encoding '%s'\n", value);
                return -1;
        }
}

int set_ssl(char *key, char *value)
{
        /* TODO: check validity of these files */
        if (strcmp(key, "ssl-ca") == 0) {
                return asprintf(&config->sslca, "%s", value);
        }
        if (strcmp(key, "ssl-key") == 0) {
                return asprintf(&config->sslkey, "%s", value);
        }
        if (strcmp(key, "ssl-cert") == 0) {
                return asprintf(&config->sslcert, "%s", value);
        }
        if (strcmp(key, "ssl-crl") == 0) {
                return asprintf(&config->sslcrl, "%s", value);
        }
        return -1;
}

/* set path to xml, xsl and xsd files */
int set_xmlpath(char *value)
{
        /* TODO: check is dir */
        return asprintf(&config->xmlpath, "%s", value);
}
