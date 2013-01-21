/* 
 * config.c
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* set config defaults */
config_t config_default = {
        .debug          = 0,
        .port           = 8080,
        .daemon         = 0,
        .encoding       = "UTF-8"
};

config_t *config;
config_t *config_new;

acl_t *prevacl;         /* pointer to last acl */
db_t  *prevdb;          /* pointer to last db  */
sql_t *prevsql;         /* pointer to last sql */
url_t *prevurl;         /* pointer to last url */

/* set config defaults if they haven't been set already */
int set_config_defaults()
{
        static int defaults_set = 0;

        if (defaults_set != 0)
                return 1;

        config = &config_default;
        config->authrealm = "gladd";

        defaults_set = 1;
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
                tmp = a;
                a = a->next;
                free(tmp);
        }
}

/* free config memory */
void free_config()
{
        free(config->encoding);
        free_acls();
        free_dbs();
        free_sql();
        free_urls();
}

/* free database struct */
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
}

/* clean up config->urls memory */
void free_urls()
{
        url_t *u;
        url_t *tmp;

        u = config->urls;
        while (u != NULL) {
                free(u->url);
                free(u->path);
                free(u->db);
                free(u->view);
                tmp = u;
                u = u->next;
                free(tmp);
        }
}

/* static url handler */
void handle_url_static(char params[LINE_MAX])
{
        url_t *newurl;
        char url[LINE_MAX];
        char path[LINE_MAX];

        newurl = malloc(sizeof(struct url_t));

        if (sscanf(params, "%s %s", url, path) == 2) {
                newurl->type = "static";
                newurl->url = strdup(url);
                newurl->path = strdup(path);
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

/* handle sqlview type urls */
void handle_url_sqlview(char params[LINE_MAX])
{
        url_t *newurl;
        char url[LINE_MAX];
        char db[LINE_MAX];
        char view[LINE_MAX];

        newurl = malloc(sizeof(struct url_t));

        if (sscanf(params, "%s %s %s", url, db, view) == 3) {
                newurl->type = "sqlview";
                newurl->url = strdup(url);
                newurl->db = strdup(db);
                newurl->view = strdup(view);
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

/* add url handler */
int add_url_handler(char *value)
{
        char type[8];
        char params[LINE_MAX];

        if (sscanf(value, "%s %[^\n]", type, params) == 2) {
                if (strncmp(type, "static", 6) == 0) {
                        handle_url_static(params);
                }
                else if (strcmp(type, "sqlview") == 0) {
                        handle_url_sqlview(params);
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

/* add acl */
int add_acl (char *value)
{
        acl_t *newacl;
        char method[LINE_MAX] = "";
        char url[LINE_MAX] = "";
        char type[LINE_MAX] = "";
        char auth[LINE_MAX] = "";
        char authtype[LINE_MAX] = "";

        if ((sscanf(value, "%s %s %s %s", 
                method, url, type, auth) != 4) &&
        (sscanf(value, "%s %s %s %s %s", 
                method, url, type, auth, authtype) != 5))
        {
                /* config line didn't match expected patterns */
                return -1;
        }

        newacl = malloc(sizeof(struct acl_t));
        if ((strncmp(type, "allow", 5) == 0) ||
            (strncmp(type, "deny", 5) == 0))
        {
                newacl->method = strndup(method, LINE_MAX);
                newacl->url = strndup(url, LINE_MAX);
                newacl->type = strndup(type, LINE_MAX);
                newacl->auth = strndup(auth, LINE_MAX);
                newacl->params = NULL;
                newacl->next = NULL;
        }
        else if (strncmp(type, "require", 5) == 0) {
                newacl->method = strndup(method, LINE_MAX);
                newacl->url = strndup(url, LINE_MAX);
                newacl->type = strndup(type, LINE_MAX);
                newacl->auth = strndup(auth, LINE_MAX);
                newacl->params = strndup(authtype, LINE_MAX);
                newacl->next = NULL;
        }
        else {
                fprintf(stderr, "Invalid acl type\n");
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

        /* mysql config line have 6 args, postgres has 4 */
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

/* store sql in config */
int add_sql(char *value)
{
        sql_t *newsql;
        char alias[LINE_MAX] = "";
        char sql[LINE_MAX] = "";

        if (sscanf(value, "%s %[^\n]", alias, sql) != 2) {
                return -1;
        }

        newsql = malloc(sizeof(struct sql_t));

        newsql->alias = strndup(alias, LINE_MAX);
        newsql->sql = strndup(sql, LINE_MAX);
        newsql->next = NULL;

        if (prevsql != NULL)
                prevsql->next = newsql;
        else
                config_new->sql = newsql;
        prevsql = newsql;

        return 0;
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

/* check config line and handle appropriately */
int process_config_line(char *line)
{
        long i = 0;
        char key[LINE_MAX] = "";
        char value[LINE_MAX] = "";

        if (line[0] == '#')
                return 1; /* skipping comment */
        
        if (sscanf(line, "%[a-zA-Z0-9]", value) == 0) {
                return 1; /* skipping blank line */
        }
        else if (sscanf(line, "%s %li", key, &i) == 2) {
                /* process long integer config values */
                if (strcmp(key, "debug") == 0) {
                        return set_config_long(&config_new->debug,
                                                "debug", i, 0, 1);
                }
                else if (strcmp(key, "port") == 0) {
                        return set_config_long(&config_new->port, 
                                                "port", i, 1, 65535);
                }
                else if (strcmp(key, "daemon") == 0) {
                        return set_config_long(&config_new->daemon, 
                                                "port", i, 0, 1);
                }
        }
        else if (sscanf(line, "%s %[^\n]", key, value) == 2) {
                if (strcmp(key, "encoding") == 0) {
                        return set_encoding(value);
                }
                if (strcmp(key, "url") == 0) {
                        return add_url_handler(value);
                }
                else if (strcmp(key, "acl") == 0) {
                        return add_acl(value);
                }
                else if (strcmp(key, "db") == 0) {
                        return add_db(value);
                }
                else if (strcmp(key, "sql") == 0) {
                        return add_sql(value);
                }
                else {
                        fprintf(stderr, "unknown config directive '%s'\n", 
                                                                        key);
                }
        }

        return -1; /* syntax error */
}

/* open config file for reading */
FILE *open_config(char *configfile)
{
        FILE *fd;

        fd = fopen(configfile, "r");
        if (fd == NULL) {
                int errsv = errno;
                fprintf(stderr, "ERROR: %s\n", strerror(errsv));
        }
        return fd;
}

/* read config file into memory */
int read_config(char *configfile)
{
        FILE *fd;
        char line[LINE_MAX];
        int lc = 0;
        int retval = 0;

        set_config_defaults();
        config_new = &config_default;

        prevurl = NULL;

        /* open file for reading */
        fd = open_config(configfile);
        if (fd == NULL)
                return 1;

        /* read in config */
        while (fgets(line, LINE_MAX, fd) != NULL) {
                lc++;
                if (process_config_line(line) < 0) {
                        printf("Error in line %i of %s.\n", lc, configfile);
                        retval = 1;
                }
        }

        /* close file */
        fclose(fd);

        /* if config parsed okay, make active */
        if (retval == 0)
                config = config_new;

        return retval;
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
