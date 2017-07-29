/*
 * handler.c - some code to handle incoming connections
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2017 Brett Sheffield <brett@gladserv.com>
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

#ifndef _NAUTH
#include "auth.h"
#endif /* _NAUTH */

#include "config.h"
#ifndef _NGLADDB
#include "gladdb/db.h"
#endif
#include "tls.h"
#include "handler.h"
#include "main.h"
#include "mime.h"
#include "string.h"
#include "utils.h"
#include "xml.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <libxml/parser.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#ifdef _GIT
#include <git2.h>
#endif /* _GIT */

#ifndef _NGLADDB
#ifndef _NLDIF
#include <ldap.h>
#include <ldif.h>
#include "gladdb/ldif.h"
#endif /* _NLDIF */
#endif /* _NGLADDB */

http_status_code_t response_xslpost(int sock, url_t *u);
field_t *get_element(int *err);

/*
 * get sockaddr, IPv4 or IPv6:
 */
void *get_in_addr(struct sockaddr *sa)
{
        if (sa->sa_family == AF_INET) {
                return &(((struct sockaddr_in*)sa)->sin_addr);
        }

        return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* block on socket until data arrives or timeout exceeded
 * return 1 if data available, 0 if not */
int waitfordata(int sock, int bytes, char s[INET6_ADDRSTRLEN])
{
        int peek = 0;
        char peekbuf[1] = "";
        struct timeval tv;
        if (bytes > 0) return 1; /* we already have data */
        tv.tv_sec = config->keepalive; tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                (char *)&tv, sizeof(struct timeval)) == -1)
        {
                syslog(LOG_ERR, "setsockopt error: %s", strerror(errno));
        }
        peek = rcv(sock, peekbuf, 1, MSG_PEEK | MSG_WAITALL);
        if (peek == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        syslog(LOG_DEBUG,
                                "[%s] connection timeout", s);
                }
                else {
                        syslog(LOG_DEBUG,"%s",strerror(errno));
                }
                return 0;
        }
        else if (peek == 0) {
                syslog(LOG_DEBUG,
                        "[%s] client closed connection", s);
                return 0;
        }
        return 1;
}

/*
 * child process where we handle incoming connections
 */
void handle_connection(int sock, struct sockaddr_storage their_addr)
{
        char s[INET6_ADDRSTRLEN] = "";
        handler_result_t err = HANDLER_OK;
        int i = 0;

        inet_ntop(their_addr.ss_family,
                        get_in_addr((struct sockaddr *)&their_addr),
                        s, sizeof s);
        syslog(LOG_DEBUG, "[%s] connection received", s);

        if (config->ssl) do_tls_handshake(sock);

        /* loop to allow persistent connections & pipelining */
        do {
                /* wait for data if we have none */
                if (!waitfordata(sock, bytes, s)) break;
                syslog(LOG_DEBUG, "handling request %i on connection", ++i);
                err = handle_request(sock, s);
                free_request(&request);
                http_flush_buffer();
        }
        while ((err == HANDLER_OK) && (config->pipelining == 1));
        syslog(LOG_DEBUG, "[%s] closing connection", s);

        /* close client connection */
        if (config->ssl)
                ssl_cleanup(sock);
        else
                close(sock);

        /* free memory */
        free_config();

        /* child process can exit */
        _exit(EXIT_SUCCESS);
}

handler_result_t handle_request(int sock, char *s)
{
        char *mtype = NULL;
        http_status_code_t err = 0;
#ifndef _NAUTH
        int auth = -1;
#endif
        int hcount = 0;
        url_t *u = NULL;
        long len = 0;


        /* read http client request */
        request = http_read_request(sock, &hcount, &err);
        if (err != 0) {
                http_response(sock, err);
                return HANDLER_OK;
        }

        if (request == NULL) /* connection was closed */
                return HANDLER_CLOSE_CONNECTION;

        /* keep a note of client ip */
        asprintf(&request->clientip, "%s", s);

        http_validate_headers(request, &err);
        if (err != 0) {
                syslog(LOG_INFO, "Bad Request - invalid request headers");
                http_response(sock, err);
                return HANDLER_OK;
        }

        /* X-Forwarded-For */
        if (config->xforward == 1) {
                char *xforwardip;
                xforwardip = http_get_header(request, "X-Forwarded-For");
                if (xforwardip) {
                        syslog(LOG_DEBUG, "X-Forwarded-For: %s", xforwardip);
                        request->xforwardip = strdup(xforwardip);
                }
        }

        /* has client requested compression? */
        if (http_accept_encoding(request, "gzip")) {
                syslog(LOG_DEBUG, "Client has requested gzip encoding");
        }

        syslog(LOG_DEBUG, "Client header count: %i", hcount);
        syslog(LOG_DEBUG, "Method: %s", request->method);
        syslog(LOG_DEBUG, "Resource: %s", request->res);
        syslog(LOG_DEBUG, "HTTP Version: %s", request->httpv);

        /* Return HTTP response */

        /* put a cork in it */
        setcork(sock, 1);

        /* if / requested, substitute default */
        if (strcmp(request->res, "/") == 0) {
                free(request->res);
                request->res = strdup(config->urldefault);
        }

        /* match url */
        u = http_match_url(request);
        if (u == NULL) {
                /* Not found */
                syslog(LOG_DEBUG, "failed to find matching url in config");
                http_response(sock, HTTP_NOT_FOUND);
                return HANDLER_OK;
        }

        /* check auth & auth */
#ifndef _NAUTH
        auth = check_auth(request);
        if (auth != 0) {
                http_response(sock, auth);
                return HANDLER_OK;
        }
#endif /* _NAUTH */

        if (strcmp(request->method, "POST") == 0) {
                /* POST requires Content-Length header */
                http_status_code_t err;

                len = check_content_length(request, &err);
                if (err != 0) {
                        syslog(LOG_DEBUG, "Incorrect content length");
                        http_response(sock, err);
                        return HANDLER_CLOSE_CONNECTION;
                }
                else {
                        syslog(LOG_DEBUG, "Content-Length: %li", len);
                }
                mtype = check_content_type(request, &err, u->type);
                if (err != 0) {
                        syslog(LOG_ERR,
                                "Unsupported Media Type '%s'", mtype);
                        http_response(sock, err);
                        return HANDLER_CLOSE_CONNECTION;
                }
        }
        syslog(LOG_DEBUG, "Type: %s", u->type);
        if (strncmp(u->type, "static", 6) == 0) {
                /* serve static files */
                err = response_static(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
#ifdef _GIT
	else if (strcmp(u->type, "git") == 0) {
                err = response_git(sock, u);
                if (err != 0)
                        http_response(sock, err);
	}
#endif /* _GIT */
#ifndef _NGLADDB
        else if (strcmp(u->type, "keyval") == 0) {
		err = response_keyval(sock, u);
                if (err != 0)
                        http_response(sock, err);
	}
#ifndef _NLDIF
        else if (strcmp(u->type, "ldif") == 0) {
                err = response_ldif(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
#endif /* _NLDIF */
        else if (strcmp(u->type, "sqlview") == 0) {
                /* handle sqlview */
                err = response_sqlview(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
        else if (strcmp(u->type, "sqlexec") == 0) {
                err = response_sqlexec(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
        else if (strcmp(u->type, "xslpost") == 0) {
                err = response_xslpost(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
        else if (strcmp(u->type, "xslt") == 0) {
                err = response_xslt(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
#endif /* _NGLADDB */
        else if (strcmp(u->type, "upload") == 0) {
                err = response_upload(sock, u);
                if (err != 0)
                        http_response(sock, err);
		/* close connection after an upload, otherwise Chrome 
		 * has a habit of sending the same file again even if a 
		 * different one is selected */
		return HANDLER_CLOSE_CONNECTION;
        }
        else if (strcmp(u->type, "plugin") == 0) {
                if (strcmp(u->method, "POST") == 0) {
                        err = response_xml_plugin(sock, u);
                }
                else {
                        err = response_plugin(sock, u);
                }
                if (err != 0)
                        http_response(sock, err);
        }
        else if ((strcmp(u->type, "proxy") == 0)
        || (strcmp(u->type, "rewrite") == 0))
        {
                err = http_response_proxy(sock, u);
                if (err != 0)
                        http_response(sock, err);
        }
        else {
                syslog(LOG_ERR, "Unknown url type '%s'", u->type);
                http_response(sock, HTTP_INTERNAL_SERVER_ERROR);
                return HANDLER_CLOSE_CONNECTION;
        }

        if (strcmp(request->httpv, "1.0") == 0)
                return HANDLER_CLOSE_CONNECTION;
        else
                return HANDLER_OK;
}

void respond (int fd, char *response)
{
        snd(fd, response, strlen(response), 0);
}

#ifndef _NGLADDB
static int handler_fetch_keyval(db_t *db, url_t *u, keyval_t **k)
{
	keyval_t *kv = *k;

	/* do variable substitution */
	kv = calloc(1, sizeof(keyval_t));
	kv->key = strdup(u->view);
	replacevars(&kv->key, request->res);

	/* fetch data */
	if (db_fetch_keyval(db, kv) != EXIT_SUCCESS) {
		syslog(LOG_ERR, "Error in db_fetch_key()");
		free(kv->key);
		free(kv);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (kv->value == NULL) {
		return HTTP_NOT_FOUND;
	}
	*k = kv;

	return 0;
}

http_status_code_t response_keyval(int sock, url_t *u)
{
	char *headers = NULL;
	char *page = NULL;
	char *r = NULL;
	int err = 0;
	db_t *db = NULL;
	keyval_t *kv = NULL;
	keyval_t *kvt = NULL;
	int isconn = 0;
	url_t *template = NULL;

	if (!(db = getdbv(u->db))) {
		syslog(LOG_ERR, "db '%s' not in config", u->db);
		free_db(db);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* connect if we aren't already */
	if (db->conn == NULL) {
		if (db_connect(db) != 0) {
			syslog(LOG_ERR, "Failed to connect to db on %s", db->host);
			return -1;
		}
		isconn = 1;
	}

	/* fetch keyval */
	if ((err = handler_fetch_keyval(db, u, &kv)) != 0) {
		goto close_conn;
	}

	/* fetch template */
	template = http_match_template(request);
	if (template) {
		syslog(LOG_DEBUG, "fetching template '%s'", template->view);
		/* TODO: check database is the same as for url */
		if ((err = handler_fetch_keyval(db, template, &kvt)) != 0) {
			goto close_conn;
		}
		xmltransform_mem(kvt->value, kv->value, &page);
		if (page == NULL)
			return HTTP_INTERNAL_SERVER_ERROR;
	}
	else {
		page = strdup(kv->value);
	}
	free_db(db);

	if (asprintf(&r, RESPONSE_200, config->serverstring, headers, page) == -1)
	{
		free(kv->key);
		free(kv->value);
		free(kv);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	free(page);
	free(headers);
	set_headers(&r); /* set any additional headers */
	respond(sock, r);
	free(kv->key);
	free(kv->value);
	free(kv);

close_conn:
	/* leave the connection how we found it */
	if (isconn == 1)
		db_disconnect(db);
	return err;
}

#ifndef _NLDIF
http_status_code_t response_ldif(int sock, url_t *u)
{
        db_t *db = NULL;
        struct berval cred;
        struct berval *servcred;
        int rc;

        syslog(LOG_DEBUG, "response_ldif()");
        if (strcmp(u->method, "POST") != 0) {
                syslog(LOG_ERR, "ldif method not POST");
                return HTTP_METHOD_NOT_ALLOWED;
        }
        if (!(db = getdbv(u->db))) {
                syslog(LOG_ERR, "db '%s' not in config", u->db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        db_connect(db);

        /* bind if we have any credentials */
        if (db->user || request->authuser) {
                char *user = (request->authuser) ? request->authuser:db->user;
                char *pass = (request->authpass) ? request->authpass:db->pass;
                cred.bv_val = pass;
                cred.bv_len = strlen(pass);
                rc = ldap_sasl_bind_s(db->conn, user, LDAP_SASL_SIMPLE,
                        &cred, NULL, NULL, &servcred);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_ERR, "bind failed: %s", ldap_err2string(rc));
                        db_disconnect(db);
                        free_db(db);
                        return HTTP_UNAUTHORIZED;
                }
        }

        LDIFFP *fp = ldif_open_mem(request->data->value, bytes, "r");
        rc = process_ldif(db, fp);
        ldif_close(fp);
        db_disconnect(db);
        free_db(db);
        http_response(sock, (rc == 1) ? HTTP_OK : HTTP_BAD_REQUEST);
        return 0;
}
#endif

/* handle sqlview */
http_status_code_t response_sqlview(int sock, url_t *u)
{
        char *headers = NULL;
        char *r = NULL;
        char *sql = NULL;
        field_t *filter = NULL;
        char *xml = NULL;
        int err = 0;
        db_t *db = NULL;

        if (!(db = getdbv(u->db))) {
                syslog(LOG_ERR, "db '%s' not in config", u->db);
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* fetch element id as filter, if applicable */
        if (!request->nofilter) {
                filter = get_element(&err);
                if (err != 0) {
                        free_db(db);
                        return err;
                }
        }

        if (strcmp(request->method, "POST") == 0) {
                if (filter == NULL) {
                        /* POST to collection => create */
                        if (db_insert(db, u->view, request->data) != 0) {
                                free_db(db);
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
                }
                else {
                        /* TODO: POST to element => update */
                        syslog(LOG_ERR, "POST to element not implemented");
                        free_db(db);
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        if (asprintf(&sql, "%s", getsql(u->view)) == -1)
        {
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (sqltoxml(db, sql, filter, &xml, 1) != 0) {
                free(sql);
                free_db(db);
                free(xml);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(sql);
        free_db(db);
        asprintf(&headers,"%s\nContent-Length: %i",MIME_XML,(int)strlen(xml));
        if (asprintf(&r, RESPONSE_200, config->serverstring, headers, xml) == -1)
        {
                free(xml);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(headers);
        set_headers(&r); /* set any additional headers */
        respond(sock, r);
        free(r);
        free(xml);

        return 0;
}

/* handle sqlexec */
http_status_code_t response_sqlexec(int sock, url_t *u)
{
        char *sql = NULL;
        db_t *db = NULL;

        if (!(db = getdbv(u->db))) {
                syslog(LOG_ERR, "db '%s' not in config", u->db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (asprintf(&sql, "%s", getsql(u->view)) == -1)
        {
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        replacevars(&sql, request->res);
        syslog(LOG_DEBUG, "SQL: %s", sql);
        if (db_exec_sql(db, sql) != 0) {
                free(sql);
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(sql);
        free_db(db);
        http_response(sock, HTTP_OK);

        return 0;
}

/* handle xslpost */
http_status_code_t response_xslpost(int sock, url_t *u)
{
        db_t *db = NULL;
        char *headers = NULL;
        char *xml = NULL;
        char *xsd = NULL;
        char *xsl = NULL;
        char *sql = NULL;
        char *r = NULL;
        char *action = NULL;
        char *mime = MIME_XML;
        int err = 0;
        field_t *filter = NULL;

        syslog(LOG_DEBUG, "response_xslpost()");

        if (strcmp(u->method, "POST") != 0) {
                syslog(LOG_ERR, "xslpost method not POST");
                return HTTP_METHOD_NOT_ALLOWED;
        }

        if (!(db = getdbv(u->db))) {
                syslog(LOG_ERR, "db '%s' not in config", u->db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* fetch element id as filter, if applicable */
        filter = get_element(&err);
        if (err != 0) {
                free_db(db);
                return err;
        }

        if (filter == NULL) {
                /* POST to collection => create */
                asprintf(&action, "create");
        }
        else {
                /* POST to element => update */
                asprintf(&action, "update");
        }

        /* validate request body xml */
        assert(asprintf(&xsd, "%s/%s/%s.xsd", config->xmlpath, u->view, action)
                != -1);
        if (xml_validate(xsd, request->data->value) != 0) {
                free(xsd);
                syslog(LOG_DEBUG, "%s", request->data->value);
                syslog(LOG_ERR, "Request XML failed validation");
                return HTTP_BAD_REQUEST;
        }
        free(xsd);

        /* transform xml into sql */
        assert(asprintf(&xsl, "%s/%s/%s.xsl", config->xmlpath, u->view, action)
                != -1);

        syslog(LOG_DEBUG, "Performing XSLT Transformation");

        if (xmltransform(xsl, request->data->value, &sql, filter) != 0) {
                free(xsl);
                free_db(db);
                syslog(LOG_ERR, "XSLT transform failed");
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(xsl);

        /* connect to database, if not already */
        if (!db->conn) db_connect(db);

        syslog(LOG_DEBUG, "Executing SQL");

        /* execute sql */
        if (sqltoxml(db, sql, NULL, &xml, 1) < 0) {
                free(sql);
                free(xml);
                syslog(LOG_ERR, "xsltpost sql execution failed. ROLLBACK");
                /* rollback transaction and/or disconnect */
                http_response_xml(sock, HTTP_INTERNAL_SERVER_ERROR, dberrcode,
                                  dberror);
                db_exec_sql(db, "ROLLBACK;");
                if (config->pipelining == 0) db_disconnect(db);
        }
        free(sql);

        /* check if we have created.xsl / updated.xsl */
        assert(asprintf(&xsl, "%s/%s/%sd.xsl", config->xmlpath, u->view,
                action) != -1);
        if (access(xsl, R_OK) == 0) {
                /* use {created,updated}.xsl for result */
                syslog(LOG_DEBUG, "overriding results using %sd.xsl", action);
                free(xml);
                if (xmltransform(xsl, request->data->value, &sql, filter)!= 0){
                        free(xsl);
                        syslog(LOG_ERR, "XSLT transform failed");
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
                if (sqltoxml(db, sql, filter, &xml, 1) != 0) {
                        free(xsl);
                        free(sql);
                        free_db(db);
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
                free(sql);
        }
        free(xsl);

        if (request->htmlout) {
                /* html output was requested */
                syslog(LOG_DEBUG, "html output conversion requested");
                assert(asprintf(&xsl, "%s/%s/%s.html.xsl", config->xmlpath,
                        u->view, action) != -1);
                free(action);
                if (access(xsl, R_OK) == 0) {
                        /* convert xml result to html */
                        syslog(LOG_DEBUG, "converting results to html");
                        char *resultxml = strdup(xml);
                        free(xml);
                        if (xmltransform(xsl, resultxml, &xml, NULL) != 0) {
                                syslog(LOG_ERR, "XSLT transform failed");
                                free(xsl);
                                free(resultxml);
                                free_db(db);
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
                        mime = MIME_HTML;
                }
                else {
                        syslog(LOG_ERR, "'%s' not found", xsl);
                }
                free(xsl);
        }

        asprintf(&headers, "%s\nContent-Length: %i", mime,
                (int)strlen(xml));
        if (asprintf(&r, RESPONSE_200, config->serverstring, headers, xml) == -1)
        {
                free(xml);
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(headers);
        free(xml);
        set_headers(&r); /* set any additional headers */
        respond(sock, r);
        free(r);
        if (config->pipelining != 0) db_disconnect(db);
        free_db(db);

        syslog(LOG_DEBUG, "xsltpost complete");

        return 0;
}

http_status_code_t response_xslt(int sock, url_t *u)
{
        char *headers = NULL;
        char *r = NULL;
        char *sql = NULL;
        char *xml = NULL;
        char *xsl = NULL;
        char *html = NULL;
        int err = 0;
        db_t *db = NULL;
        field_t *filter = NULL;

        syslog(LOG_DEBUG, "response_xslt()");

        /* ensure method is GET */
        if (strcmp(u->method, "GET") != 0) {
                syslog(LOG_ERR, "xslt method not GET");
                return HTTP_METHOD_NOT_ALLOWED;
        }

        /* ensure we have a valid database */
        if (!(db = getdbv(u->db))) {
                syslog(LOG_ERR, "db '%s' not in config", u->db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* ensure we have some sql to work with */
        if (!(sql = getsql(u->view))) {
                syslog(LOG_ERR, "sql '%s' not in config", u->view);
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* fetch element id as filter, if applicable */
        if (!request->nofilter) {
                filter = get_element(&err);
                if (err != 0) {
                        free_db(db);
                        return err;
                }
        }

        /* fetch data as xml */
        if (sqltoxml(db, sql, filter, &xml, 1) != 0) {
                free(sql);
                free(xml);
                free_db(db);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* ensure XSLT file exists */
        assert(asprintf(&xsl, "%s/%s/view.xsl", config->xmlpath, u->view)
                != -1);

        /* transform xml data into html */
        syslog(LOG_DEBUG, "Performing XSLT Transformation");
        if (xmltransform(xsl, xml, &html, NULL) != 0) {
                free(xsl); free(xml);
                free_db(db);
                syslog(LOG_ERR, "XSLT transform failed");
                return HTTP_BAD_REQUEST;
        }
        free(xsl); free(xml);
        free_db(db);

        /* build response */
        asprintf(&headers,"%s\nContent-Length: %i",MIME_HTML,(int)strlen(html));
        if (asprintf(&r, RESPONSE_200, config->serverstring, headers, html) == -1)
        {
                free(html);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(headers);

        /* return html response */
        set_headers(&r); /* set any additional headers */
        respond(sock, r);
        free(r);
        free(html);

        return 0;
}
#endif /* _NGLADDB */

/* receive uploaded files */
http_status_code_t response_upload(int sock, url_t *u)
{
        EVP_MD_CTX *mdctx;
        char *b = request->boundary;
        char *clen = NULL;
        char *crlf = NULL;
        char *dir = NULL;
        char *filename = NULL;
        char *headstart = NULL;
        char *mhead = NULL;
        char *mimetype = NULL;
        char *pbuf = NULL;
        char *ptmp = NULL;
        char *tmp = NULL;
        char hash[SHA_DIGEST_LENGTH*2+1];
        char template[] = "/var/tmp/upload-XXXXXX";
        char uuid[37];
        uuid_t uuid_bin;
        const EVP_MD *md = NULL;
        http_status_code_t err = 0;
        int complete = 0;
        int fd = 0;
        long lclen = 0;
        ssize_t ret = 0;
        size_t required = 0;
        size_t size = 0;
        size_t written = 0;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int i = 0;
        unsigned int md_len = 0;

        /* get expected length of body */
        clen = http_get_header(request, "Content-Length");
        lclen = strtol(clen, NULL, 10);

        /* Ensure Content-Length is not greater than uploadmax. 
         * If too large, just drop the connection.  We have no way to signal 
         * an error to the client without first accepting the whole request. */
        if (config->uploadmax > 0) {
                long bodysize = lclen;
                if (bodysize > config->uploadmax * 1024 * 1024) {
                        syslog(LOG_INFO, "Upload aborted. " 
                        "Request body of size %li exceeds uploadmax (%liMB)",
                        bodysize, config->uploadmax);
                        return 0;
                }
        }

        /* abort if we don't have a boundary */
        if (!b) {
                syslog(LOG_ERR, "No boundary header for upload url");
                return HTTP_BAD_REQUEST;
        }

        /* first, grab any bytes already in buffer */
        size = bytes;
        syslog(LOG_DEBUG, "I already have %i bytes", (int) size);

        /* fill the buffer if empty: Chrome often gets here with 0 bytes */
	while (bytes == 0) {
		required = ((lclen-size)>BUFSIZE) ? BUFSIZE : lclen - size;
		syslog(LOG_DEBUG, "Initial attempt to read %i bytes",
			(int) required);
		if ((bytes = rcv(sock, buf, required, MSG_WAITALL)) == -1) {
			syslog(LOG_DEBUG, "failed to fill buffer");
			return HTTP_BAD_REQUEST;
		}
                size += bytes;
	}

        /* find boundary */
        pbuf = memsearch(buf, b, BUFSIZE);
        if (pbuf == NULL) {
                syslog(LOG_ERR, "No boundary found in data");
                return HTTP_BAD_REQUEST;
        }
        pbuf += strlen(b) + 2; /* skip boundary and CRLF */

        /* keep a note of where the multipart headers start */
        headstart = pbuf;

        /* find end of headers => find blank line (search for 2xCRLF) */
        pbuf = memsearch(pbuf, "\r\n\r\n", BUFSIZE-(pbuf-buf));
        if (pbuf == NULL) {
                syslog(LOG_ERR, "Blank line required after multipart headers");
                return HTTP_BAD_REQUEST;
        }

        /* read multipart headers, get Content-Type */
        mimetype = calloc(LINE_MAX, sizeof(char));
        while ((crlf = memsearch(headstart,"\r\n",pbuf-headstart+2)) != NULL) {
                /* process multipart header */
                mhead = strndup(headstart, crlf - headstart);
                syslog(LOG_DEBUG, "multipart header [%s]", mhead);
                if (strncmp(mhead, "Content-Type: ", 14) == 0) {
                        if (sscanf(mhead, "Content-Type: %s", mimetype) != 1) {
                                free(mimetype);
                                mimetype = NULL;
                        }
                }
                free(mhead);
                headstart = crlf + 2; /* next line */
        }

        pbuf += 4; /* skip CRLF */

        /* open file for writing */
        umask(022);
        fd = mkstemp(template);
        if (fd == -1) {
                syslog(LOG_ERR, "Could not create temporary file for upload");
                free(mimetype);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* start building SHA1 */
        OpenSSL_add_all_digests();
        md = EVP_get_digestbyname("SHA1");
        if(!md) {
                syslog(LOG_ERR, "SHA1 digest unavailable");
                free(mimetype);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);

        ptmp = memsearch(pbuf, b, BUFSIZE-(pbuf-buf)); /* check for boundary */
        if (ptmp != NULL) {
                /* boundary found - short write */
                syslog(LOG_DEBUG, "end boundary found in initial buffer");
                ret = write(fd, pbuf, ptmp - pbuf - 4);
                EVP_DigestUpdate(mdctx, pbuf, ptmp - pbuf - 4);
                written += ret;
        }
        else {
                syslog(LOG_DEBUG, "end boundary NOT found in initial buffer");
                ret = write(fd, pbuf, size - (pbuf - buf));
                EVP_DigestUpdate(mdctx, pbuf, size - (pbuf - buf));
                written += ret;
        }
        while(lclen > size) {
                /* read into buffer */
                errno = 0;
                required = ((lclen-size)>BUFSIZE) ? BUFSIZE : lclen - size;
                syslog(LOG_DEBUG, "Reading %i bytes", (int) required);
                bytes = rcv(sock, buf, required, MSG_WAITALL);
                size += bytes;

                if (complete) continue; /* read to end of request */

                /* check for boundary */
                pbuf = memsearch(buf, b, bytes);
                if (pbuf != NULL) {
                        /* boundary reached, we're done here */
                        syslog(LOG_DEBUG, "boundary reached, we're done here");
                        ret = write(fd, buf, pbuf - buf - 4);
                        if (ret > 0) {
                                written += ret;
                                EVP_DigestUpdate(mdctx, buf, pbuf-buf-4);
                        }
                        complete = 1;
                }
                else {
                        /* write contents of buffer out to file */
                        ret = write(fd, buf, (int) bytes);
                        if (ret > 0) {
                                written += ret;
                                EVP_DigestUpdate(mdctx, buf, bytes);
                        }
                }
        }
        syslog(LOG_DEBUG, "Buffer flushed");
        http_flush_buffer();
        if (lclen != size) {
                syslog(LOG_ERR, "ERROR: Read %li/%li bytes",
                        (long) size, lclen);
                syslog(LOG_ERR, "ERROR: Expected another %li bytes",
                        lclen - (long)size);
                free(mimetype);
                return HTTP_BAD_REQUEST;
        }
        syslog(LOG_DEBUG, "Read %li bytes total", (long)size);
        syslog(LOG_DEBUG, "Wrote %li bytes total", (long)written);

        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);

        for (i=0; i < SHA_DIGEST_LENGTH; i++) {
                sprintf((char*)&(hash[i*2]), "%02x", md_value[i]);
        }

        /* set permissions */
        if (fchmod(fd, 0644) == -1) {
                syslog(LOG_ERR, "Failed to set file permissions on upload");
                free(mimetype);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* close file */
        close(fd);

        /* ensure destination directory exists */
        dir = strdup(u->path);
        replacevars(&dir, request->res);
        umask(022);
        if (!rmkdir(dir, 0755)) {
                free(dir);
                free(mimetype);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (request->uuid) {
                /* rename to <path>/<uuid> */
                uuid_generate(uuid_bin);
                uuid_unparse(uuid_bin, uuid);
                syslog(LOG_DEBUG, "UUID: %s", uuid);
                asprintf(&filename, "%s/%s", dir, uuid);
        }
        else {
                /* rename to <path>/<sha1sum> */
                asprintf(&filename, "%s/%s", dir, hash);
        }
        free(dir);
        syslog(LOG_ERR, "filename: %s", filename);
        if (rename(template, filename) == -1) {
                syslog(LOG_ERR, "Failed to rename uploaded file: %s",
                        strerror(errno));
                free(filename);
                free(mimetype);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* write metadata to file */
        if (mimetype) {
                char *metafile;
                asprintf(&metafile, "%s.mime", filename);
                syslog(LOG_DEBUG, "writing mime type to %s", metafile);
                if ((fd = creat(metafile, S_IRUSR | S_IWUSR)) == -1) {
                        syslog(LOG_DEBUG, "failed to write metadata");
                }
                else {
                        write(fd, mimetype, strlen(mimetype));
                        close(fd);
                        syslog(LOG_DEBUG, "metadata written");
                }
                free(mimetype);
                free(metafile);
        }
        else {
                syslog(LOG_DEBUG, "No metadata. Skipping.");
        }
        free(filename);

        /* return response to client with hash of uploaded file */
        char *r;
        asprintf(&r, "<sha1sum>%s</sha1sum>", hash);
        if (request->uuid) {
                tmp = strdup(r);
                free(r);
                asprintf(&r, "<resources><uuid>%s</uuid>\n%s\n</resources>",
                        uuid, tmp);
                free(tmp);
        }
        set_headers(&r); /* set any additional headers */
        http_response_full(sock, HTTP_CREATED, "text/xml", r);
        free(r);

        return err;
}

/* plugin function to process xml POST data
 * fork and execute plugin, write request data (xml) to plugin stdin
 * and return xml from plugin stdout to http client
 */
/* TODO: set plugin POST data limit from config */
http_status_code_t response_xml_plugin(int sock, url_t *u)
{
        FILE *fd = NULL;
        char plugout[BUFSIZE] = "";
        int err = 0;
        int pipes[4];
        pid_t pid = 0;

        pipe(&pipes[0]);
        pipe(&pipes[2]);

        /* fork and exec */
        pid = fork();
        if (pid == -1) {
                syslog(LOG_ERR, "plugin fork failed");
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (pid == 0) { /* child */
                /* close unused pipes */
                close(pipes[1]);
                close(pipes[2]);

                /* redirect stdin and stdout to pipes */
                close(STDIN_FILENO);
                close(STDOUT_FILENO);
                dup2(pipes[0], STDIN_FILENO);
                dup2(pipes[3], STDOUT_FILENO);

                /* execute plugin */
		int i = 0;
                char *cmd = strdup(u->path);
                replacevars(&cmd, request->res);
		char **args = calloc(strlen(cmd), sizeof(char *));
		args[i++] = cmd;
		char *word = strtok(cmd, " ");
		while (word != NULL) {
			word = strtok(NULL, " ");
			args[i++] = word;
		}
                syslog(LOG_DEBUG, "executing plugin: %s", cmd);
                if (execv(cmd, args) == -1) {
                        syslog(LOG_ERR, "error executing plugin: %s",
					strerror(errno));
                }
		free(args);
                free(cmd);
                _exit(EXIT_FAILURE);
        }
        close(pipes[0]); close(pipes[3]); /* close unused pipes in parent */

        /* write to stdin of plugin */
        fd = fdopen(pipes[1], "w");
        fprintf(fd, "%s", request->data->value);
        fclose(fd);

        /* read from stdout of plugin */
        fd = fdopen(pipes[2], "r");
        memset(plugout, 0, sizeof plugout);
        fread(plugout, sizeof plugout - 1, 1, fd);
        fclose(fd);

        /* obtain plugin exit code */
        int status = 0;
        int httpcode = HTTP_INTERNAL_SERVER_ERROR;
        waitpid(pid, &status, 0);
	syslog(LOG_DEBUG, "status is %i", status);
        if (WIFEXITED(status)) {
                syslog(LOG_DEBUG, "plugin exited with code %d",
                        WEXITSTATUS(status));
                switch (WEXITSTATUS(status)) {
                case 0:
                        httpcode = HTTP_OK;
                        break;
                case 4:
                        httpcode = HTTP_BAD_REQUEST;
                        break;
                default:
                        break;
                }
        }
        /* respond to http client */
        char *r = strdup(plugout);
        set_headers(&r); /* set any additional headers */
        http_response_full(sock, httpcode, "text/xml", r);
        free(r);

        return err;
}

/* call a plugin */
http_status_code_t response_plugin(int sock, url_t *u)
{
        FILE *fd = NULL;
        char pbuf[BUFSIZE] = "";
        http_status_code_t err = 0;
        int ret = 0;
        ssize_t ibytes = BUFSIZE;
        char *cmd = NULL;

        cmd = strdup(u->path);
        replacevars(&cmd, request->res);
        syslog(LOG_DEBUG, "executing plugin: %s", cmd);
        fd = popen(cmd, "r");
        if (fd == NULL) {
                syslog(LOG_ERR, "popen(): %s", strerror(errno));
                free(cmd);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        free(cmd);

        /* write HTTP headers */
        //set_headers(&r); /* set any additional headers */
        http_response_headers(sock, HTTP_OK, 0, NULL);
        snd_blank_line(sock);

        /* keep reading from plugin and sending output back to HTTP client */
        char *chunksize;
        while (ibytes == BUFSIZE) {
                ibytes = fread(pbuf, 1, BUFSIZE, fd);
                syslog(LOG_DEBUG, "writing %i bytes to socket", (int) ibytes);
                asprintf(&chunksize, "%x\r\n", (int)ibytes);
                snd(sock, chunksize, strlen(chunksize), 0);
                snd(sock, pbuf, ibytes, 0);
                snd(sock, "\r\n", 2, 0); /* CRLF */
                free(chunksize);
        }
        snd(sock, "0\r\n", 3, 0); /* Send final (empty) chunk */
        snd_blank_line(sock);

        /* pop TCP cork */
        setcork(sock, 0);

        /* TODO: handle exit codes */
        ret = pclose(fd);
        if (ret == -1) {
                syslog(LOG_ERR, "pclose(): %s", strerror(errno));
        }


        return err;
}

#ifdef _GIT
http_status_code_t response_git(int sock, url_t *u)
{
        http_status_code_t err = 0;
        git_repository *repo = NULL;
        git_reference *ref = NULL;
        git_object *obj = NULL;
        git_tree_entry *entry = NULL;
        int rc = 0;
        char *gitrepo;
        char *branch;
        char *revstr;
        const git_oid *oid = NULL;
        const char *ptr;

        /* open repository */
        gitrepo = strdup(u->db);
        replacevars(&gitrepo, request->res);
        syslog(LOG_DEBUG, "opening git repo '%s'", gitrepo);
        rc = git_repository_open_bare(&repo, gitrepo);
        if (rc != 0) {
                syslog(LOG_DEBUG, "error in git_repository_open_bare()");
                free(gitrepo);
                return HTTP_NOT_FOUND;
        }
	free(gitrepo);

        /* find branch */
        branch = strdup(u->view);
        replacevars(&branch, request->res);
        rc = git_branch_lookup(&ref, repo, branch, GIT_BRANCH_LOCAL);
        if (rc != 0) {
                syslog(LOG_DEBUG, "'%s' is not a valid branch", branch);
		free(branch);
                git_repository_free(repo);
                return HTTP_NOT_FOUND;
        }

        /* find blob that matches requested file */
        asprintf(&revstr, "%s^{tree}", branch);
        rc = git_revparse_single(&obj, repo, revstr);
        if (rc != 0) {
                syslog(LOG_DEBUG, "error in git_revparse_single()");
		free(branch);
                git_repository_free(repo);
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        git_tree *tree = (git_tree *)obj;
        char *file = request->res + 1; /* strip leading slash */
        syslog(LOG_DEBUG, "fetching '%s' from branch '%s'", file, branch);
        rc = git_tree_entry_bypath(&entry, tree, file);
        if (rc != 0) {
                syslog(LOG_DEBUG, "'%s' not found in branch '%s'",
                       file, branch);
		free(branch);
                git_repository_free(repo);
                return HTTP_NOT_FOUND;
        }
        free(branch);
        free(revstr);
        oid = git_tree_entry_id(entry);
        git_blob *blob = NULL;
        rc = git_blob_lookup(&blob, repo, oid);
        if (rc != 0) {
                syslog(LOG_DEBUG, "error in git_blob_lookup()");
                git_repository_free(repo);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* output raw blob */
        ptr = git_blob_rawcontent(blob);

	/* TODO: support non-text mime types */
        char *mime = "text/plain";

	http_response_headers(sock, 200, git_blob_rawsize(blob), mime);
	snd_blank_line(sock);
        snd(sock, (void *)ptr, (size_t)git_blob_rawsize(blob), 0);

	/* pop TCP cork */
	setcork(sock, 0);

        /* clean up */
        git_object_free(obj);
        git_blob_free(blob);
        git_tree_entry_free(entry);
        git_reference_free(ref);
        git_repository_free(repo);

        return err;
}
#endif /* _GIT */

/* serve static files */
http_status_code_t response_static(int sock, url_t *u)
{
        char *filename = NULL;
        char *base = NULL;
        http_status_code_t err = 0;

        base = basefile_pattern(request->res, u->url);
        if (strcmp(u->url, request->res) == 0) {
                filename = strdup(u->path);
        }
        else {
                asprintf(&filename, "%s%s", u->path, base);
        }
        free(base);
        send_file(sock, filename, &err);
        free(filename);

        return err;
}

/* send a static file */
int send_file(int sock, char *file, http_status_code_t *err)
{
        char *path = NULL;
        char *headers = NULL;
        char *mimetype = NULL;
        char *r = NULL;
        char expires[39];
        int f = 0;
        int rc = 0;
        off_t offset = 0;
        struct stat stat_buf;
        struct tm *tmp = NULL;
        time_t t = 0;

        *err = 0;

        /* perform variable substitution on path */
        path = strdup(file);
        replacevars(&path, request->res);

        f = open(path, O_RDONLY);
        if (f == -1) {
                syslog(LOG_ERR, "unable to open '%s': %s\n", path,
                                strerror(errno));
                *err = HTTP_NOT_FOUND;
                free(path);
                return -1;
        }

        /* get size of file */
        fstat(f, &stat_buf);

        /* ensure file is a regular file */
        if (! S_ISREG(stat_buf.st_mode)) {
                syslog(LOG_ERR, "'%s' is not a regular file\n", path);
                *err = HTTP_NOT_FOUND;
                free(path);
                return -1;
        }

        syslog(LOG_DEBUG, "Sending %i bytes", (int)stat_buf.st_size);

        /* send headers */
        mimetype = get_mime_type(path);
        syslog(LOG_DEBUG, "Content-Type: %s", mimetype);
        asprintf(&headers, "%s\nContent-Length: %i", mimetype,
                (int)stat_buf.st_size);
        free(mimetype);
        if (asprintf(&r, RESPONSE_200, config->serverstring, headers, "") == -1) {
                syslog(LOG_ERR, "send_file(): malloc failed");
                *err = HTTP_INTERNAL_SERVER_ERROR;
                free(path);
                return -1;
        }
        free(headers);

        if (!request->nocache) {
                /* Add Expires header in RFC1123 date format, 10 years ahead */
                int tenyears = 10 * 365 * 24 * 60 * 60; /* ish */
                t = time(NULL) + tenyears;
                tmp = localtime(&t);
                if (strftime(expires, 39, "Expires: %a, %d %b %Y %T GMT", tmp))
                {
                        http_insert_header(&r, expires);
                }
        }
        set_headers(&r); /* set any additional headers */
        respond(sock, r);

        /* send the file */
        errno = 0;
        offset = 0;
        if (config->ssl) {
                rc = sendfile_ssl(sock, f, stat_buf.st_size);
        }
        else {
                rc = sendfile(sock, f, &offset, stat_buf.st_size);
                if (rc == -1) {
                        syslog(LOG_ERR, "error from sendfile: %s\n",
                                strerror(errno));
                }
        }
        syslog(LOG_DEBUG, "Sent %i bytes", rc);

        /* everything sent ? */
        if (rc != stat_buf.st_size) {
                syslog(LOG_ERR,
                        "incomplete transfer from sendfile: %d of %d bytes\n",
                        rc, (int)stat_buf.st_size);
        }

        /* pop my cork */
        setcork(sock, 0);

        close(f);
        free(path);

        return 0;
}

/* if not a collection, fetch the last element from the request url */
field_t * get_element(int *err) {
        int i = 0;
        field_t * filter = NULL;

        *err = 0;

        if (strncmp(request->res + strlen(request->res) - 1, "/", 1) != 0) {
                /* url didn't end in / - this is an element of a collection */
                filter = malloc(sizeof(field_t));
                if (asprintf(&filter->fname, "id") == -1) {
                        *err = HTTP_INTERNAL_SERVER_ERROR;
                        free(filter);
                        return NULL;
                }
                /* grab the key (the last segment of the url) */
                for (i = strlen(request->res); i > 0; --i) {
                        if (strncmp(request->res + i, "/", 1) == 0)
                                break;
                }
                if (i == 0) {
                        *err = HTTP_INTERNAL_SERVER_ERROR;
                        free(filter);
                        return NULL;
                }
                filter->fvalue = strdup(request->res + i + 1);
                syslog(LOG_DEBUG, "URL requested: %s", request->res);
                syslog(LOG_DEBUG, "Element id: %s", filter->fvalue);
        }
        return filter;
}

/*
 * return a pointer to a copy of this db
 * after performing variable substitutions.
 * free with free_db() after use.
 */
db_t *getdbv(char *alias)
{
        db_t *db;
        db_t *dbs;
        dbs = getdb(alias);
        db = calloc(1, sizeof(db_t));
        db->alias = strdup(dbs->alias);
        db->type = strdup(dbs->type);
        if (dbs->host) {
                db->host = strdup(dbs->host);
                replacevars(&db->host, request->res);
        }
        if (dbs->db) {
                db->db = strdup(dbs->db);
                replacevars(&db->db, request->res);
        }
        if (dbs->user) {
                db->user = strdup(dbs->user);
                replacevars(&db->user, request->res);
        }
        if (dbs->pass) {
                db->pass = strdup(dbs->pass);
                replacevars(&db->pass, request->res);
        }
        return db;
}

size_t rcv(int sock, void *data, size_t len, int flags)
{
        size_t rbytes = 0;
        if (config->ssl) {
                if ((flags & MSG_PEEK) == MSG_PEEK) {
                        rbytes = ssl_peek(data, len);/* look but don't touch */
                }
                else {
                        rbytes = ssl_recv(data, len);
                }
        }
        else {
                rbytes = recv(sock, data, len, flags);
        }
        return rbytes;
}

ssize_t snd(int sock, void *data, size_t len, int flags)
{
        ssize_t bytes = 0;
        if (config->ssl) {
                bytes = ssl_send(data, len);
        }
        else {
                bytes = send(sock, data, len, flags);
                if (bytes == -1) {
                        syslog(LOG_ERR, "send error: %s", strerror(errno));
                        bytes = 0;
                }
        }
        return bytes;
}

ssize_t snd_blank_line(int sock)
{
	return snd(sock, "\r\n", 2, 0);
}

void setcork(int sock, int state)
{
        if (config->ssl) {
                setcork_ssl(state);
        }
        else {
                if (setsockopt(sock, IPPROTO_TCP, TCP_CORK,
                                &state, sizeof(state)) == -1)
                {
                        syslog(LOG_ERR, "Failed to set TCP_CORK: %s",
                                strerror(errno));
                }
        }
}

/* set any additional headers */
void set_headers(char **r)
{
        syslog(LOG_DEBUG, "set_headers()");
#ifndef _NAUTH
        if (http_get_header(request, "Logout")) {
                /* Logout header detected, unset session cookie */
                auth_unset_cookie(r);
        }
        else if (request->cookie) {
                syslog(LOG_DEBUG, "param requires cookie to be set");
                auth_set_cookie(r, HTTP_COOKIE_SESSION);
        }
#endif /* _NAUTH */
        if (request->nocache) {
                /* Tell all browsers not to cache this */
                http_insert_header(r,
                        "Cache-Control: no-cache, no-store, must-revalidate");
                http_insert_header(r, "Pragma: no-cache");
                http_insert_header(r, "Expires: 0");
        }
        if (request->serverheaders) {
                keyval_t *h = request->serverheaders;
                while (h != NULL) {
                        http_insert_header(r, h->value);
                        h = h->next;
                }
        }
        syslog(LOG_DEBUG, "set_headers() done");
}
