/* 
 * http.c
 *
 * this file is part of GLADD
 *
 * Copyright (c) 2012-2018 Brett Sheffield <brett@gladserv.com>
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
#include <assert.h>
#ifndef _NAUTH
#include <b64/cdecode.h>
#include <b64/cencode.h>
#endif /* _NAUTH */
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "handler.h"
#include "http.h"
#include "main.h"
#include "tls.h"
#include "string.h"
#include "xml.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* 
 * HTTP response codes from:
 *   http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
 */
struct http_status httpcode[] = {
        { 101, "Switching Protocols" },
        { 200, "OK" },
        { 201, "Created" },
        { 202, "Accepted" },
        { 203, "Non-Authoritative Information" },
        { 204, "No Content" },
        { 205, "Reset Content" },
        { 206, "Partial Content" },
        { 300, "Multiple Choices" },
        { 301, "Moved Permanently" },
        { 302, "Found" },
        { 303, "See Other" },
        { 304, "Not Modified" },
        { 305, "Use Proxy" },
        { 307, "Temporary Redirect" },
        { 400, "Bad Request" },
        { 401, "Unauthorized" },
        { 402, "Payment Required" },
        { 403, "Forbidden" },
        { 404, "Not Found" },
        { 405, "Method Not Allowed" },
        { 406, "Not Acceptable" },
        { 407, "Proxy Authentication Required" },
        { 408, "Request Timeout" },
        { 409, "Conflict" },
        { 410, "Gone" },
        { 411, "Length Required" },
        { 412, "Precondition Failed" },
        { 413, "Request Entity Too Large" },
        { 414, "Request-URI Too Long" },
        { 415, "Unsupported Media Type" },
        { 416, "Requested Range Not Satisfiable" },
        { 418, "I'm a teapot" },
        { 417, "Expectation Failed" },
        { 500, "Internal Server Error" },
        { 505, "HTTP Version Not Supported" }
};

http_request_t *request;
char buf[BUFSIZE];
size_t bytes = 0;

/* 
 * bodyline() - Also known as Fast Leg Theory.
 * handles each line of the body of the request.
 * Remember to duck.
 */
http_status_code_t bodyline(http_request_t *r, char *line)
{
        CURL *handle;
        char *clear;
        char *despaced;
        char dtok[LINE_MAX] = "";
        char key[LINE_MAX] = "";
        char value[LINE_MAX] = "";
        int l = 0;
        FILE *fd;

        fd = fmemopen(line, strlen(line), "r");
        if (fd == NULL) {
               syslog(LOG_ERR, "fmemopen failed");
               return HTTP_INTERNAL_SERVER_ERROR;
        }

        handle = curl_easy_init();

	r->data = NULL;
        while (fscanf(fd, "%[^&]&", dtok) == 1) {
                /* curl_easy_unescape() has a bug and doesn't unescape 
                 * '+' to space.
                 * see https://github.com/bmuller/mod_auth_openid/issues/10 */
                despaced = replaceall(dtok, "+", " "); /* fix curl bug */
                clear = curl_easy_unescape(handle, despaced, strlen(dtok), &l);
                if (sscanf(clear, "%[^=]=%[^\n]", key, value) == 2) {
                        http_add_request_data(r, key, value);
                }
                free(clear);
                free(despaced);
        }

        fclose(fd);

        curl_easy_cleanup(handle);
        curl_global_cleanup();

        return 0;
}

/* Check we received a valid Content-Length header
 * returns either the length or -1 on error
 * err is set to the appropriate http status code on error
 */
int check_content_length(http_request_t *r, http_status_code_t *err)
{
        long len;
        char *clength;

        *err = 0;

        clength = http_get_header(r, "Content-Length");
        if (clength == NULL) {
                /* 411 - Length Required */
                syslog(LOG_ERR, "Error, no Content-Length header");
                *err = HTTP_LENGTH_REQUIRED;
                return -1;
        }
        errno = 0;
        len = strtol(clength, NULL, 10);
        if ((errno == ERANGE && (len == LONG_MAX || len == LONG_MIN))
                || (errno != 0 && len == 0))
        {
                /* Invalid length - return 400 Bad Request */
                syslog(LOG_ERR, "Error, Invalid Content-Length");
                *err = HTTP_BAD_REQUEST;
                return -1;
        }

        return len;
}

/* ensure Content-Type header is present and valid
 * returns content-type string or NULL on error
 * err is set to the appropriate http status code on error
 */
char *check_content_type(http_request_t *r, http_status_code_t *err, char *type)
{
        char *mtype;
        mtype = http_get_header(request, "Content-Type");
        if (mtype == NULL) {
                syslog(LOG_ERR, "Content-Type header missing");
                *err = HTTP_BAD_REQUEST;
                return NULL;
        }
        if ((strcmp(mtype, "application/x-www-form-urlencoded") == 0)
        || (strlcmp(mtype, "text/xml") == 0)
        || (strlcmp(mtype, "application/json") == 0)
        || (strlcmp(mtype, "text/ldif") == 0))
        {
                return mtype;
        }
        else if ((strncmp(mtype, "multipart/form-data",
                strlen("multipart/form-data")) == 0) &&
                (strcmp(type, "upload") == 0)
        )
        {
                return mtype;
        }
        else {
                syslog(LOG_DEBUG,
                        "Unsupported Media Type '%s'", mtype);
                *err = HTTP_UNSUPPORTED_MEDIA_TYPE;
                return NULL;
        }
}

#ifndef _NAUTH
/* return decoded base64 string */
char *decode64(char *str)
{
        int i;
        char *plain = NULL;

        plain = malloc(strlen(str) * 2);

        base64_decodestate *d;
        d = malloc(sizeof(base64_decodestate));
        base64_init_decodestate(d);
        i = base64_decode_block(str, strlen(str), plain, d);
        plain[i] = '\0';

        free(d);

        return plain;
}

/* return encoded base64 string, without trailing '='s */
char *encode64(char *str, int len)
{
        int i;
        char *encoded = NULL;

        encoded = malloc(len * 4/3);

        base64_encodestate *d;
        d = malloc(sizeof(base64_encodestate));
        base64_init_encodestate(d);

        i = base64_encode_block(str, len, encoded, d);
        encoded[i] = '\0';

        free(d);

        return encoded;
}
#endif /* _NAUTH */

/* key -> value lookup for client request headers */
char *http_get_header(http_request_t *r, char *key)
{
        keyval_t *h = r->headers;
        while (h != NULL) {
                if (strcasecmp(h->key, key) == 0)
                        return h->value;
                h = h->next;
        }
        return NULL;
}

url_t *http_url_search(http_request_t *r, url_t *u)
{
        char *ip;
        char *host = http_get_header(r, "Host");

	if (host == NULL)
		asprintf(&host, "*");

        syslog(LOG_DEBUG, "Host requested: %s", host);

        ip = (r->xforwardip) ? r->xforwardip : r->clientip;

        syslog(LOG_INFO, "[%s] %s %s\n", ip, r->method, r->res);
        while (u != NULL) {
                if ((fnmatch(u->url, r->res, 0) == 0) &&
                         (fnmatch(u->domain, host, 0) == 0) &&
                         (strcmp(r->method, u->method) == 0))
                {
                        break;
                }
                u = u->next;
        }

        return u;
}

/* match requested url to config->urls */
url_t *http_match_url(http_request_t *r)
{
	url_t *u = config->urls;
	url_t *res = NULL;
	res = http_url_search(r, u);
        return res;
}

/* match requested url to config->urls */
url_t *http_match_template(http_request_t *r)
{
	url_t *u = config->templates;
	url_t *res = NULL;
	res = http_url_search(r, u);
	if (res == NULL)
		syslog(LOG_DEBUG, "No template matches URL");
	else
		syslog(LOG_DEBUG, "Template matched: '%s'", res->view);
        return res;
}

/* record key=value pair from client request */
void http_add_request_data(http_request_t *r, char *key, char *value)
{
        keyval_t *h;
        static keyval_t *hlast;

        h = http_set_keyval(key, value);

        if (r->data == NULL)
                r->data = h;
        else if (hlast != NULL)
                hlast->next = h;
        hlast = h;
}

/* return an initialized http request struct */
http_request_t *http_init_request()
{
        http_request_t *r;
        r = calloc(1, sizeof(http_request_t));
        asprintf(&r->authtype,"Basic");
        r->authuser = NULL;
        return r;
}

/* return a keyval_t with the key and value set */
keyval_t *http_set_keyval (char *key, char *value)
{
        keyval_t *h;

        h = malloc(sizeof(keyval_t));
        h->key = strdup(key);
        h->value = strdup(value);
        h->next = NULL;

        return h;
}

/* set http_request_t->method to new value, reallocating memory if needed */
void http_set_request_method(http_request_t *r, char *method)
{
        int i = 0;

        if (r->method != NULL) {
                free(r->method);
        }
        i = asprintf(&r->method, "%s", method);
        assert(i != -1);
	_unused(i);
}

/* set http_request_t->res to new value, reallocating memory if needed */
void http_set_request_resource(http_request_t *r, char *res)
{
        int i;
        char url[LINE_MAX];
        char qstr[LINE_MAX];

        if (r->res != NULL) {
                free(r->res);
        }
        if (sscanf(res, "%[^?]?%[^\n]", url, qstr) == 2) {
                /* we have a querystring - store it */
                i = asprintf(&r->res, "%s", url);
                assert(i != -1);
                i = asprintf(&r->querystr, "%s", qstr);
        }
        else {
                i = asprintf(&r->res, "%s", res);
        }
        assert(i != -1);
	_unused(i);
}

int http_insert_header(char **r, char *header, ...)
{
        char *pos;
        char *body = NULL;
        char *headers = NULL;
        char nl[3];
        char *tmp = strdup(*r);
        char b[LINE_MAX];
        va_list argp;
        free(*r);

        va_start(argp, header);
        vsprintf(b, header, argp);
        va_end(argp);

        syslog(LOG_DEBUG, "inserting header");
        syslog(LOG_DEBUG, "[%s]", b);

        /* insert just before the first blank line, otherwise at end */
        pos = memsearch(tmp, "\r\n\r\n", strlen(tmp));
        if (!pos) {
                pos = memsearch(tmp, "\n\n", strlen(tmp));
                if (!pos) {
                        /* no body, just tack header on the end */
                        asprintf(r, "%s%s\r\n", tmp, b);
                }
                else {
                        strcpy(nl, "\n");
                }
        }
        else {
                strcpy(nl, "\r\n");
        }
        if (pos) {
                /* request has body, insert header before the blank line */
                size_t hsize = pos-tmp;
                headers = calloc(1, hsize + 1);
                strncpy(headers, tmp, hsize);

                size_t bsize = strlen(pos+strlen(nl));
                body = calloc(1, bsize + 1);
                strncpy(body, pos+strlen(nl), bsize);

                asprintf(r, "%s%s%s%s%s", headers,nl,b,nl,body);
                free(headers);
                free(body);
        }
        free(tmp);
        return 0;
}

void http_flush_buffer()
{
	memset(buf, '\0', sizeof (buf));
        bytes = 0;
}

/* top up http buffer, returning number of bytes read or -1 on error 
 * lclen = value of Content-Length header, or -1 */
ssize_t http_fill_buffer(int sock, ssize_t lclen)
{
        size_t fillbytes;
        size_t newbytes;
        struct timeval tv;

        /* set socket timeout */
        tv.tv_sec = 0; tv.tv_usec = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                (char *)&tv, sizeof(struct timeval)) == -1)
        {
                syslog(LOG_ERR, "Error setting socket options: %s", 
                        strerror(errno));
                return -1;
        }

        /* bytes req'd to top up buffer */
        if (lclen > 0 && lclen < BUFSIZE) {
                fillbytes = (size_t)lclen - bytes;
        }
        else {
                fillbytes = BUFSIZE - bytes;
        }

        newbytes = rcv(sock, buf + bytes, fillbytes, MSG_WAITALL);
        if (newbytes == -1) {
                syslog(LOG_ERR, "Error reading from socket: %s", 
                        strerror(errno));
                return -1;
        }
        bytes += newbytes;

        return newbytes;
}

/* Read a line from the http buffer, filling the buffer as required.
 * returns either the line or NULL if no lines found
 * NB: lines cannot be longer than LINE_MAX
 * we strip off CRLF or LF from the end of the line before returning it
 * lclen = value of Content-length header, or -1
 */
char *http_readline(int sock, ssize_t lclen)
{
        char *line = NULL;
        char *nl = NULL;
        int pos = 0;
        int t = 0;
        size_t ll = 0;  /* line length */

        line = calloc(1, LINE_MAX + 1);
        for (;;) {
                /* fill the buffer if empty */
                /* loop until we have some data, or ~5s have passed */
                for (t=0; bytes == 0; t++) {
                        if (http_fill_buffer(sock, lclen) == -1) {
                                syslog(LOG_DEBUG, "failed to fill buffer");
                                return line;
                        }
                        if (t == 5000) { /* FIXME: this is an awful hack */
                                syslog(LOG_DEBUG, "timeout filling buffer");
                                return line;
                        }
                }

                /* scan buffer for newline */
                nl = memchr(buf, '\n', bytes);
                if (nl != NULL) {
                        pos = nl - buf;
                        memcpy(line + ll, buf, pos + 1);
                        line[pos] = '\0';
                        if (pos > 0)
                                if (line[pos - 1] == '\r')
                                        line[pos - 1] = '\0';
                        bytes -= pos + 1;
                        /* move unprocessed bytes to beginning of buffer */
                        memmove(buf, nl + 1, bytes);
                        memset(buf + bytes, '\0', BUFSIZE-bytes);
                        break;
                }
                else {
                        /* newline not found, so copy everything */
                        memcpy(line + ll, buf, bytes);
                        ll += bytes;
                        http_flush_buffer();
                }
        }
        return line;
}

/* return 1 if encoding was requested, 0 if not
 * r            - the request handle
 * encoding     - the encoding to check for */
int http_accept_encoding(http_request_t *r, char *encoding)
{
        char **tokens;
        char *tmp;
        char *ztypes = NULL;
        int i;
        int match = 0;
        int toks;

        ztypes = http_get_header(r, "Accept-Encoding");
        if (ztypes == NULL) { /* no encoding requested */
                return 0;
        }

        tmp = strdup(ztypes);
        tokens = tokenize(&toks, &tmp, ",");
        for(i=0; i < toks; i++) {
                if (strncmp(strip(tokens[i]), encoding, strlen(encoding))==0) {
                        match = 1;
                }
        }
        free(tmp);
        free(tokens);

        return match;
}

/* read body of http request, returning bytes read */
size_t http_read_body(int sock, char **body, long lclen)
{
        size_t size = bytes;
        struct timeval tv;

        /* first, grab any bytes already in buffer */
        memcpy(*body, buf, bytes);

        /* read remaining body data */
        if (bytes < lclen) {
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                        (char *)&tv, sizeof(struct timeval)) == -1)
                {
                        syslog(LOG_ERR, "setsockopt error: %s",
                                        strerror(errno));
                }
                bytes = rcv(sock, *body + size, lclen - size, MSG_WAITALL);
                size += bytes;
        }

        /* In debug mode, write request body to file */
        if (config->debug == 1) {
                FILE *fd;
                fd = fopen("/tmp/lastpost", "w");
                if (fd != NULL) {
                        fprintf(fd, "%s", *body);
                        fclose(fd);
                }
                else {
                        syslog(LOG_DEBUG,
                                "unable to open /tmp/lastpost for writing");
                }
        }

        return size;
}

int read_request_body(int sock, char *ctype, long lclen,
                http_status_code_t *err, http_request_t *r)
{
        size_t size = 0;
        char *body = calloc(1, lclen + 1);
        if (body == NULL) {
                syslog(LOG_ERR, "failed to allocate buffer for request body");
                *err = HTTP_INTERNAL_SERVER_ERROR;
                return 0;
        }
        r->data = calloc(1, sizeof(keyval_t));
        if (r->data == NULL) {
                syslog(LOG_ERR, "failed to allocate request keyval");
                *err = HTTP_INTERNAL_SERVER_ERROR;
                return 0;
        }
        size = http_read_body(sock, &body, lclen);
        r->bytes += size;
        if (size != lclen) {
                /* we have the wrong number of bytes */
                syslog(LOG_ERR, "request body has unexpected length.");
                syslog(LOG_DEBUG, "expected: %li, got %li", lclen, (long) size);
                *err = HTTP_BAD_REQUEST;
                return 0;
        }

        /* NB: only match first part of mime type, ignoring charset etc. */
        if (strlcmp(ctype, "text/xml") == 0) {
                asprintf(&r->data->key, "text/xml");
                r->data->value = body;
        }
        else if (strlcmp(ctype, "text/ldif") == 0) {
                asprintf(&r->data->key, "text/ldif");
                r->data->value = body;
        }
        if (strlcmp(ctype, "application/x-www-form-urlencoded") == 0) {
                bodyline(r, body); /* process keyvals */
        }
	else {
		r->data->key = strdup(ctype);
		r->data->value = body;
	}
        return 1;
}

/* check & store http headers from client */
http_request_t *http_read_request(int sock, int *hcount,
        http_status_code_t *err)
{
        char *clen;
        char *ctype;
        char httpv[LINE_MAX] = "";
        char key[LINE_MAX] = "";
        char *line;
        char method[LINE_MAX] = "";
        char resource[LINE_MAX] = "";
        char value[LINE_MAX] = "";
        http_request_t *r;
        keyval_t *h = NULL;
        keyval_t *hlast = NULL;
        long lclen;

        *err = 0;

        r = http_init_request();
        r->headlen = 0;

        /* first line has http request */
        line = http_readline(sock, -1);
        if (line == NULL) {
                syslog(LOG_ERR, "HTTP request is NULL");
                *err = HTTP_BAD_REQUEST;
                free(line);
                return r;
        }
        syslog(LOG_INFO, "%s", line);
        r->bytes = strlen(line);
        if (sscanf(line, "%s %s HTTP/%s", method, resource, httpv) != 3) {
                syslog(LOG_ERR, "HTTP request invalid");
                *err = HTTP_BAD_REQUEST;
                free(line);
                return r;
        }
        free(line);
        r->httpv = strdup(httpv);

        if ((strcmp(r->httpv, "1.0") != 0) && (strcmp(r->httpv, "1.1") != 0)) {
                syslog(LOG_ERR, "HTTP version '%s' not supported", r->httpv);
                *err = HTTP_VERSION_NOT_SUPPORTED;
                return r;
        }

        http_set_request_method(r, method);
        http_set_request_resource(r, resource);

        /* read headers */
        for (;;) {
                line = http_readline(sock, -1);
                if (line == NULL) break;
                if (strlen(line) == 0) break;
                r->headlen += strlen(line);
                syslog(LOG_DEBUG, "[%s]", line);
                if (sscanf(line, "%[^:]: %[^\r\n]", key, value) != 2) break;
                free(line);
                h = http_set_keyval(key, value);
                if (hlast != NULL) {
                        hlast->next = h;
                }
                else {
                        r->headers = h;
                }
                hlast = h;
                (*hcount)++;
        }
        free(line);
        syslog(LOG_DEBUG, "headers size: %i", r->headlen);
        r->bytes += r->headlen;

        /* only read body if we have a Content-Type and Content-Length */
        if ((ctype = http_get_header(r, "Content-Type"))
          && (clen = http_get_header(r, "Content-Length")))
        {
                syslog(LOG_DEBUG, "reading request body");
                errno = 0;
                lclen = strtol(clen, NULL, 10);
                if (errno != 0)
                        return r;

                /* multipart form data */
                if (strlcmp(ctype, "multipart/form-data") == 0)
                {
                        /* get boundary */
                        r->boundary = strdup(ctype +
                                strlen("multipart/form-data; boundary="));
                        syslog(LOG_DEBUG, "multipart boundary: %s",
                                r->boundary);
                }
                else {
                        read_request_body(sock, ctype, lclen, err, r);
                }
        }

        return r;
}

/* Output http status code response to the socket */
void http_response(int sock, int code)
{
        char *response;
        char *status;
        char *mime = "text/html";

        status = get_status(code).status;
        asprintf(&response, HTTP_RESPONSE_HTTP, code, status);
        http_response_full(sock, code, mime, response);
        free(response);
        syslog(LOG_INFO, "%i - %s", code, status);
}

/* Output http status code and message to the socket in xml format */
void http_response_xml(int sock, int code, char *respcode, char *resptext)
{
        char *response = NULL;
        char *status;
        char *mime = "text/xml";

        status = get_status(code).status;
        buildxmlresponse(&response, code, status, respcode, resptext);
        http_response_full(sock, code, mime, response);
        free(response);
        syslog(LOG_INFO, "%i - %s: %s (%s)", code, status, resptext, respcode);
}

/* output HTTP/1.1 response and basic headers only */
void http_response_headers(int sock, int code, int len, char *mime)
{
        char *r;
        char *status;
        status = get_status(code).status;
        asprintf(&r, "HTTP/1.1 %i %s\r\n", code, status);
        http_insert_header(&r, "Server: %s", config->serverstring);
        if (!config->pipelining)
                http_insert_header(&r, "Connection: close");
        if (mime) {
                http_insert_header(&r, "Content-Type: %s", mime);
        }
        if (len) {
                http_insert_header(&r, "Content-Length: %i", len);
        }
        else {
                http_insert_header(&r, "Transfer-Encoding: chunked");
        }
        if (code == HTTP_UNAUTHORIZED) {
                /* 401 Unauthorized MUST include WWW-Authenticate header */
                http_insert_header(&r, "WWW-Authenticate: %s realm=\"%s\"", 
                        request->authtype, config->authrealm);
        }
        respond(sock, r);
        free(r);
}

/* store additional server response header */
void http_response_header_add(char *header)
{
        keyval_t *k;
        k = calloc(1, sizeof(keyval_t));
        k -> value = strdup(header);
        keyval_t *h = request->serverheaders;
        if (h == NULL) {
                request->serverheaders = k;
        }
        else {
                while (h->next != NULL) {
                        h = h->next;
                }
                h->next = k;
        }
}

/* output full response including body */
void http_response_full(int sock, int code, char *mime, char *body)
{
        char *r;
        char *status;
        status = get_status(code).status;
        asprintf(&r, "HTTP/1.1 %i %s\r\n\r\n%s", code, status, body);
        http_insert_header(&r, "Server: %s", config->serverstring);
        if (!config->pipelining)
                http_insert_header(&r, "Connection: close");
        if (mime) {
                http_insert_header(&r, "Content-Type: %s", mime);
                http_insert_header(&r, "Content-Length: %i", strlen(body));
        }
        if (code == HTTP_UNAUTHORIZED) {
                /* 401 Unauthorized MUST include WWW-Authenticate header */
                http_insert_header(&r, "WWW-Authenticate: %s realm=\"%s\"", 
                        request->authtype, config->authrealm);
        }
        if (request->serverheaders) {
                keyval_t *h = request->serverheaders;
                while (h != NULL) {
                        http_insert_header(&r, h->value);
                        h = h->next;
                }
        }
        respond(sock, r);
        free(r);
}

size_t http_curl_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
        if (config->ssl)
                ssl_send(ptr, size*nmemb);
        else
                fwrite(ptr, size, nmemb, stream);
        return size*nmemb;
}

http_status_code_t http_response_proxy(int sock, url_t *u)
{
        http_status_code_t err = 0;
        CURL *curl = curl_easy_init();
        CURLcode r;
        char curlerr[CURL_ERROR_SIZE];
        FILE *f;
        char *url;

        /* build url */
        if (strcmp(u->type, "proxy") == 0) {
                asprintf(&url, "%s%s", u->path, request->res + strlen(u->url) - 1);
        }
        else if (strcmp(u->type, "rewrite") == 0) {
                asprintf(&url, "%s", u->path);
                replacevars(&url, request->res);
        }
        syslog(LOG_DEBUG, "proxying %s", url);

        f = fdopen(sock, "w");
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerr);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, f);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_curl_write);
        r = curl_easy_perform(curl);
        if (r != CURLE_OK) {
                syslog(LOG_ERR, "%s", curlerr);
                err = HTTP_INTERNAL_SERVER_ERROR;
        }
        curl_easy_cleanup(curl);
        fclose(f);
        free(url);

        return err;
}

/* find http status by numerical code */
struct http_status get_status(int code)
{
        int x;
        struct http_status hcode = { code, "Unknown" };

        for (x = 0; x < HTTPKEYS; x++) {
                if (httpcode[x].code == code)
                        hcode = httpcode[x];
        }

        return hcode;
}

/* process the headers from the client http request */
int http_validate_headers(http_request_t *r, http_status_code_t *err)
{
#ifndef _NAUTH
        char type[LINE_MAX] = "";
        char user[LINE_MAX] = "";
        char pass[LINE_MAX] = "";
        char cryptauth[LINE_MAX] = "";
        char *clearauth;
#endif /* _NAUTH */
        keyval_t *h;

        *err = 0;

        h = r->headers;
        while (h != NULL) {
#ifndef _NAUTH
                if (strcmp(h->key, "Authorization") == 0) {
                        if (sscanf(h->value, "%s %s", type, cryptauth) == 2) {
                                clearauth = decode64(cryptauth);
                                if (sscanf(clearauth, "%[^:]:%[^:]",
                                        user, pass) == 2)
                                {
                                        free(r->authtype);
                                        r->authtype = strdup(type);
                                        r->authuser = strdup(user);
                                        r->authpass = strdup(pass);
                                        free(clearauth);
                                }
                                else {
                                        syslog(LOG_DEBUG,
                                                "Invalid auth details\n");
                                        free(clearauth);
                                        *err = HTTP_UNAUTHORIZED;
                                        return -1;
                                }
                        }
                        else {
                                syslog(LOG_DEBUG,
                                        "Invalid Authorization header '%s'", h->value);
                                *err = HTTP_BAD_REQUEST;
                                return -1;
                        }
                }
#endif /* _NAUTH */
                h = h->next;
        }
        return 0;
}

/* free request info */
void free_request(http_request_t **r)
{
        if (r) {
                free_keyval((*r)->serverheaders);
                free_keyval((*r)->headers);
                free_keyval((*r)->data);
                free((*r)->httpv);
                free((*r)->method);
                free((*r)->res);
                free((*r)->querystr);
                free((*r)->clientip);
                free((*r)->xforwardip);
                free((*r)->authtype);
                free((*r)->authuser);
                free((*r)->authpass);
                free((*r)->boundary);
                free((*r));
                *r = NULL;
        }
}
