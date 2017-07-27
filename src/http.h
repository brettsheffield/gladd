/* 
 * http.h
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

#ifndef __GLADD_HTTP_H__
#define __GLADD_HTTP_H__ 1

#define HTTPKEYS (sizeof httpcode / sizeof (struct http_status))
#define HTTP_RESPONSE_HTTP "<html><body><h1>%1$i %2$s</h1>\n</body>\n</html>\n"
#define MAX_RESOURCE_LEN 256
#define BUFSIZE 32768

#include <sys/types.h>
#include "config.h"

typedef enum {
        HTTP_OK                         = 200,
        HTTP_CREATED                    = 201,
        HTTP_BAD_REQUEST                = 400,
        HTTP_UNAUTHORIZED               = 401,
        HTTP_FORBIDDEN                  = 403,
        HTTP_NOT_FOUND                  = 404,
        HTTP_METHOD_NOT_ALLOWED         = 405,
        HTTP_LENGTH_REQUIRED            = 411,
        HTTP_UNSUPPORTED_MEDIA_TYPE     = 415,
        HTTP_TEAPOT                     = 418,
        HTTP_INTERNAL_SERVER_ERROR      = 500,
        HTTP_NOT_IMPLEMENTED            = 501,
        HTTP_VERSION_NOT_SUPPORTED      = 505
} http_status_code_t;

typedef enum {
        HTTP_COOKIE_SESSION
} http_cookie_type_t;

struct http_status {
        int code;
        char *status;
};

typedef struct http_request_t {
        char *httpv;            /* HTTP version                          */
        char *method;           /* HTTP request method (GET, POST etc.)  */
        char *res;              /* resource (url) requested              */
        char *querystr;         /* any query string supplied             */
        ssize_t bytes;          /* bytes recv()'d                        */
        char *clientip;         /* IP address of client                  */
        char *xforwardip;       /* X-Forwarded-For header                */
        char *authtype;         /* Basic, or Silent                      */
        char *authuser;         /* username supplied for http basic auth */
        char *authpass;         /* password    "      "   "     "    "   */
        char *boundary;         /* boundary for multipart data           */
        int cookie;             /* 0 (default), 1 = set session cookie   */
        int headlen;            /* length of request headers (bytes)     */
        int htmlout;            /* 0 (default), 1 = convert output to html */
        int nocache;            /* 0 (default), 1 = do not cache         */
        int nofilter;           /* 0 (default), 1 = no SQL WHERE filter  */
        int uuid;               /* 0 (default), 1 = use uuid for uploads */
        keyval_t *headers;      /* client request headers                */
        keyval_t *data;         /* client request data                   */
        keyval_t *serverheaders;/* additional server response headers    */
} http_request_t;

extern http_request_t *request;
extern char buf[BUFSIZE];
extern size_t bytes;

http_status_code_t bodyline(http_request_t *r, char *line);
int check_content_length(http_request_t *r, http_status_code_t *err);
char *check_content_type(http_request_t *r, http_status_code_t *err, char *type);
void free_request(http_request_t **r);
char *decode64(char *str);
char *encode64(char *str, int len);
struct http_status get_status(int code);
void http_add_request_data(http_request_t *r, char *key, char *value);
http_request_t *http_init_request();
url_t  *http_match_url(http_request_t *r);
url_t  *http_match_template(http_request_t *r);
keyval_t *http_set_keyval (char *key, char *value);
void http_response(int sock, int code);
void http_response_xml(int sock, int code, char *respcode, char *resptext);
void http_response_headers(int sock, int code, int len, char *mime);
void http_response_header_add(char *header);
void http_response_full(int sock, int code, char *mime, char *body);
char *http_get_header(http_request_t *r, char *key);
void http_flush_buffer();
ssize_t http_fill_buffer(int sock, ssize_t lclen);
char *http_readline(int sock, ssize_t lclen);
size_t http_read_body(int sock, char **body, long lclen);
http_request_t *http_read_request(int sock, int *hcount,
        http_status_code_t *err);
void http_set_request_method(http_request_t *r, char *method);
void http_set_request_resource(http_request_t *r, char *res);
http_status_code_t http_response_proxy(int sock, url_t *u);
int http_validate_headers(http_request_t *r, http_status_code_t *err);
int http_accept_encoding(http_request_t *r, char *encoding);
int http_insert_header(char **r, char *header, ...);

#endif /* __GLADD_HTTP_H__ */
