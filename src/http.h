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
#define HTTP_RESPONSE "HTTP/1.1 %1$i %2$s\nServer: gladd\nConnection: close\nContent-Type: %3$s%4$s\n\n<html><body><h1>%1$i %2$s</h1>\n</body>\n</html>\n"
#define MAX_RESOURCE_LEN 256

struct http_status {
        int code;
        char *status;
};

typedef struct http_header_t {
        char *key;
        char *value;
        struct http_header_t *next;
} http_header_t;

typedef struct http_request_t {
        char *httpv;            /* HTTP version                          */
        char *method;           /* HTTP request method (GET, POST etc.)  */
        char *res;              /* resource (url) requested              */
        ssize_t bytes;          /* bytes recv()'d                        */
        char *authuser;         /* username supplied for http basic auth */
        char *authpass;         /* password    "      "   "     "    "   */
        http_header_t *headers; /* client request headers                */
} http_request_t;

extern http_request_t *request;

char *decode64(char *str);
struct http_status get_status(int code);
void http_response(int sock, int code);
char *http_get_header(http_header_t *h, char *key);
int http_read_headers(char *buf, ssize_t bytes);
int http_validate_headers(http_header_t *h);

#endif /* __GLADD_HTTP_H__ */
