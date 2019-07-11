/* 
 * http_test.c - unit tests for http.c
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
#include "config.h"
#include "http_test.h"
#include "minunit.h"
#include "string.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

char *test_http_read_request_get()
{
        int hcount = 0;
#ifndef _NAUTH
        char *clear;
#endif
        char *headers;
        http_status_code_t err;

        config->ssl = 0;

        keyval_t *h = NULL;
        http_request_t *r = NULL;

        asprintf(&headers, "GET /static/form.html?somequerystring=value HTTP/1.1\r\nAuthorization: Basic YmV0dHk6bm9iYnk=\r\nUser-Agent: curl/7.25.0 (x86_64-pc-linux-gnu) libcurl/7.25.0 OpenSSL/1.0.0j zlib/1.2.5.1 libidn/1.25\r\nHost: localhost:3000\r\nAccept: */*\r\n\r\n");

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }
        write(sv[0], headers, strlen(headers));
        close(sv[0]); /* close write socket */

        r = http_read_request(sv[1], &hcount, &err);

        close(sv[1]); /* close read socket */
        free(headers);

        mu_assert("Test http_read_headers() with GET", err == 0);

        h = r->headers;

        mu_assert("Check client header count", hcount == 4);
        mu_assert("Check request method = GET", strcmp(r->method, "GET") == 0);
        mu_assert("Check HTTP version = 1.1", strcmp(r->httpv, "1.1") == 0);
        mu_assert("Check request url = /static/form.html",
                strcmp(r->res, "/static/form.html") == 0);
        mu_assert("Check request querystring",
                strcmp(r->querystr, "somequerystring=value") == 0);
        fprintf(stderr, "Headers: %i\n", hcount);
        fprintf(stderr, "'%s'\n", h->key);
        fprintf(stderr, "'%s'\n", h->value);
        mu_assert("Test 1st header key",
                (strcmp(h->key, "Authorization") == 0));
        mu_assert("http_get_header()",
                strcmp(http_get_header(r, "Authorization"),
                "Basic YmV0dHk6bm9iYnk=") == 0);

#ifndef _NAUTH
        clear = decode64("YmV0dHk6bm9iYnk=");
        mu_assert("Decode base64", strncmp(clear, "betty:nobby",
                strlen("betty:nobby")) == 0);
        free(clear);
#endif

        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 2nd header key", strcmp(h->key, "User-Agent") == 0);
        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 3rd header key", strcmp(h->key, "Host") == 0);
        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 4th header key", strcmp(h->key, "Accept") == 0);
        mu_assert("Ensure final header->next is NULL", !(h = h->next));

        mu_assert("http_validate_headers()",
                http_validate_headers(r, &err) == 0);
#ifndef _NAUTH
        mu_assert("http_validate_headers() - r->authuser != NULL", 
                r->authuser != NULL);
        mu_assert("http_validate_headers() - r->authuser (check value)",
                strcmp(r->authuser, "betty") == 0);
        mu_assert("http_validate_headers() - r->authpass != NULL", 
                r->authpass != NULL);
        mu_assert("http_validate_headers() - r->authpass (check value)",
                strcmp(r->authpass, "nobby") == 0);
#endif

        free_request(&r);

        return 0;
}

/* ensure http_readline() behaves correctly */
char *test_http_readline()
{
        char *data = "POST /sqlview/ HTTP/1.1\nUser-Agent: curl/7.25.0 (x86_64-pc-linux-gnu) libcurl/7.25.0 OpenSSL/1.0.0j zlib/1.2.5.1 libidn/1.25\nHost: localhost:3000\nAccept: */*\nContent-Length: 49\nContent-Type: application/x-www-form-urlencoded\n\nname=boris+was+here%2For+there%3F&id=9999999%2622";
        char *line;
        int ret;
        int sv[2];

        config->ssl = 0; /* ensure we're not using ssl */

        /* create a pair of connected sockets */
        fprintf(stderr, "Creating test sockets.\n");
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }

        /* write some data */
        fprintf(stderr, "Writing some data to test socket\n");
        ret = write(sv[0], data, strlen(data));
        if (ret == -1) {
                perror("Error writing to socket");
        }
        close(sv[0]); /* close write socket */

        /* read a line */
        fprintf(stderr, "flushing buffer\n");
        http_flush_buffer(); /* make sure buffer is clear */
        fprintf(stderr, "http_readline() - entering\n");
        line = http_readline(sv[1], -1);
        free(line);
        fprintf(stderr, "http_readline() done\n");

        close(sv[1]); /* close read socket */

        /* test we got what we expected */
        mu_assert("http_readline()", line != NULL);

        return 0;
}

char *test_http_read_request_post()
{
        int hcount = 0;
        http_status_code_t err;

        keyval_t *h = NULL;
        http_request_t *r = NULL;

        char *headers = "POST /sqlview/ HTTP/1.1\nUser-Agent: curl/7.25.0 (x86_64-pc-linux-gnu) libcurl/7.25.0 OpenSSL/1.0.0j zlib/1.2.5.1 libidn/1.25\nHost: localhost:3000\nAccept: */*\nContent-Length: 49\nContent-Type: application/x-www-form-urlencoded\n\nname=boris+was+here%2For+there%3F&id=9999999%2622";

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }
        write(sv[0], headers, strlen(headers));
        close(sv[0]); /* close write socket */

        http_flush_buffer(); /* clear buffer before making new request */
        fprintf(stderr, "That's all she wrote");
        r = http_read_request(sv[1], &hcount, &err);
        fprintf(stderr, "Angela Landsbury");
        close(sv[1]); /* close read socket */

        mu_assert("Test http_read_headers() with POST", err == 0);

        h = r->headers;

        mu_assert("Check client header count", hcount == 5);
        mu_assert("Check request method = POST",
                strcmp(r->method, "POST") == 0);
        mu_assert("Check HTTP version = 1.1", strcmp(r->httpv, "1.1") == 0);
        mu_assert("Check request url = /sqlview/",
                strcmp(r->res, "/sqlview/") == 0);
        fprintf(stderr, "Headers: %i\n", hcount);
        mu_assert("Test 1st header key", (strcmp(h->key, "User-Agent") == 0));
        mu_assert("http_get_header()", strcmp(http_get_header(r, "User-Agent"),
                "curl/7.25.0 (x86_64-pc-linux-gnu) libcurl/7.25.0 OpenSSL/1.0.0j zlib/1.2.5.1 libidn/1.25") == 0);

        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 2nd header key", strcmp(h->key, "Host") == 0);
        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 3rd header key", strcmp(h->key, "Accept") == 0);
        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 4th header key", strcmp(h->key,"Content-Length") == 0);
        mu_assert("Fetch next header", h = h->next);
        mu_assert("Test 5th header key", strcmp(h->key,"Content-Type") == 0);
        mu_assert("Ensure final header->next is NULL", !(h = h->next));

        mu_assert("Check Content-Type is valid",
                strcmp(http_get_header(r, "Content-Type"),
                "application/x-www-form-urlencoded") == 0);

        mu_assert("http_validate_headers()",
                http_validate_headers(r, &err) == 0);

        free_request(&r);

        return 0;
}

char *test_http_read_request_data()
{
        http_request_t *r = NULL;

        r = http_init_request();

        bodyline(r, "like=this&do=that");

        mu_assert("The Bodyline Test, 1932 (key)",
                strcmp(r->data->key, "like") == 0);
        mu_assert("The Bodyline Test, 1932 (value)",
                strcmp(r->data->value, "this") == 0);
        mu_assert("The Bodyline Test, 1933 (key)",
                strcmp(r->data->next->key, "do") == 0);
        mu_assert("The Bodyline Test, 1933 (value)",
                strcmp(r->data->next->value, "that") == 0);

        free_request(&r);

        return 0;
}

char *test_http_postdata_invalid()
{
        http_request_t *r;

        r = http_init_request();
        asprintf(&r->method, "POST");
        asprintf(&r->res, "/invalid/");
        mu_assert("http_match_url() - Ensure unmatched url fails",
                http_match_url(r) == NULL);
        free_request(&r);

        return 0;
}

char *test_http_postdata_checks()
{
        http_request_t *r;

        r = http_init_request();
        asprintf(&r->method, "POST");
        asprintf(&r->res, "/sqlview/");
        mu_assert("http_match_url() - match test url",
                http_match_url(r) != NULL);
        free_request(&r);

        return 0;
}

char *test_http_read_request_post_xml()
{
        http_request_t *r;
        int hcount = 0;
        http_status_code_t err = 0;

        char *headers = "POST / HTTP/1.1\nHost: localhost:3000\nAccept: */*\nContent-Length: 227\nContent-Type: text/xml\n";
        char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<journal description=\"My First Journal Entry\">\n  <debit account=\"1100\" amount=\"120.00\" />\n  <credit account=\"2222\" amount=\"20.00\" />\n  <credit account=\"4000\" amount=\"100.00\" />\n</journal>\n";
        char *xmlreq;

        asprintf(&xmlreq, "%s\n%s", headers, xml);

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }
        write(sv[0], xmlreq, strlen(xmlreq));
        close(sv[0]); /* close write socket */

        http_flush_buffer(); /* clear buffer before making new request */
        mu_assert("Read XML POST request",
                r = http_read_request(sv[1], &hcount, &err));
        close(sv[1]); /* close read socket */

        free(xmlreq);

        fprintf(stderr, "%s\n", r->data->value);

        free_request(&r);

        return 0;
}

/* POST data in excess of buffer size */
char *test_http_read_request_post_large()
{
        char *databuf;
        char *headers;
        http_request_t *r;
        http_status_code_t err = 0;
        int buflen;
        int datalen = BUFSIZE * 2 ;
        int hcount = 0;
        int headlen;
        int i;

        http_flush_buffer(); /* clear buffer before making new request */

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }

        /* write headers */
        asprintf(&headers, "POST / HTTP/1.1\nHost: localhost:3000\nAccept: */*\nContent-Length: %i\nContent-Type: text/xml\n\n", datalen);
        headlen = strlen(headers);
        buflen = headlen + datalen;
        databuf = calloc(buflen + 1, 1);
        strcpy(databuf, headers);
        free(headers);

        /* write enough data to overfill recv buffer */
        for (i=headlen; i<buflen; i++) {
                strcpy(databuf + i, "0");
        }
        write(sv[0], databuf, strlen(databuf));
        close(sv[0]); /* close write socket */

        mu_assert("POST more data than buffer",
                r = http_read_request(sv[1], &hcount, &err));

        close(sv[1]); /* close read socket */

        fprintf(stderr, "%i / %i bytes read\n",
                (int)r->bytes, (int)strlen(databuf));
        mu_assert("Ensure correct number of bytes read back",
                r->bytes == strlen(databuf)-6);

        free(databuf);
        free_request(&r);

        return 0;
}

char *test_http_proxy_request()
{
        char *url = "http://www.gladserv.com/";
        char *checkstring = "<!DOCTYPE HTML PUBLIC";
        char buf[1024];
        url_t u;
        size_t size = 0;

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }

        request = http_init_request();
        request->res = strdup("/report/index.html");

        /* build a url */
        asprintf(&u.type, "proxy");
        asprintf(&u.method, "GET");
        u.url = strdup("/report/*");
        u.path = strdup(url);

        /* fetch file */
        http_response_proxy(sv[0], &u);
        close(sv[0]); /* close write socket */
        size = recv(sv[1], buf, sizeof buf, 0);
        buf[size] = '\0';

        /* compare checksum */
        mu_assert("fetch file and compare checksum",
                strncmp(buf, checkstring, strlen(checkstring)) == 0);

        close(sv[1]); /* close read socket */

        free(u.type);
        free(u.method);
        free(u.url);
        free(u.path);
        free_request(&request);

        return 0;
}

char *test_http_rewrite_request()
{
        char *url = "http://www.gladserv.com/$2/$3/$4";
        char *checkstring = "<!DOCTYPE HTML";
        char buf[1024];
        url_t u;
        size_t size = 0;

        /* create a pair of connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
                perror("socketpair");
        }

        request = http_init_request();
        request->res = strdup("/reports/customers/42/2013-08-01/2013-09-30/");

        /* build a url */
        asprintf(&u.type, "rewrite");
        asprintf(&u.method, "GET");
        u.url = strdup("/report/*/*/*/*/");
        u.path = strdup(url);

        /* fetch file */
        http_response_proxy(sv[0], &u);
        close(sv[0]); /* close write socket */
        size = recv(sv[1], buf, sizeof buf, 0);
        buf[size] = '\0';

        /* compare checksum */
        mu_assert("fetch file and compare checksum",
                strncmp(buf, checkstring, strlen(checkstring)) == 0);

        close(sv[1]); /* close read socket */
        
        free(u.type);
        free(u.method);
        free(u.url);
        free(u.path);
        free_request(&request);

        return 0;
}

char *test_http_accept_encoding()
{
        http_request_t *r = http_init_request();

        /* no headers at all - MUST return 0 */
        mu_assert("Check for encoding with no header - MUST fail",
                !http_accept_encoding(r, "gzip"));

        /* Set Accept-Encoding header in request */
        r->headers = calloc(1, sizeof (struct keyval_t));
        asprintf(&r->headers->key, "Accept-Encoding");
        asprintf(&r->headers->value, "gzip, deflate");

        /* run some tests */
        mu_assert("Check for encoding (gzip)",
                http_accept_encoding(r, "gzip"));
        mu_assert("Check for encoding (deflate)",
                http_accept_encoding(r, "deflate"));
        mu_assert("Check for missing encoding (lzma)",
                !http_accept_encoding(r, "lzma"));

        free_request(&r);

        return 0;
}

char *test_http_insert_header()
{
        char *r;
        char *header = "Cache-Control: 3600";

        /* build a typical request */
        asprintf(&r, "GET /static/somefile.txt HTTP/1.1\nAuthorization: Basic YmV0dHk6bm9iYnk=\nUser-Agent: curl/7.25.0 (x86_64-pc-linux-gnu) libcurl/7.25.0 OpenSSL/1.0.0j zlib/1.2.5.1 libidn/1.25\nHost: localhost:3000\nAccept: */*\n");

        /* insert header after request (no body)*/
        http_insert_header(&r, header);
        mu_assert("check for inserted header",
                memsearch(r, header, strlen(r)) != NULL);
        free(r);

        /* check header is correctly inserted before body */
        asprintf(&r, "POST /static/stuff/ HTTP/1.1\r\nAuthorization: Basic YmV0dHk6bm9iYnk=\r\nUser-Agent: telnet\r\nHost: localhost\r\nAccept: */*\r\n\r\nBODY HERE");
        http_insert_header(&r, header);

        int pos = strlen("POST /static/stuff/ HTTP/1.1\r\nAuthorization: Basic YmV0dHk6bm9iYnk=\r\nUser-Agent: telnet\r\nHost: localhost\r\nAccept: */*\r\n");

        mu_assert("check header is inserted before body",
                memsearch(r, header, strlen(r))-r == pos);
        free(r);

        return 0;
}
