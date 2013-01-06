/*
 * handler.c
 * some code to handle incoming connections
 */

#define _GNU_SOURCE

#define BUFSIZE 8096
#define MAX_RESOURCE_LEN 256

#include "config.h"
#include "main.h"
#include "mime.h"
#include "http.h"
#include "handler.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libxml/parser.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

int sockme;


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

/*
 * child process where we handle incoming connections
 */
void handle_connection(int sock, struct sockaddr_storage their_addr)
{
        char *basefile;
        char buf[BUFSIZE];
        char *filename;

        char httpv[8];
        char method[8];
        char res[MAX_RESOURCE_LEN];

        char s[INET6_ADDRSTRLEN];
        int byte_count;
        int state;
        
        url_t *u;

        //char *r;
        //char *xml;

        inet_ntop(their_addr.ss_family,
                        get_in_addr((struct sockaddr *)&their_addr),
                        s, sizeof s);

        syslog(LOG_INFO, "server: got connection from %s", s);

        /* What are we being asked to do? */
        byte_count = recv(sock, buf, sizeof buf, 0);
        syslog(LOG_DEBUG, "recv()'d %d bytes of data in buf\n", byte_count);

        if (sscanf(buf, "%s %s HTTP/%s", method, res, httpv) != 3) {
                syslog(LOG_INFO, "Bad Request");
                http_response(sock, 400);
                exit(EXIT_FAILURE);
        }

        syslog(LOG_DEBUG, "Method: %s", method);
        syslog(LOG_DEBUG, "Resource: %s", res);
        syslog(LOG_DEBUG, "HTTP Version: %s", httpv);

        /* Return HTTP response */

        /* put a cork in it */
        state = 1;
        setsockopt(sockme, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

        /* TODO: refactor to remove duplication */
        if (strncmp(method, "GET", 3) == 0) {

                int safety_counter =0;

                u = config->urls;
                while ((u != NULL) && (safety_counter < 5)) {
                        syslog(LOG_DEBUG, "url matching... Trying %s", u->url);
                        if (strncmp(res, u->url, strlen(u->url)) == 0) {
                                if (strncmp(u->type, "static", 6)) {
                                        /* serve static files */
                                        basefile = strndup(res+8, sizeof(res));
                                        asprintf(&filename, "%s%s", u->path,
                                                                    basefile);
                                        free(basefile);
                                        send_file(sock, filename);
                                        free(filename);
                                        break;
                                }
                        }
                        u = config->urls->next;
                        safety_counter++;
                }

                /* dynamic urls */
                /*
                else if (strncmp(res, "/guess/", 7) == 0){
                        prepare_response(res, &xml, 0);
                        if (asprintf(&r, RESPONSE_200, MIME_XML, xml) == -1) {
                                syslog(LOG_ERR, "Malloc failed");
                                exit(EXIT_FAILURE);
                        }
                        respond(sock, r);
                        free(xml);
                        free(r);
                }
                */
                if (u == NULL) {
                        /* Not found */
                        http_response(sock, 404);
                }
        }
        else {
                http_response(sock, 405);
        }

        /* close client connection */
        close(sock);

        /* child process can exit */
        exit (EXIT_SUCCESS);
}


/*
 *  prepare an XML document response
 *
 *  free() xml after use
 */
int prepare_response(char resource[], char **xml, char *query)
{
        xmlNodePtr n;
        xmlDocPtr doc;
        xmlChar *xmlbuff;
        int buffersize;

        doc = xmlNewDoc(BAD_CAST "1.0");
        n = xmlNewNode(NULL, BAD_CAST "resources");

        xmlDocSetRootElement(doc, n);

        /* flatten xml */
        xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
        *xml = malloc(snprintf(NULL, 0, "%s", (char *) xmlbuff));
        sprintf(*xml, "%s", (char *) xmlbuff);

        xmlFree(xmlbuff);
        xmlFreeDoc(doc);

        return 0;
}

int send_file(int sock, char *path)
{
        char *r;
        char *mimetype;
        int f;
        int rc;
        off_t offset;
        int state;
        struct stat stat_buf;

        /* TODO: first, check file exists, or return 404 */

        f = open(path, O_RDONLY);
        if (f == -1) {
                syslog(LOG_ERR, "unable to open '%s': %s\n", path,
                                strerror(errno));
                return 1;
        }

        /* get size of file */
        fstat(f, &stat_buf);
        syslog(LOG_DEBUG, "Sending %i bytes", (int)stat_buf.st_size);

        /* send headers */
        mimetype = malloc(strlen(MIME_DEFAULT)+1);
        get_mime_type(mimetype, path);
        syslog(LOG_DEBUG, "Content-Type: %s", mimetype);
        if (asprintf(&r, RESPONSE_200, mimetype, "") == -1) {
                syslog(LOG_ERR, "Malloc failed");
                exit(EXIT_FAILURE);
        }
        free(mimetype);
        respond(sock, r);

        /* send the file */
        errno = 0;
        offset = 0;
        rc = sendfile(sock, f, &offset, stat_buf.st_size);
        if (rc == -1) {
                syslog(LOG_ERR, "error from sendfile: %s\n", strerror(errno));
        }
        syslog(LOG_DEBUG, "Sent %i bytes", rc);

        /* everything sent ? */
        if (rc != stat_buf.st_size) {
                syslog(LOG_ERR,
                        "incomplete transfer from sendfile: %d of %d bytes\n",
                        rc, (int)stat_buf.st_size);
        }

        /* pop my cork */
        state = 0;
        setsockopt(sockme, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

        close(f);

        return 0;
}
