/* 
 * openssl.c
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

#include "tls.h"
#include "dh.h"
#include "config.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

SSL_CTX *ctx;
SSL_METHOD *method;
SSL_SESSION session;
SSL *ssl;
DH *dh;

char *ssl_err(int errcode)
{
        static char errstr[120];
        ERR_error_string(errcode, errstr);
        return errstr;
}

void do_tls_handshake(int fd)
{
        int ret;
        ssl = SSL_new(ctx);
        ret = SSL_set_fd(ssl, fd);
        if (ret != 1) {
                syslog(LOG_ERR, "failed to connect SSL object");
                _exit(EXIT_FAILURE);
        }
        ret = SSL_accept(ssl);
        if (ret != 1) {
                syslog(LOG_ERR, "SSL handshake failed (%s)", ssl_err(ret));
                _exit(EXIT_FAILURE);
        }
        syslog(LOG_DEBUG, "SSL Handshake completed (%s)",
                SSL_get_cipher_name(ssl));
}

int generate_dh_params(void)
{
        int codes;
        DH *dh = get_dh1024();

        if (DH_check(dh, &codes) != 1) {
                syslog(LOG_ERR, "Diffie Hellman check failed");
        }

        if (1 != SSL_CTX_set_tmp_dh(ctx, dh)) {
                syslog(LOG_ERR, "error loading Diffie Hellman params");
        }
        DH_free(dh);

        return 0;
}

int sendfile_ssl(int sock, int fd, size_t size)
{
        char buf[4096];
        size_t len;
        size_t sent = 0;
        int ret;
        int offset = 0;

        syslog(LOG_DEBUG, "Sending file...");

        /* read from file descriptor and send to ssl socket */
        do {
                if (offset == 0) len = read(fd, buf, sizeof buf);
                ret = SSL_write(ssl, buf+offset, len-offset);
                if (ret >= 0) {
                        sent += ret;
                        offset = len - ret;
                }
                else {
                        syslog(LOG_ERR, "Error in ssl_send(): %s",
                                ssl_err(ret));
                        break;
                }

        } while (sent < size);
        syslog(LOG_DEBUG, "%i/%i bytes sent", (int)sent, (int)size);

        return sent;
}

void setcork_ssl(int state)
{
        int sock = SSL_get_fd(ssl);
        if (setsockopt(sock, IPPROTO_TCP,TCP_CORK, &state,sizeof(state)) == -1)
        {
                syslog(LOG_ERR, "Failed to set TCP_CORK(ssl): %s",
                                strerror(errno));
        }
}

void ssl_cleanup(int fd)
{
        SSL_free(ssl);
        close(fd);
}

size_t ssl_peek(char *b, int len)
{
        int ret;
        int nread = 0;
        ret = SSL_peek(ssl, b, len);
        switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
                nread += ret;
                break;
        case SSL_ERROR_ZERO_RETURN:
                return 0;
        case SSL_ERROR_SYSCALL:
                return 0;
        default:
                return 0;
        }
        return nread;
}

size_t ssl_recv(char *b, int len)
{
        int ret;
        int nread = 0;
        do {
                ret = SSL_read(ssl, b+nread, len-nread);
                switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_NONE:
                        nread += ret;
                        break;
                case SSL_ERROR_ZERO_RETURN:
                        break;
                case SSL_ERROR_WANT_WRITE:
                        break;
                case SSL_ERROR_WANT_READ:
                        break;
                default:
                        break;
                }
        } while(ret > 0);
        return nread;
}

size_t ssl_send(char *msg, size_t len)
{
        int ret;
        int nwrite = 0;
        do {
	        syslog(LOG_DEBUG, "(openssl) pending %d bytes", SSL_pending(ssl));
	        syslog(LOG_DEBUG, "(openssl) attempting to read %i bytes", len-nread);
                ret = SSL_write(ssl, msg+nwrite, len-nwrite);
                switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_NONE:
                        nwrite += ret;
                        syslog(LOG_DEBUG, "(openssl) %i bytes read", ret);
                        break;
                case SSL_ERROR_ZERO_RETURN:
                        syslog(LOG_DEBUG, "(openssl) SSL_ERROR_ZERO_RETURN");
                        break;
                case SSL_ERROR_WANT_WRITE:
                        syslog(LOG_DEBUG, "(openssl) SSL_ERROR_WANT_WRITE");
                        break;
                case SSL_ERROR_WANT_READ:
                        syslog(LOG_DEBUG, "(openssl) SSL_ERROR_WANT_READ");
                        break;
                default:
                        break;
                }
                break;
        } while(ret > 0);
        return nwrite;
}

void ssl_setup()
{
        int ret;
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(SSLv23_server_method());
        if (config->ssl > 1) {
                SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
                syslog(LOG_DEBUG, "Disabling SSLv2 ciphers");
        }
        if (config->ssl > 2) {
                SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
                syslog(LOG_DEBUG, "Disabling SSLv3 ciphers");
        }
        if (config->ssl > 3) {
                SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
                syslog(LOG_DEBUG, "Disabling TLSv1.0 ciphers");
        }
        if (config->ssl > 4) {
                SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
                syslog(LOG_DEBUG, "Disabling TLSv1.1 ciphers");
        }
        if (config->ssl > 0) {
                SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
                syslog(LOG_DEBUG, "Disabling SSL compression");
        }
        if (SSL_CTX_set_cipher_list(ctx, config->sslciphers) != 1) {
                syslog(LOG_ERR, "Failed to set SSL ciphers");
                _exit(EXIT_FAILURE);
        }
        generate_dh_params();
        ret = SSL_CTX_use_certificate_chain_file(ctx, config->sslcert);
        if (ret != 1) {
                syslog(LOG_ERR, "Error loading certificate: %s.\n",
                        ssl_err(ret));
                _exit(EXIT_FAILURE);
        }
        ret = SSL_CTX_use_PrivateKey_file(ctx,config->sslkey,SSL_FILETYPE_PEM);
        if (ret != 1) {
                syslog(LOG_ERR, "Error loading private key: %s\n",
                        ssl_err(ret));
                _exit(EXIT_FAILURE);
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
                syslog(LOG_ERR, "Private key verification failure: %s.\n",
                        ssl_err(ret));
                _exit(EXIT_FAILURE);
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
}
