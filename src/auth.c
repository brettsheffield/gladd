/* 
 * auth.c - authentication functions
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

#include "auth.h"
#include "config.h"
#ifndef _NGLADDB
#include "gladdb/db.h"
#ifndef _NLDAP
#include "gladdb/ldap.h"
#endif /* _NLDAP */
#endif /* _NGLADDB */
#include "string.h"
#include "xml.h"
#include <errno.h>
#include <fnmatch.h>
#include <grp.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

struct pam_response *r;

int null_conv(int num_msg, const struct pam_message **msg,
struct pam_response **resp, void *appdata_ptr)
{
         *resp = r;
        return PAM_SUCCESS;
}

static struct pam_conv conv = {
        null_conv,
        NULL
};

int check_auth_pam(char *service, char *username, char *password)
{
        int ret;
        pam_handle_t *pamh = NULL;
        char *pass = strdup(password);

        ret = pam_start(service, username, &conv, &pamh);
        if (ret == PAM_SUCCESS) {
                r = (struct pam_response *)malloc(sizeof(struct pam_response));
                r[0].resp = pass;
                r[0].resp_retcode = 0;

                ret = pam_authenticate(pamh, 0);
                if (ret == PAM_SUCCESS) {
                        syslog(LOG_DEBUG,
                               "PAM authentication successful for user %s", username);
                }
                else {
                        if (config->debug) {
                                syslog(LOG_DEBUG, "PAM: %s",
                                        pam_strerror(pamh, ret));
                        }
                        syslog(LOG_ERR,
                                "PAM authentication failure for user %s",
                                username);
                }

        }
        pam_end(pamh, ret);
        return ( ret == PAM_SUCCESS ? 0:HTTP_UNAUTHORIZED );
}

/* 
 * check if authorized for requested method and url
 * default is to return 403 Forbidden
 * a return value of 0 is allow.
 */
int check_auth(http_request_t *r)
{
        acl_t *acls = malloc(sizeof (acl_t));
        acl_t *a = NULL;
        int i = 0;
        int pass = 0;
        http_status_code_t res = HTTP_FORBIDDEN;

	if (config->acls == NULL) {
		syslog(LOG_DEBUG, "No acls set.  Allow by default");
		return 0; /* allow if no acls set */
	}

        a = memcpy(acls, config->acls, sizeof (acl_t));
        while (a != NULL) {
                syslog(LOG_DEBUG, 
                        "Checking acls for %s %s ... trying %s %s", 
                        r->method, r->res, a->method, a->url);
                /* ensure method and url matches */
                if ((fnmatch(a->url, r->res, 0) == 0
                    && strncmp(r->method, a->method, strlen(r->method)) == 0)
                || (fnmatch(a->url, r->res, 0) == 0
                    && strcmp(a->method, "*") == 0))
                {
                        syslog(LOG_DEBUG,
                                "Found matching acl - checking credentials");

                        i = 0;

                        if (strcmp(a->type, "deny") == 0) {
                                syslog(LOG_DEBUG, "acl deny");
                                free(acls);
                                return HTTP_FORBIDDEN;
                        }
                        else if (strcmp(a->type, "params") == 0) {
                                if (strcmp(a->auth, "cookie:session") == 0) {
                                        syslog(LOG_DEBUG, "cookie");
                                        r->cookie = 1;
                                }
                                else if (strcmp(a->auth, "nocache") == 0) {
                                        syslog(LOG_DEBUG, "nocache");
                                        r->nocache = 1;
                                }
                                else if (strcmp(a->auth, "nofilter") == 0) {
                                        syslog(LOG_DEBUG, "nofilter");
                                        r->nofilter = 1;
                                }
                                else if (strcmp(a->auth, "htmlout") == 0) {
                                        syslog(LOG_DEBUG, "htmlout");
                                        r->htmlout = 1;
                                }
                                else if (strcmp(a->auth, "uuid") == 0) {
                                        syslog(LOG_DEBUG, "uuid");
                                        r->uuid = 1;
                                }
                                else {
                                        syslog(LOG_DEBUG,
                                        "Ignoring unknown param: %s", a->auth);
                                }
                        }
                        else if (strcmp(a->type, "allow") == 0) {
                                /* TODO: check for ip address */
                                syslog(LOG_DEBUG, "acl allow");
                                free(acls);
                                return 0;
                        }
                        else if (strcmp(a->type, "sufficient") == 0) {
                                syslog(LOG_DEBUG, "acl sufficient...");
                                /* if this is successful, no further checks */
                                i = check_auth_sufficient(a->auth, r);
                                if (i == 0) {
                                        syslog(LOG_DEBUG, "auth sufficient");
                                        free(acls);
                                        return i;
                                }
                                /* if we fail later, code is 401, not 403 */
                                res = HTTP_UNAUTHORIZED;
                        }
                        else if (strcmp(a->type, "optional") == 0) {
                                syslog(LOG_DEBUG, "acl optional...");
                                i = check_auth_alias(a->auth, r);
                        }
                        else if (strcmp(a->type, "require") == 0) {
                                syslog(LOG_DEBUG, "acl require ...");
                                /* this MUST pass, but do further checks */
                                i = check_auth_require(a->auth, r);
                                if (i != 0) {
                                        syslog(LOG_DEBUG, "auth require fail");
                                        free(acls);
                                        return i;
                                }
                                pass++;
                        }
                        else {
                                syslog(LOG_DEBUG,
                                "acl auth type '%s' not understood", a->type);
                                free(acls);
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }

                        /* skip forward a->skip acls if condition met */
                        if ((i == 0 && strcmp(a->skipon,"success")==0)
                        || (i != 0 && strcmp(a->skipon,"fail")==0)){
                                for (i=a->skip; i>0; i--) {
                                        a = a->next;
                                        if (a == NULL) {
                                                free(acls);
                                                return i; 
                                        }
                                }
                                continue;
                        }

                }
                a = a->next;
        }
        free(acls);
        if (pass > 0) return 0;
        syslog(LOG_DEBUG, "no acl matched");
        return res;
}

/* any auth will do */
int check_auth_sufficient(char *alias, http_request_t *r)
{
        auth_t *a;
        int i;

        if (strcmp(alias, "*") == 0) {
                a = config->auth;
                while (a != NULL) {
                        i = check_auth_alias(a->alias, r);
                        if (i == 0) {
                                return i; /* That'll do nicely */
                        }
                        a = a->next;
                }
        }
        else {
                return check_auth_alias(alias, r);
        }

        return HTTP_FORBIDDEN;
}

/* all auth MUST pass */
int check_auth_require(char *alias, http_request_t *r)
{
        auth_t *a;
        int i;
        
        if (strcmp(alias, "*") == 0) {
                /* all auth MUST succeed */
                a = config->auth;
                while (a != NULL) {
                        i = check_auth_alias(a->alias, r);
                        if (i != 0) {
                                return i; /* one failure is all it takes */
                        }
                        a = a->next;
                }
        }
        else {
                return check_auth_alias(alias, r);
        }

        return 0;
}

int check_auth_alias(char *alias, http_request_t *r)
{
        auth_t *a;

        if (! (a = getauth(alias))) {
                syslog(LOG_ERR, 
                        "Invalid alias '%s' supplied to check_auth_alias()",
                        alias);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        syslog(LOG_DEBUG, "checking alias %s", alias);

        if (strcmp(a->type, "cookie") == 0) {
                return check_auth_cookie(r, a);
        }
        else if (r->authuser == NULL) {
                syslog(LOG_DEBUG, "auth attempted with blank username");
                return HTTP_UNAUTHORIZED;
        }
        else if (strcmp(a->type, "group") == 0) {
                char *vgroup = strdup(a->db);
                char *url = strdup(r->res);
                replacevars(&vgroup, url);
                if (check_auth_group(r->authuser, vgroup)) {
                        syslog(LOG_DEBUG, "user %s in group %s",
                                r->authuser, vgroup);
                        free(url);
                        free(vgroup);
                        return 0;
                }
                else {
                        syslog(LOG_DEBUG, "user %s NOT in group %s",
                                r->authuser, vgroup);
                        free(url);
                        free(vgroup);
                        return HTTP_UNAUTHORIZED;
                }
        }
        else if (r->authpass == NULL) {
                syslog(LOG_DEBUG, "auth attempted with blank password");
                return HTTP_UNAUTHORIZED;
        }
#ifndef _NLDAP
        else if (strcmp(a->type, "ldap") == 0) {
                int res;
                /* test credentials against ldap */
                syslog(LOG_DEBUG, "checking ldap users");
                res = db_test_bind(getdb(a->db),
                        getsql(a->sql), a->bind,
                        r->authuser, r->authpass);
                if (res == -1) return HTTP_INTERNAL_SERVER_ERROR;
                if (res == -2) return HTTP_UNAUTHORIZED;
                return res;
        }
#endif
        else if (strcmp(a->type, "user") == 0) {
                /* test credentials against users */
                syslog(LOG_DEBUG, "checking static users");
                user_t *u;
                u = getuser(r->authuser);
                if (u == NULL) {
                        /* user not found */
                        syslog(LOG_DEBUG, "no static user match");
                        return HTTP_UNAUTHORIZED;
                }
                syslog(LOG_DEBUG, "matched static user");
                if ((strncmp(r->authpass, u->password,
                strlen(u->password)) != 0)
                || (strlen(r->authpass) != strlen(u->password)))
                {
                        /* password incorrect */
                        syslog(LOG_DEBUG, "password incorrect");
                        return HTTP_UNAUTHORIZED;
                }
        }
        else if (strcmp(a->type, "pam") == 0) {
                /* use pam authentication */
                syslog(LOG_DEBUG, "checking PAM authentication");
                return check_auth_pam(a->db, r->authuser, r->authpass);
        }
        else {
                syslog(LOG_ERR,
                        "Invalid auth type '%s' in check_auth_require()",
                        a->type);
                return HTTP_INTERNAL_SERVER_ERROR;
        }

        return 0;
}

/* return 1 if user in config-defined group, 0 if not */
int ingroup(char *user, char *group)
{
        group_t *g;
        user_t *m;

        g = getgroup(group);
        if (!g) {
                fprintf(stderr, "group not found\n");
                return -1;
        }

        m = g->members;
        while (m != NULL) {
                if (strcmp(m->username, user) == 0) return 1;
                m = m->next;
        }

        return 0;
}

/* check is user is in specified group
 * searches, static config-defined groups, then NSS
 * returns 1 if in group, 0 if not, or -1 on error */
int check_auth_group(char *username, char *groupname)
{
        /* check config groups first */
        if (ingroup(username, groupname) == 1) {
                return 1;
        }

        /* now search nsswitch groups */
        int ret = 0;
        char *member;
        int i = 0;
        struct group *g;
        if ((g = getgrnam(groupname))) {
                while ((member = g->gr_mem[i++])) {
                        if (strcmp(username, member) == 0) {
                                ret = 1;
                                break;
                        }
                }
        }
        endgrent();
        return ret;
}

/* return domain from Host header, with port stripped
 * NB: free() the returned char pointer when done */
char *auth_get_host()
{
	char *host = http_get_header(request, "Host");
	char *domain;
	int i;
	int dots = 0;
	int alpha = 0;
        if (host) {
		/* count dots and letters to give us a hint about Host */
		for (i=0; i< strlen(host); i++) {
			if (host[i] == '.') dots++;
			if (host[i] >= 'a' && host[i] <= 'z') alpha++;
		}
		if (dots > 0 && alpha == 0) {
			syslog(LOG_DEBUG, "Host headers appears to be ipv4");
			domain = calloc(1, sizeof (char));
		}
		else if (memchr(host, '.', strlen(host)) == NULL) {
			syslog(LOG_DEBUG, "Host header not a domain");
			domain = calloc(1, sizeof (char));
		}
		else if (memchr(host, '[', strlen(host)) != NULL) {
			syslog(LOG_DEBUG, "Host header appears to be ipv6");
			domain = calloc(1, sizeof (char));
		}
		else {
			asprintf(&domain, " Domain=.%s;", host);
		}
	}
	else {
		domain = calloc(1, sizeof (char));
	}
	
	/* if domain contains a port number, remove it */
	/* TODO: handle ipv6 addresses in Host
	 * eg. https://[dead:beef:cafe::1]:4443/ */
	char *port = memchr(domain, ':', strlen(domain));
	if (port != NULL) {
		syslog(LOG_DEBUG, "stripping port number from cookie domain");
		*port = ';';
		*(port+1) = '\0';
	}

	return domain;
}

/* set session cookie */
int auth_set_cookie(char **r, http_cookie_type_t type)
{
        /* we create the session cookie by concatenating:
         * <username> <timestamp> <nonce>
         * and encrypting this using the blowfish cipher and our key */
        char *nonce = randstring(64);
        time_t timestamp = time(NULL);
        char *dough;
        char *cookie;

        asprintf(&dough, "%s %li %s", request->authuser, (long)timestamp,
                nonce);
        free(nonce);
        cookie = encipher(dough);
        free(dough);

	char *domain = auth_get_host();
        syslog(LOG_DEBUG, "setting session cookie %s", cookie);
        http_insert_header(r, "Set-Cookie: SID=%s;%s Path=/; Secure; HttpOnly",
                cookie, domain);
	free(domain);
        free(cookie);

        return 0;
}

/* invalidate session cookie */
int auth_unset_cookie(char **r)
{
        syslog(LOG_DEBUG, "logout requested - invalidating session cookie");
	char *domain = auth_get_host();
	/* Use Expires with arbitrary value rather than Max-Age,
	 * as some browsers don't support Max-Age */
        http_insert_header(r,
	    "Set-Cookie: SID=logout;%s Path=/; Expires: Thu, 01 Dec 1994 16:00:00 GMT; Secure; HttpOnly", domain);
	free(domain);
        return 0;
}

int check_auth_cookie(http_request_t *r, auth_t *a)
{
        /* get the Cookie header (we only expect one) */
        char *cookie = http_get_header(r, "Cookie");
        if (!cookie) {
                syslog(LOG_DEBUG, "No Cookie header, skipping cookie auth");
                return HTTP_UNAUTHORIZED;
        }
        syslog(LOG_DEBUG, "attempting cookie auth");
        syslog(LOG_DEBUG, "cookie: %s", cookie);

        /* find the first cookie called SID, ignore any others */
        int p;
        int l = strlen(cookie);
        if (l < 80) {
                syslog(LOG_DEBUG, "cookie not found");
                return HTTP_UNAUTHORIZED;
        }
        for (p = 0; p < l-80; p++) {
                if (strncmp(cookie+p, "SID=", 4) == 0)
                        break;
        }
        if (p == l-80) {
                syslog(LOG_DEBUG, "SID Session cookie not found");
                return HTTP_UNAUTHORIZED;
        }
        char *tmp = malloc(l);
	errno = 0;
        int ret = sscanf(cookie+p, "SID=%[^;]", tmp);
	if (errno != 0) {
                syslog(LOG_DEBUG, "%s", strerror(errno));
                free(tmp);
                return HTTP_UNAUTHORIZED;
	}
        if (ret != 1) {
                syslog(LOG_DEBUG, "Session cookie not found");
                free(tmp);
                return HTTP_UNAUTHORIZED;
        }
	if (strlen(tmp) < 80) {
                syslog(LOG_DEBUG, "Session cookie has invalid length of %i",
			(int)strlen(tmp));
                free(tmp);
                return HTTP_UNAUTHORIZED;
	}
        /* decrypt cookie */
        char *clearcookie = decipher(tmp);
        free(tmp);
	if (!clearcookie) {
                syslog(LOG_DEBUG, "Failed to decipher cookie");
		free(clearcookie);
                return HTTP_UNAUTHORIZED;
	}

        /* check cookie is valid */
        char *username = malloc(l+1);
        char *nonce = malloc(l+1);
        long timestamp;
        if (sscanf(clearcookie, "%s %li %s",
        username, &timestamp, nonce) != 3)
        {
                syslog(LOG_DEBUG, "Invalid cookie");
                free(username); free(nonce);
		free(clearcookie);
                return HTTP_UNAUTHORIZED;
        }
        syslog(LOG_DEBUG, "Decrypted cookie: %s", clearcookie);
        free(nonce);
        free(clearcookie);

        /* check cookie freshness */
        long now = (long)time(NULL);
        if ((timestamp + config->sessiontimeout) < now) {
                syslog(LOG_DEBUG, "Stale cookie (older than %lis)",
                        config->sessiontimeout);
                free(username);
                return HTTP_UNAUTHORIZED;
        }

        /* set session info from cookie */
        syslog(LOG_INFO, "Valid cookie obtained for %s", username);
        syslog(LOG_DEBUG, "Setting username %s from session cookie", username);
        request->authuser = strdup(username);
        free(username);

        return 0;
}


/* Return blowfish-encrypted ciphertext using our secretkey */
char *encipher(char *cleartext)
{
        unsigned char *ciphertext = calloc(strlen(cleartext)+1, sizeof(char));
        int i;

        for (i=0; i< strlen(cleartext); i+=8) {
                BF_ecb_encrypt((unsigned char *)cleartext+i, ciphertext+i,
                        &config->ctx, BF_ENCRYPT);
        }

        /* blowfish may contain embedded nuls, so run it through base64 */
        char *base64 = encode64((char *)ciphertext, strlen(cleartext));

        return base64;
}

/* Return decrypted blowfish ciphertext (limit: 64 chars) */
char *decipher(char *base64)
{
        unsigned char *cleartext = calloc(strlen(base64)+1, sizeof(char));
        int i;

        /* first, strip base64 encoding */
        unsigned char *ciphertext = (unsigned char *)decode64(base64);

	if (!ciphertext) {
		syslog(LOG_DEBUG, "base64 decoding failed");
		return NULL;
	}

        for (i=0; i< 64; i+=8) {
                BF_ecb_encrypt(ciphertext+i, cleartext+i, &config->ctx,
                        BF_DECRYPT);
        }

        free(ciphertext);

        char *clear = strdup((char *)cleartext);

        return clear;
}
