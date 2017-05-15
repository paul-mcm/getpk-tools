#ifdef FreeBSD
#define _WITH_DPRINTF
#endif

#include "ldap_call.h"

int init_ldap_handle(LDAP **l, struct configuration *c, char *uri)
{
	int r;

	if ((r = c->init_f(l, uri)) != 0) {
	    l = NULL;
	    return r;
	} else
	    return 0;
}

int do_ldap_init(LDAP **l, char *u)
{
	int r;

        if ((r = ldap_initialize(l, u)) != LDAP_SUCCESS) {
	    log_die("Init ldap handle failed: %s", ldap_err2string(r));
            return(-1);
        }
	return(0);
}

int do_ldap_tls_init(LDAP **l, char *u)
{
	int r;

	if (do_ldap_init(l, u) < 0)
	    return(-1);

	if ((r = ldap_start_tls_s(*l, NULL, NULL)) != LDAP_SUCCESS) {
	    /* NON FATAL ERROR */
	    log_msg("TLS initializatin failed: %d %s", r, ldap_err2string(r));
	    return(r);
	}
        return(0);
}

int do_ldap_search(LDAP *l, int scope, char *filter, char **attrs)
{
	int result_n;
	int mid;

	/* NON FATAL ERRORS */
        if (ldap_search_ext(l, NULL, scope, filter, attrs, 0, NULL, NULL, NULL, \
	    LDAP_NO_LIMIT, &mid) < 0) {
	    (void)ldap_get_option(l, LDAP_OPT_RESULT_CODE, &result_n);

	    log_msg("ldap search error. %d %s", result_n, ldap_err2string(result_n));
	    return(-1);
        }

	return mid;
}

/* THESE SHOULD BE FATAL ERRORS */
int do_set_ldap_opts(struct configuration *c)
{
	const struct timeval n_to = { c->net_timeout, 0 };
        const struct timeval sync_to = { c->sync_timeout, 0 };
	int v = LDAP_VERSION3;
	int tls = TLS_OPT;
	int r;

	if ((r = ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &v)) \
	    != LDAP_OPT_SUCCESS) {
            log_ldap_quit("error setting protocl version.", r);
            return(-1);
        }

        if ((r = ldap_set_option(NULL, LDAP_OPT_DEFBASE, c->ldap_search_base)) \
	    != LDAP_OPT_SUCCESS) {
            log_ldap_quit("error setting DEFBASE.", r);
            return(-1);
        }

        if ((r = ldap_set_option(NULL, LDAP_OPT_TIMELIMIT, &c->srch_timelimit)) \
	    != LDAP_OPT_SUCCESS) {
            log_ldap_quit("error setting TIMELIMIT", r);
            return(-1);
        }

	if ((r = ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &n_to)) \
	    != LDAP_OPT_SUCCESS) {
            log_ldap_quit("error setting NETWORK_TIMEOUT.", r);
            return(-1);
        }

        if ((r = ldap_set_option(NULL, LDAP_OPT_TIMEOUT, &sync_to)) \
	    != LDAP_OPT_SUCCESS) {
            log_ldap_quit("error setting TIMEOUT.", r);
            return(-1);
        }

        /* Set TLS Option */
	if (c->use_tls == TLS_TRUE) {
	    if ((r = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, \
		c->ca_certpath)) != LDAP_OPT_SUCCESS) {
		log_ldap_quit("error setting CACERTFILE location.", r);
		return(-1);
	    }

	    if ((r = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, \
		&tls)) != LDAP_OPT_SUCCESS) {
		log_ldap_quit("error setting REQUIRE_CERT.", r);
		return(-1);
	    }
	}
	return 0;
}

int process_result(int d, LDAP *l, LDAPMessage *m, const char *a)
{
	LDAPMessage *entry;
        struct berval **vals;
	int i, r;

	if ((entry = ldap_first_entry(l, m)) == NULL) {
	    log_msg("error processing LDAP response");
	    return(-1);
	}

	if ((vals = ldap_get_values_len(l, entry, a)) != NULL) {
	    for (i = 0; vals[i] != NULL; i++) {
		if ((r = dprintf(d, "%s\n", vals[i]->bv_val)) < 0) {
		    log_msg("error writing response to descripton: %d" );
		    ldap_value_free_len(vals);
		    return(-1);
		}
	    }	

	    ldap_value_free_len(vals);
	}

	return 0;
}

void get_head_url(LDAP *l, char *u)
{
	/* u points area w/ length of URI_MAX + 1 */

	LDAPURLDesc *lud;
	char *urllist;
	char *u_ptr;
	char *f_ptr;

	ldap_get_option(l, LDAP_OPT_URI, &urllist);
	f_ptr = ldap_strdup(urllist);
	u_ptr = f_ptr;

 	ldap_url_parse(strsep(&u_ptr, " "), &lud);
#ifdef BSD
	strlcpy(u, lud->lud_host, URI_MAX + 1);
#elif LINUX
	strncpy(u, lud->lud_host, URI_MAX);
	u[strlen(u)] = '\0';
#endif
	ldap_free_urldesc(lud);
	free(f_ptr);
	ldap_memfree(urllist);
}

int get_refcnt(LDAP *l)
{
	int cnt = 0;

	if (ldap_get_option(l, LDAP_OPT_SESSION_REFCNT, &cnt) != LDAP_OPT_SUCCESS)
		return -1;
	else
		return cnt;
}

void free_lobj(void *l)
{
	int r;

	if (get_refcnt((LDAP *)l) > 0)
	    if ((r = ldap_destroy((LDAP *)l)) != LDAP_SUCCESS)
		log_msg("ERROR: failed to destroy LDAP handle: %s", \
		    ldap_err2string(r));
}

void log_ldap_quit(char *s, int n) {
        syslog(LOG_ERR, "fatal ldap error: %s %d - %s\n", n, \
            ldap_err2string(n));
        exit(-1);
}

void log_ldap_msg(char *s, int n) {
        syslog(LOG_ERR, "ldap error: %s %d\n", s, n, ldap_err2string(n));
}
