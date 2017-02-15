#include "uri.h"
#include "string.h"

/* ALL FUNCTIONS MUST BE CALLED WHILE HOLDING THE uri_list LOCK */

int uri_tailq_creat(const char *uri_string)
{
        char		*uri_str, *uid;
        struct uri 	*uri_strct;
	const char 	delims[] = " \t";
        int 		i = 1;
	struct uri 	*u;

	uri_str = strndup(uri_string, strlen(uri_string));

        while ((uid = strsep(&uri_str, delims)) != NULL) {
	    if (uid[0] == '\0')
		continue;

	    if ((uri_strct = malloc(sizeof(struct uri))) == NULL) {
		log_ret("malloc failed while building uri list", errno);
#ifdef BSD
		while ((u = TAILQ_FIRST(&uris_head))) {
		    TAILQ_REMOVE(&uris_head, u, uris);
		    free(u);
		}
#elif LINUX
		while (uris_head.tqh_first != NULL)
		    TAILQ_REMOVE(&uris_head, uris_head.tqh_first, uris);
#endif
		free(uri_str);
		return(-1);
	    }

	    strncpy(uri_strct->uri, uid, strlen(uid) + 1);
	    uri_strct->seq = i;
	    uri_strct->status = ONLINE;

	    TAILQ_INSERT_TAIL(&uris_head, uri_strct, uris);
	    i++;
        }

	free(uri_str);
	return i;
}

void uri_tailq_free()
{
	struct uri *u;

#ifdef BSD
	while ((u = TAILQ_FIRST(&uris_head))) {
	    TAILQ_REMOVE(&uris_head, u, uris);
	    free(u);
     	}

#elif LINUX
	while (uris_head.tqh_first != NULL)
           TAILQ_REMOVE(&uris_head, uris_head.tqh_first, uris);
#endif
}

void uri_iterate_list(void)
{
        struct uri *u;

	TAILQ_FOREACH(u, &uris_head, uris)
	    log_msg("URI: %s STATUS: %d", u->uri, u->status);

}

int uri_listlen(void)
{
	int l;
        struct uri *u;

	/*
	 * Calculate number of bytes requried for a NULL terminated, 
	 * space separated list if LDAP URIs   
	 */

	TAILQ_FOREACH(u, &uris_head, uris) {
#ifdef DEBUG
	    log_msg("URI: %s STATUS: %d", u->uri, u->status);
#endif
	    l += strlen(u->uri);
	}

	return l + uri_cnt();
}

int uri_status(char *h)
{
	char uri_str[URI_MAX + 1] = "ldap://";
        size_t len = strlen(uri_str);
        struct uri *u;
	int r;

	TAILQ_FOREACH(u, &uris_head, uris) {
	    uri_str[len] = '\0';
#ifdef BSD
	    strlcat(uri_str, h, URI_MAX + 1);
	    if (strcmp(u->uri, uri_str) == 0) {
#elif LINUX
	    if (strcmp(u->uri, strncat(uri_str, h, URI_MAX - strlen(uri_str))) == 0) {
#endif
		if (u->status == OFFLINE)
		    return 0;
		else
		    return 1;
	    }
	}

	return r;
}

void uri_setall_offline(void)
{
	struct uri *u;
	TAILQ_FOREACH(u, &uris_head, uris)
		u->status = OFFLINE;
}

int uri_set_offline(char *h)
{
	char uri_str[URI_MAX + 1] = "ldap://";
	struct uri *u;

	TAILQ_FOREACH(u, &uris_head, uris) {
	    uri_str[7] = '\0';
#ifdef BSD		
	    strlcat(uri_str, h, URI_MAX + 1);
	    if (strcmp(u->uri, uri_str) == 0) {
#elif LINUX
	    if (strcmp(u->uri, strncat(uri_str, h, URI_MAX - strlen(uri_str))) == 0) {
#endif
		u->status = OFFLINE;
		break;
	    }
	}
	return 0;
}

void uri_set_online(char *h)
{
	struct uri *u;

	TAILQ_FOREACH(u, &uris_head, uris) {		
	    if (strcmp(u->uri, h) == 0) {
		u->status = ONLINE;
		break;
	    }
	}
}

int uri_down_cnt()
{
	struct uri *u;
	int n = 0;

        TAILQ_FOREACH(u, &uris_head, uris) {
	    if (u->status == OFFLINE)
		n++;
	}

	return n;
}

int uri_cnt()
{
	struct uri *u;
	int n = 0;

        TAILQ_FOREACH(u, &uris_head, uris)
	    n++;

	return n;
}

int uri_list_offline(char **l)
{
	int i = 0;
	struct uri *u;

        TAILQ_FOREACH(u, &uris_head, uris) {
	    if (u->status == OFFLINE) {
		l[i] = strndup(u->uri, URI_MAX);
        	i++;
	    }
	}

	return i;
}

int uri_build_string(char *str, int len)
{
	/* len param includes space for NULL termination */

	int c, i;
	struct uri *u;
	str[0] = '\0';

	i = 1;
	c = uri_cnt();

	if (c == uri_down_cnt())	/* All servers offline */
	    return -1;

        TAILQ_FOREACH(u, &uris_head, uris) {
	    if (u->status == ONLINE) {
#ifdef BSD
		strlcat(str, u->uri, len);
		if (i < c) {
		    strlcat(str, " ", len);
		    i++;
		}
#elif LINUX
		strncat(str, u->uri, len - 1 - strlen(str));
		if (i < c) {
		    strncat(str, " ", len - 1 - strlen(str));
		    i++;
		}		
#endif
	    }
	}
	return c;
}
