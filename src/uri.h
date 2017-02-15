#ifndef URI_H
#define URI_H

#include <sys/param.h>
#include <sys/queue.h>
#include <errno.h>
#include <ldap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errorlog.h"

#define URI_MAX (MAXHOSTNAMELEN + 7)

pthread_rwlock_t urilist_lock;
int urilist_len;

enum srvr_status {
        OFFLINE,
        ONLINE
};

/* TAIL QUEUE OF LDAP SERVER URIS */
struct uri {
        char			uri[URI_MAX + 1];	/* LDAP SERVER URI */
        int			n;			/* ? */
        int			seq;			/* POSITION IN LIST */
        enum srvr_status	status;			/* UP OR DOWN */
        TAILQ_ENTRY(uri)	uris;
};

TAILQ_HEAD(uri_list, uri) uris_head;

/* ALL FUNCTIONS MUST BE CALLED WHILE HOLDING THE uri_list LOCK */
int	uri_tailq_creat(const char *);
void	uri_iterate_list(void);
int	uri_status(char *);
int	uri_set_offline(char *);
void	uri_setall_offline(void);
void	uri_set_online(char *);
int	uri_down_cnt(void);
int	uri_cnt(void);
int	uri_list_offline(char **);
void	uri_tailq_free(void);
int	uri_build_string(char *, int);
int	uri_listlen();

#endif
