#ifndef GETPKD_H
#define GETPKD_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <ldap.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "ldap_call.h"
#include "uri.h"

/* RFC1274: MAX USERID LENGTH for LDAP schema attr type 0.9.2342.19200300.100.1.1 */
#define UNAME_MAX 256
#define SA struct sockaddr
#define LISTENQ 10

struct timespec ldap_ctime;
LDAP *ldap;
pthread_mutex_t ldap_lock;
pthread_mutex_t recovery_lock;
pthread_attr_t dflt_attrs;
pthread_attr_t serverthread_attrs;
pthread_t recthread_id;
int debug;

/* thread_args is ARG STRUCT THAT IS CAST TO void * WHEN PASSED TO EACH 
*  NEW THREAD.
*
*       ldap            -       LDAP SESSION HANDLE
*       timeout         -       IDLE CONNECTION TIMEOUT
*	rtrhead_id	-	THREAD ID OF THREAD USED FOR
*				CHECKING SERVERS REPORTED DOWN
*       ldap_lock_tstmp -       TIME STAMP FOR LDAP SESSION HANDLE
*       fd              -       DESCRIPTOR REFERENCING LOCAL UNIX SOCKET
*       cfg             -       PTR TO CONFIG STRUCT
*/

struct thread_args {
        LDAP *ldap;
        int timeout;
	pthread_t rthread_id;
        struct timespec ldap_lock_tstmp;
        int fd;
        struct configuration *cfg;
};

struct rec_thrd_data {
	LDAP			*l;
	LDAPMessage		*msg;
	int			cnt;
	char			**offline_hosts;
};

struct hostnames {
	int	cnt;
	char	**hosts;
};

enum recvry_states {
	NOT_DEGRADED,
	DEGRADED,
};

enum init_status {
	NEED_REINIT,
	INITED,
};

enum recvd_sighup_status {
	FALSE,
	TRUE,
};

enum recvry_states rec_status; 		/* REQUIRES recovery_lock MUTEX */
enum init_status reinit_status; 	/* REQUIRES ldap_lock MUTEX */
enum recvd_sighup_status sighup_status; /* DOES NOT REQUIRE LOCKING */

struct uri_callback_args {
	pthread_t		rthread_id;
	struct configuration	*cfg;
};

int	compare_time(struct timespec *);
void	*accept_thread(void *);
void	*query_thread(void *);
void	drop_privileges(void);
void	free_rec_thrd_data(void *);
void	free_targs(void *);
int	load_config(struct configuration *);
int	process_uri_list(LDAP *, LDAPURLDesc **, LDAPURLDesc **, void *);
int	reinit(struct configuration *, LDAP **);
int	remove_list_head(LDAP *);
void 	set_rec_status(pthread_t);
void 	set_reinit(void);
int	server(int, char *);
void 	*sigalrm_thrd(void *);
void	sigterm_handler();
void	*sighup_thrd(void *);
void	terminate(void);
void	term_sigalrm_thrd(void *);
void	unset_alarm(void *);
void	*uri_recovery_thrd(void *);
int	call_accept(int);
void	configure(struct configuration *);
int	do_search_failure(struct thread_args *);
int	do_result_failure(struct thread_args *);
int	intitializ(LDAP *, struct configuration *);
int	uristr_calloc(char *, int);

#endif
