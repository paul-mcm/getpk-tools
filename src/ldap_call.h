#ifndef LDAP_CALL_H
#define LDAP_CALL_H

#include <errno.h>
#include <stdio.h>
#include <syslog.h>

#include <ldap.h>
#include "config.h"

#define TLS_OPT LDAP_OPT_X_TLS_NEVER

void	arg_fail(const char *);
void	opt_fail(int);
int	do_set_ldap_opts(struct configuration *);
int	do_ldap_init(LDAP **, char *);
int	do_ldap_tls_init(LDAP **, char *);
int	do_ldap_search(LDAP *, int, char *, char **);
int	process_result(int, LDAP *, LDAPMessage *, const char *);
void	get_head_url(LDAP *, char *);
int	get_refcnt(LDAP *);
int	init_ldap_handle(LDAP **, struct configuration *, char *);
void	free_lobj(void *);
void	log_ldap_quit(char *, int);
void	log_ldap_msg(char *, int);

#endif
