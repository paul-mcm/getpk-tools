#ifndef CONFIG_H
#define CONFIG_H

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "parse_line.h"
#include "uri.h"

enum tls {
	TLS_FALSE,
        TLS_TRUE,
};

struct configuration {
	char		config_file[PATH_MAX + 1];
        char		*ldap_search_base;
	int		scope;
	int 		(*init_f)(LDAP **, char *);
	void		*(*srvr_thrdf)(void *);
        char 		*uri_string;
	int		uri_strlen;
        struct uri_list *uris;
	int		n_uris;
        char 		*ignores;
        size_t 		ignore_size;
        char 		**ignore_list;
        unsigned int	idle_timeout;	/* MAX IDLE CONNECTION OPEN */
	int		sock_fd;

	/* LDAP OPT SETTINGS */
        enum tls	use_tls;		/* YES/NO */
        char 		ca_certpath[PATH_MAX + 1];				
	int		net_timeout;		/* connect(2) TIMEOUT */
	int		srch_timelimit;		/* LDAP SEARCH TIMEOUT */
	int		sync_timeout;		/* SYNCHRONOUS CALL TIMEOUT */
};

int	read_config(struct configuration *, FILE *);
int	parse_line(char *, struct configuration *);
void	build_ignore_list(struct configuration *);
void	show_config(struct configuration *);
char	*cat_strings(char *, const char *);
void	set_cfg_defaults(struct configuration *);
int	validate_config(struct configuration *);
void	free_ignore_list(struct configuration *);
void	free_config(struct configuration *);
int	build_config(struct configuration *c);

#endif
