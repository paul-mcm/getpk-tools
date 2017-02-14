#include "config.h"
#include <sys/stat.h>
#include <fcntl.h>

int build_config(struct configuration *c)
{
	FILE	*fptr;

        if ((fptr = fopen(c->config_file, "ro")) == NULL) {
	    log_ret("Failed to open config file %s %s", c->config_file, strerror(errno));
	    return -1;
	}
	
        if (read_config(c, fptr) < 0) {
	    log_msg("Error setting up configuration");
	    fclose(fptr);
	    return -1;
	} else {
	    fclose(fptr);
	    return 0;
	}
}

int read_config(struct configuration *cfg, FILE *fp)
{
	int 	n_bytes;
        char 	*line, *l;

        for (;;) {
	 
	    l = NULL;
	    line = NULL;

	    n_bytes = (line_byte_cnt(fp));

	    if (n_bytes == 1) {
		(void)fseek(fp, 1, SEEK_CUR);
		continue;
	    } else if (n_bytes == 0)
		return 0;

	    if ((line = malloc((size_t)(n_bytes + 1))) == NULL)
		/* FATAL */
		log_syserr("malloc error while reading config file", errno);

	    if ((l = fgets(line, n_bytes + 1, fp)) == NULL)
		if (feof(fp)) {
		    free(line);
		    return 0;
		} else
		    /* FATAL */
		    log_die("error calling fgets on config file", errno);

	    if (check_line(l) != 0) {
		free(line);
		continue;
	    }

	    if (parse_line(l, cfg) < 0) {
		log_msg("parsing config line failed\n");
		free(line);
		return(-1);
	    }
        }
}

int 
parse_line(char *l, struct configuration *cfg)
{
	char		*k = NULL, *v = NULL;	/* key -> value */
	const char	*errstr = NULL;

	while(isblank((int)l[0]) != 0) /* XXX HACK */
            l++;

	k = strsep(&l, "=");
	v = rm_space(l);
	rm_end_space(k);

	if (strcasecmp("IDLE_TIMEOUT", k) == 0) {
#ifdef BSD
	    cfg->idle_timeout = strtonum(v, 0, 600, &errstr);
		if (errstr) {
		    log_msg("Config error: Bad value for idle_timeout");
		    return(-1);
		}
#elif LINUX
	    cfg->idle_timeout = atoi(v);
#endif
	}
	if (strcasecmp("NETWORK_TIMEOUT", k) == 0) {
#ifdef BSD
	    cfg->net_timeout = strtonum(v, 0, 600, &errstr);
	    if (errstr != NULL) {
		log_msg("Config error: Bad value for network_timeout");
		return(-1);
	    }
#elif LINUX
	    cfg->net_timeout = atoi(v);	/*XXX NEEDS ERROR CHECKING? */
#endif
	}

	if (strcasecmp("SEARCH_TIMELIMIT", k) == 0) {
#ifdef BSD
	    cfg->srch_timelimit = strtonum(v, 0, 600, &errstr);
	    if (errstr != NULL) {
		log_msg("Config error: Bad value for search_timeout");
		return(-1);
	    }
#elif LINUX
	    cfg->srch_timelimit = atoi(v);
#endif
	}

	if (strcasecmp("SYNC_TIMEOUT", k) == 0) {
#ifdef BSD
	    cfg->sync_timeout = strtonum(v, 0, 600, &errstr);
	    if (errstr != NULL) {
		log_msg("Config error: Bad value for sync_timeout");
		return(-1);
	    }
#elif LINUX
	    cfg->sync_timeout = atoi(v);
#endif
	}

	if (strcasecmp("CA_CERTPATH", k) == 0) {
#ifdef BSD
	    strlcpy(cfg->ca_certpath, v, sizeof(cfg->ca_certpath));
#elif LINUX
	    strncpy(cfg->ca_certpath, v, sizeof(cfg->ca_certpath) - 1);
	    cfg->ca_certpath[strlen(cfg->ca_certpath)] = '\0';
#endif
	} else if (strcasecmp("URI", k) == 0)
	    cfg->uri_string = strdup(v);
		
	else if (strcasecmp("IGNORE", k) == 0)
  	    cfg->ignores = strdup(v);
	
	else if (strcasecmp("LDAP_SEARCHBASE", k) == 0) {
	    cfg->ldap_search_base = strdup(v);
	}
	else if (strcasecmp("SCOPE", k) == 0) {
	    if (strcasecmp("BASE", v) == 0)
		cfg->scope = LDAP_SCOPE_BASE;
	    else if (strcasecmp("ONELEVEL", v) == 0)
		cfg->scope = LDAP_SCOPE_ONELEVEL;
	    else if (strcasecmp("SUBTREE", v) == 0)
		cfg->scope = LDAP_SCOPE_SUBTREE;
	    else if  (strcasecmp("CHILDREN", v)== 0)
		cfg->scope = LDAP_SCOPE_CHILDREN;
	    else {
		log_msg("Config error: Bad scope option\n");
		return(-1);
	    }

	 } else if (strcasecmp("USE_TLS", k) == 0) {
	    if (strcasecmp("yes", v) == 0)
		cfg->use_tls = TLS_TRUE;
	    else if (strcasecmp("no", v) == 0)
		cfg->use_tls = TLS_FALSE;
	    else {
		log_msg("Config error: Bad tls options\n");
		return(-1);
	    }
	}

	return 0;
}

void build_ignore_list(struct configuration *c)
{
        int i;

        c->ignore_size = (size_t)cnt_elements(c->ignores, ",");

        char *ignores_list[c->ignore_size];

	if ((c->ignore_list = malloc((sizeof(char *) * c->ignore_size))) == NULL)
	    log_die("malloc failed allocation space for ignore_list", \
		strerror(errno));

        parse_string(c->ignores, ignores_list, ",");

        qsort(ignores_list, c->ignore_size, sizeof(char *), comp_string);

        for (i = 0; i < (int)c->ignore_size; i++)
	    if ((c->ignore_list[i] = strdup(ignores_list[i])) == NULL)
		log_die("strdup error building ignore list: %s", \
		    strerror(errno));
}

void show_config(struct configuration *c)
{
	int i;

	log_msg("config_file:\t\t%s", c->config_file);
        log_msg("ldap_search_base:\t%s", c->ldap_search_base);
	log_msg("scope:\t\t\t%d", c->scope);
        log_msg("uri_string:\t\t%s", c->uri_string);
	log_msg("uri_strlen:\t\t%d", c->uri_strlen);
        log_msg("ignores:\t\t%s", c->ignores);
        log_msg("ignore_size:\t\t%d", (int)c->ignore_size);

	log_msg("ignore list");
        for (i = 0; i < (int)c->ignore_size; i++)
	    log_msg("\t%s", c->ignore_list[i]);

        log_msg("idle_timeout:\t\t%u", c->idle_timeout);
        log_msg("use_tls:\t\t%d", c->use_tls);
        log_msg("ca_certpath:\t\t%s", c->ca_certpath);
	log_msg("net_timeout:\t\t%d", c->net_timeout);
	log_msg("srch_timelimit:\t\t%d", c->srch_timelimit);
	log_msg("sync_timeout:\t\t%d", c->sync_timeout);
}

void set_cfg_defaults(struct configuration *c)
{
	c->net_timeout = 10;
	c->srch_timelimit = 10;
	c->idle_timeout = 20;
	c->sync_timeout = 10;  /* USER CAN'T SET THIS */
	c->use_tls = TLS_FALSE;
	c->scope = LDAP_SCOPE_ONELEVEL;
}	

int validate_config(struct configuration *c)
{
	struct stat sb;	
	int fd;

	if (c->use_tls == TLS_TRUE && strlen(c->ca_certpath) == 0)
	    log_die("Path to CA Cert not defined");

	if (c->use_tls == TLS_TRUE && stat(c->ca_certpath, &sb) == -1)
	    log_syserr("Failed to stat CA certfile %s", c->ca_certpath, errno);

	if ((fd = open(c->ca_certpath, O_RDONLY)) == -1)
	    log_syserr("Can't read CA cert file %s", c->ca_certpath, errno);
	else
	    close(fd);

	if (c->ldap_search_base == NULL) {
	    log_msg("LDAP search base missing");
	    return(-1);
	}

	if (c->uri_string == NULL) {
	    log_msg("no LDAP servers given");
	    return(-1);
	}
	return 0;
}

void free_config(struct configuration *c)
{
        free(c->ldap_search_base);
        free(c->uri_string);
	uri_tailq_free();
	free(c->ignores);
	free_ignore_list(c);
};

void free_ignore_list(struct configuration *c)
{
	int i;

	for (i = 0; i < (int)c->ignore_size; i++) {
	    free(c->ignore_list[i]);
	    c->ignore_list[i] = NULL;
	}
}
