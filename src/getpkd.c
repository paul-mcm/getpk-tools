#include "getpkd.h"

char sock_path[] = "/tmp/getpkd/getpkd.sock";
char sock_dir[] = "/tmp/getpkd";
char *attrs[] = { "authkey", '\0' };

int main(int argc, char *argv[])
{
	struct sockaddr_un 	servaddr;
	struct rlimit 		rlim_ptr;
	int 			fd, i, c, r;
	mode_t			old_umask;
	char			config_file[PATH_MAX + 1] = "/etc/getpkd.conf\0";

	debug = 0;

	log_open(argv[0], LOG_PID, LOG_DAEMON);

	if (argc > 1) {
	    while ((c = getopt (argc, argv, "df:")) != -1)  {   
		switch (c) {
		case 'd':
		    debug = 1;
		    break;
		case 'f':
#ifdef BSD
		    strlcpy(config_file, optarg, sizeof(config_file));
#elif LINUX
		    strncpy(config_file, optarg, sizeof(config_file) - 1);
		    config_file[strlen(config_file)] = '\0';			
#endif
		    break;
		case '?':
		    log_die("Unknown option in arg string");  
		    exit(-1);
		default:
		    abort();
		}
	    }
	}

        if (getrlimit(RLIMIT_NOFILE, &rlim_ptr) < 0)
	    log_syserr("rlimit failed %d", errno);

        for (i = 3; i <= (int)rlim_ptr.rlim_cur; i++)
	    close(i);

	if (debug == 0)	
	    if (daemon(0, 0) < 0)
		log_die("Failed to daemonize", errno);

	if (signal(SIGTERM, sigterm_handler) == SIG_ERR)
	    log_syserr("Failed to set SIGTERM handler:", errno);

	if (signal(SIGINT, sigterm_handler) == SIG_ERR)
	    log_syserr("Failed to set SIGINT handler:", errno);

	if (signal(SIGABRT, sigterm_handler) == SIG_ERR)
	    log_syserr("Failed to set SIGINT handler:", errno);

        if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
	    log_syserr("Failed to create listening socket:", errno);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, sock_path);

 	drop_privileges(); /* CALLS PLEDGE */

	if (connect(fd, (SA *) &servaddr, (socklen_t)sizeof(servaddr)) == 0)
	    log_die("Error: listing socket already listening");

	if (unlink(sock_path) == -1 && errno != ENOENT)
	    log_syserr("Failed do unlink socket:", errno);

	if (rmdir(sock_dir) == -1 && errno != ENOENT)
	    log_syserr("Failed to setup sock dir", errno);

	if (mkdir(sock_dir, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) == -1)
	    log_syserr("Failled to create sock dir", errno);

	old_umask = umask(S_IXUSR|S_IXGRP|S_IXOTH);

	if (bind(fd, (SA *) &servaddr, (socklen_t)sizeof(servaddr)) < 0) {
	    (void)umask(old_umask);
	    log_syserr("Error binding to socket:", errno);
	}

	(void)umask(old_umask);

	if (chmod(sock_path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) == -1) {
	    (void)umask(old_umask);
	    log_syserr("chmod error: %d %s", errno, strerror(errno));
	}

	if (listen(fd, LISTENQ) < 0)
	    log_syserr("Call to listen call failed:", errno);

	for (;;) {
	    if (server(fd, config_file) == 0) {
		terminate();
		exit(0);
	    }
	    else {
		log_msg("server function returned non-zero");

#ifdef DEBUG
		if (r != 0 && r == EBUSY)
		    log_msg("mutex ldap_lock still busy");
#endif
		r = pthread_rwlock_destroy(&urilist_lock);
#ifdef DEBUG
		if (r != 0 && r == EBUSY)
		    log_msg("rwlock urilist_lock still busy");
#endif
		terminate();
		return(-1);
	    }
	}
}

int server(int fd, char *cfg_file)
{
	int			r;
	pthread_t		hupthread_id;
	pthread_t		acceptthread_id;
	struct configuration	config = {0};
	struct configuration 	*cfg_ptr = &config;	
	sigset_t		sig_set;

	memset(&config, 0, sizeof(struct configuration));

#ifdef OPENBSD
	if (pledge("stdio rpath inet cpath", NULL) == -1)
	    log_syserr("pledge failure %s", strerror(errno));
#endif
        if ((r = pthread_attr_init(&dflt_attrs)) != 0)
	    log_die("Error initing thread attrs: %d\n", r);

	if ((r = pthread_attr_init(&serverthread_attrs)) != 0)
	    log_die("Error initing thread hup attrs: %d\n", r);

        if ((r = pthread_attr_setdetachstate(&dflt_attrs, \
	    PTHREAD_CREATE_DETACHED)) != 0)
		log_die("Error setting thread state: %d\n", r);

	if ((r = pthread_attr_setdetachstate(&serverthread_attrs, \
	    PTHREAD_CREATE_JOINABLE)) != 0)

	if ((r = pthread_mutex_init(&ldap_lock, NULL)) != 0)
	    log_die("Error initing thread mutex: %d", r);

	if ((r = pthread_mutex_init(&recovery_lock, NULL)) != 0)
	    log_die("Error initing thread mutex: %d", r);

	if ((r = pthread_rwlock_init(&urilist_lock, NULL)) < 0)
	    log_syserr("Failed to init urilist_lock rwlock:", errno);

	TAILQ_INIT(&uris_head);

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGUSR1);
 	sigaddset(&sig_set, SIGALRM);
 	sigaddset(&sig_set, SIGPIPE);
	sigaddset(&sig_set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sig_set, NULL);
#ifdef BSD
	strlcpy(cfg_ptr->config_file, cfg_file, sizeof(cfg_ptr->config_file));
#elif LINUX
	strncpy(cfg_ptr->config_file, cfg_file, sizeof(cfg_ptr->config_file) - 1);
	cfg_ptr->config_file[strlen(cfg_ptr->config_file)] = '\0';
#endif
	set_cfg_defaults(cfg_ptr);
	cfg_ptr->uris = &uris_head;
	cfg_ptr->sock_fd = fd;

	/* BEGIN READING CONFIG */
	configure(cfg_ptr);

#ifdef DEBUG
	show_config(&config);
#endif
	pthread_mutex_lock(&recovery_lock);
	rec_status = NOT_DEGRADED;
	pthread_mutex_unlock(&recovery_lock);

	/* END CONFIG */

	/* START URI RECOVERY THREAD */
	if (pthread_create(&recthread_id, &dflt_attrs, uri_recovery_thrd, \
	    (void *) cfg_ptr) != 0)
		log_die("FAiled to start uri recovery thread: %s", strerror(errno));

	if (ldap_set_urllist_proc(NULL, process_uri_list, (void *)recthread_id) \
	    == LDAP_OPT_ERROR)
		log_die("Error setting urllist proc");

	for (;;)
	{
	    /* START MAIN LISTENING THREADS */
	    if (pthread_create(&acceptthread_id, &serverthread_attrs, accept_thread, \
		(void *) cfg_ptr) != 0)
		    log_die("Failed to start server thread: %s", strerror(errno));

	    /* START SIGHUP THREAD */
	    if (pthread_create(&hupthread_id, &dflt_attrs, sighup_thrd, (void *)acceptthread_id) != 0)
		log_die("FAiled to start sighup thread", errno);

	    /*
	     * ********************
	     * BLOCK ON SUCCESS
	     * ********************
	     */

	    if (pthread_join(acceptthread_id, NULL) != 0)
		log_die("pthread_join failed\n");

	    if (sighup_status == TRUE) {
		log_msg("RECVD SIGHUP");
		if (ldap != NULL && get_refcnt(ldap) >= 0)
		    ldap_destroy(ldap);
		free_config(cfg_ptr);
		configure(cfg_ptr);
#ifdef DEBUG
		show_config(cfg_ptr);
#endif
		uri_iterate_list();
		sighup_status = FALSE;
		continue;
	    } else {
		log_msg("Unexpected return from server thread");
		pthread_attr_destroy(&dflt_attrs);
		pthread_attr_destroy(&serverthread_attrs);
		pthread_cancel(recthread_id);

		pthread_mutex_lock(&ldap_lock);
		free_config(cfg_ptr);
		pthread_mutex_unlock(&ldap_lock);

		pthread_mutex_destroy(&ldap_lock);
		pthread_rwlock_destroy(&urilist_lock);
		pthread_mutex_destroy(&recovery_lock);

		log_msg("MAIN SRVR THREAD RETURNING");
		return(-1);
	    }
	}
}

void * accept_thread(void *cfg)
{
	int 		fd, r;
	pthread_t 	thread_id;
	pthread_t 	alrmthread_id = {0};

	struct thread_args *t_args;
	struct configuration *c = (struct configuration *)cfg;

	ldap_ctime.tv_sec = 0;
	ldap_ctime.tv_nsec = 0;

	pthread_mutex_lock(&ldap_lock);
	set_reinit();
	ldap = NULL;
	pthread_mutex_unlock(&ldap_lock);
	
	if (pthread_create(&alrmthread_id, &dflt_attrs, &sigalrm_thrd, (void *) ldap) != 0)
	     log_ret("Failed to create sigalrm thread:", errno);

	pthread_cleanup_push(term_sigalrm_thrd, (void *) &alrmthread_id);

	/* MAIN LOOP */
	for (;;) {
	    t_args = NULL;
	    if ((fd = call_accept(c->sock_fd)) < 0)
		continue;

	    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

  	    if ((t_args = malloc(sizeof(struct thread_args))) == NULL) {
		log_ret("malloc error after accept", errno);
		close(fd);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		continue;
	    }

	    memset(t_args, 0, sizeof(struct thread_args));
	    pthread_mutex_lock(&ldap_lock);

	    if (reinit_status == NEED_REINIT) {
		pthread_rwlock_wrlock(&urilist_lock);
		r = uri_build_string(c->uri_string);
		pthread_rwlock_unlock(&urilist_lock);
		if (r < 1) {
		    log_msg("Reinit ldap handle failed: All servers offline");
		    pthread_mutex_unlock(&ldap_lock);
		    goto do_cleanup;
		}
	    }

	    /* CONCURRENT CASE */
	    if (c->idle_timeout != 0) {
		if (reinit_status == NEED_REINIT) {
		    if (ldap != NULL && get_refcnt(ldap) >= 0)
			ldap_destroy(ldap);

		    if (initialize(&ldap, c) != 0) {
			ldap = NULL;
			pthread_mutex_unlock(&ldap_lock);
			goto do_cleanup;
		    }

		    clock_gettime(CLOCK_REALTIME, &ldap_ctime);
		    reinit_status = INITED;
		    t_args->ldap_lock_tstmp = ldap_ctime;
		}

		if ((t_args->ldap = ldap_dup(ldap)) == NULL) {
		    log_ret("ldap dup error:", errno);
		    ldap_destroy(ldap);
		    ldap = NULL;
		    pthread_mutex_unlock(&ldap_lock);
		    goto do_cleanup;
		}

		t_args->ldap_lock_tstmp = ldap_ctime;
  		pthread_mutex_unlock(&ldap_lock);

	    /* ITERATIVE CASE */
	    } else {
		if (initialize(&ldap, c) != 0) {
		    ldap = NULL;
		    pthread_mutex_unlock(&ldap_lock);
		    goto do_cleanup;	    
		} else {
		    reinit_status = INITED;
		    pthread_mutex_unlock(&ldap_lock);
		}

		if ((t_args->ldap = ldap_dup(ldap)) == NULL) {
		    log_ret("ldap dup error:", errno);
		    ldap_destroy(ldap);
		    ldap = NULL;
		    goto do_cleanup;
		}
	    }

	    t_args->fd = fd;
	    t_args->cfg = c;
	    t_args->rthread_id = recthread_id;

	    if (pthread_create(&thread_id, &dflt_attrs, &query_thread, \
		(void *) t_args) != 0) {
		    log_ret("Failed to create thread to handle request:", errno);
		    ldap_destroy(t_args->ldap);
		    if (c->idle_timeout != 0) {
			pthread_mutex_lock(&ldap_lock);
			ldap_destroy(ldap);
			ldap = NULL;
			pthread_mutex_unlock(&ldap_lock);
		    }
		    goto do_cleanup;
	    } else {
		if (c->idle_timeout == 0) {
		    ldap_destroy(ldap);
		    ldap = NULL;
		}
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		continue;
	    }

	do_cleanup:
	    close(fd);
	    free(t_args);
	    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	} /* END MAIN LOOP */

	pthread_exit(NULL);
	pthread_cleanup_pop(0);
}

void * query_thread(void *a)
{
	LDAPMessage		*msg;
	struct thread_args	*args;
        char			uid[UNAME_MAX];
	char			fltr[UNAME_MAX + 4] = "uid=";
	char			*key = uid;
	ssize_t			nread;
	int			msgid, r;

	args = (struct thread_args *) a;

	pthread_cleanup_push(free_targs, args);

	/* READ AT MOST UNAME_MAX BYTES */
	if ((nread = read(args->fd, uid, UNAME_MAX)) < 0) {
	    log_ret("Error reading from socket:", errno);
	    pthread_exit(NULL);
	}

	uid[nread + 1] = '\0';

#ifdef BSD
	strlcat(fltr, uid, sizeof(uid));
#elif LINUX
	strncat(fltr, uid, UNAME_MAX); 
#endif
	if (bsearch(&key, args->cfg->ignore_list, args->cfg->ignore_size, \
	    sizeof(char *), comp_string) != NULL) {
		ldap_destroy(args->ldap);
		pthread_exit(NULL);
	}

	for (;;) {
	    if ((msgid = do_ldap_search(args->ldap, args->cfg->scope, fltr, \
		attrs)) < 0) {
	
		if (args->cfg->idle_timeout != 0 && compare_time(&args->ldap_lock_tstmp) == 0) {
		    /* JUST REINIT LOCAL LDAP HANDLE */
		    ldap_destroy(args->ldap);
		    if (reinit(args->cfg, &args->ldap) == 0)
			continue;
		    else
			pthread_exit(NULL);
		}

		if (do_search_failure(args) == 0)
		    continue;
		else {
		    pthread_exit(NULL);
		}
	    }

	    if ((r = ldap_result(args->ldap, msgid, 1, NULL, &msg)) <= 0) {
		ldap_msgfree(msg);
		if (do_result_failure(args) == 0)
		    continue;
		else {
		    pthread_exit(NULL);
		}
	    }
	    /* SUCCESS */	
 	    /* log_msg("SUCCESS"); */
	    break;
	}

	if (ldap_count_entries(args->ldap, msg) > 0)
	    if (process_result(args->fd, args->ldap, msg, attrs[0]) < 0)
		log_msg("Error writing response");

	ldap_destroy(args->ldap);
	ldap_msgfree(msg);

	if (args->cfg->idle_timeout != 0)
	    if (alarm(args->cfg->idle_timeout) < 0)
		log_die("Error calling alarm: %s", strerror(errno));
	
	pthread_exit(NULL);
	pthread_cleanup_pop(0);
}

void *uri_recovery_thrd(void *cfg)
{
	LDAP			*l;
	struct rec_thrd_data	t_data = {0};
	struct configuration	*c = (struct configuration *) cfg;
	sigset_t		sig_set;
	int			msgid, sig, status, r;
	int			cnt, i;

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGUSR1);
	struct uri		*u;

	t_data.offline_hosts = calloc(c->n_uris, sizeof(char *));
	pthread_cleanup_push(free_rec_thrd_data, (void *)&t_data);

	for (;;) {
	    t_data.cnt = 0;
	    sigwait(&sig_set, &sig);
	    log_msg("URI THREAD AWAKENED");

	    pthread_rwlock_rdlock(&urilist_lock);
	    cnt = uri_down_cnt();
	    pthread_rwlock_unlock(&urilist_lock);	

	    while (cnt > 0) {
		status = 0;

		pthread_rwlock_rdlock(&urilist_lock);
		t_data.cnt = uri_list_offline(t_data.offline_hosts);	
		pthread_rwlock_unlock(&urilist_lock);

		for (i = 0; i < t_data.cnt; i++) {
		    if (init_ldap_handle(&l, c, t_data.offline_hosts[i]) < 0) {
			free_lobj(l);
			continue;
		    }

		    if ((msgid = do_ldap_search(l, LDAP_SCOPE_BASE, NULL, NULL)) < 0) {
			free_lobj(l);
			continue;
		    }

		    if ((r = ldap_result(l, msgid, 1, NULL, &t_data.msg)) > 0) {
			/* SUCCESS */
			log_msg("LDAP server %s restored", t_data.offline_hosts[i]);

			pthread_rwlock_wrlock(&urilist_lock);
			uri_set_online(t_data.offline_hosts[i]);
			pthread_rwlock_unlock(&urilist_lock);

			pthread_mutex_lock(&ldap_lock);
			set_reinit();
			pthread_mutex_unlock(&ldap_lock);

		    } else if (r == 0) {
			log_msg("Timed out waiting for %s\n", t_data.offline_hosts[i]);
		    } else {
			log_msg("Defunct: some other error\n");
		    }
		    free_lobj(l);
		    ldap_msgfree(t_data.msg);
		}

		for (i = 0; i < t_data.cnt; i++) {
		    free(t_data.offline_hosts[i]);
		    t_data.offline_hosts[i] = NULL;
		}
		pthread_rwlock_rdlock(&urilist_lock);
		cnt = uri_down_cnt();
		pthread_rwlock_unlock(&urilist_lock);

		sleep(20);
	    }
	    pthread_mutex_lock(&recovery_lock);

	    if (rec_status == DEGRADED)
		rec_status = NOT_DEGRADED;
	    else
		log_msg("Inconsistancy error for rec_stats");			
	    	
	    pthread_mutex_unlock(&recovery_lock);	
	}
	pthread_cleanup_pop(0);
}

void * sighup_thrd(void *tid)
{
	int		sig;
	sigset_t	sig_set;
	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGHUP);
	sigwait(&sig_set, &sig);

	sighup_status = TRUE;
	if (pthread_cancel((pthread_t) tid) != 0)
	    log_msg("ERROR CANCELING TRHEAD FROM SIGALRM HANDLER");
	pthread_exit(NULL);
}

void configure(struct configuration *c)
{
	int msize;

	pthread_rwlock_wrlock(&urilist_lock);
	set_cfg_defaults(c);

	if (load_config(c) != 0)
	    log_die("Error in configuration");
	if (validate_config(c) < 0)
	    log_die("Invalid config");
	if (uri_tailq_creat(c->uri_string) < 0)
	    log_die("Error building URI list");

	c->n_uris = uri_cnt();

	/*
	 * malloc enough mem for string of uris plus white
	 * space between each uri.
	 */
	msize = (URI_MAX) * (c->n_uris) + c->n_uris - 1;

	if ((c->uri_string = malloc(msize)) == NULL)
	    log_syserr("Malloc failure", errno);

	memset(c->uri_string, 0, msize);
	

	if (do_set_ldap_opts(c) != 0)
	    log_die("Failed to set LDAP options");

	pthread_rwlock_unlock(&urilist_lock);
}

void * sigalrm_thrd(void *l)
{
	sigset_t	sig_set;
	int 		r, sig;
	int 		cnt;

	pthread_cleanup_push(unset_alarm, NULL);

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGALRM);

	for (;;) {
	    sigwait(&sig_set, &sig);
	    (void)pthread_mutex_lock(&ldap_lock);

	    if (get_refcnt(ldap) > 0) {
#ifdef DEBUG
		log_msg("Destroying idle ldap handle\n");
#endif
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		free_lobj(ldap);
		ldap = NULL;
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	    }
	    set_reinit();
	    (void)pthread_mutex_unlock(&ldap_lock);
	}
	pthread_cleanup_pop(0);
}

int load_config(struct configuration *c)
{
	if (build_config(c) < 0)
	    return -1;

	if (c->ignores != NULL)
	    if (strlen(c->ignores))
		build_ignore_list(c);

	/* SET MORE DEFAULTS */
	if (c->use_tls == TLS_TRUE)
	    c->init_f = do_ldap_tls_init;
	else
	    c->init_f = do_ldap_init;

	return 0;
}

int reinit(struct configuration *c, LDAP **l)
{	
	int r;

	char uri_list[(URI_MAX * c->n_uris) + c->n_uris]; 

	pthread_rwlock_rdlock(&urilist_lock);
	r = uri_build_string(uri_list);
	pthread_rwlock_unlock(&urilist_lock);

	if (r < 0) {
	    log_msg("Reinit failed: All servers offline");
	    return -1;
	}

	if (init_ldap_handle(l, c, uri_list) < 0) {
	    log_msg("Failed to reinit LDAP handle");
	    return -1;
	}

	return 0;
}

int process_uri_list(LDAP *l, LDAPURLDesc **urllist, LDAPURLDesc **url, void *rthread)
{
        LDAPURLDesc	*l_ptr;
        int		n_downed = 0;
	int 		r;

        if (strcmp(url[0]->lud_host, urllist[0]->lud_host) == 0)
	    return(0);

        l_ptr = urllist[0];

        while (l_ptr != NULL) {
	    if (strcmp(url[0]->lud_host, l_ptr->lud_host) == 0)
		break;

	    pthread_rwlock_wrlock(&urilist_lock);

	    if (uri_status(l_ptr->lud_host) == ONLINE) {
		uri_set_offline(l_ptr->lud_host);
		n_downed++;
	    }

	    pthread_rwlock_unlock(&urilist_lock);
	    l_ptr = l_ptr->lud_next;
        }

        if (n_downed > 0) {
	    log_msg("DOWN: %d", n_downed);
	    reinit_status = NEED_REINIT;
	    pthread_mutex_lock(&recovery_lock);
	    if (rec_status != DEGRADED) {
		pthread_kill(recthread_id, SIGUSR1);
		rec_status = DEGRADED;
	    }			
	    pthread_mutex_unlock(&recovery_lock);
	}
	/* We're done.  For iterative connections, next thread will use new uri_string.
	 * For concurrent connection, if LDAP lib handled failure, the ldap obj will continue to 
	 * use back up URI, and next instantiation of ldap ojb will use the updated config.uri str.
	*/
}

int remove_list_head(LDAP *l)
{
	char	u[URI_MAX + 1];

	get_head_url(l, u);

	pthread_rwlock_wrlock(&urilist_lock);
	if (uri_status(u) == ONLINE) {
	    log_msg("marking %s down", u);
	    uri_set_offline(u);
	}

	pthread_rwlock_unlock(&urilist_lock);
	return 0;
}

void term_sigalrm_thrd(void *trd_id)
{
	int r;
	if ((r = pthread_cancel(*(pthread_t *)trd_id)) != 0)
		log_msg("Error canceling alrm thread: %d\n", r);
}

void free_targs(void *d)
{
	struct thread_args *a;
	a = (struct thread_args *)d;

	if (a != NULL) {
	    close(a->fd);
	    free(a);
	}
}

void free_rec_thrd_data(void *d)
{
	int i;
	struct rec_thrd_data *td;
        td = (struct rec_thrd_data *) d;

	free_lobj((LDAP *)td->l);

	if ((LDAPMessage *)td->msg != NULL) {
	    ldap_msgfree((LDAPMessage *)td->msg);
	    td->msg == NULL;
	}

	for (i = 0; i < td->cnt; i++) {
	    if(td->offline_hosts[i] != NULL) {
		free(td->offline_hosts[i]);
		td->offline_hosts[i] = NULL;
		}
	}
}

void unset_alarm(void *a)
{
	unsigned int r;
	if ((r = alarm(0)) == -1) {
		log_msg("voiding current alarm failed: %s\n", strerror(errno));
	}
}

void set_rec_status(pthread_t tid)
{
	pthread_mutex_lock(&recovery_lock);
	if (rec_status != DEGRADED) {
	    rec_status = DEGRADED;
	    if (pthread_kill(tid, SIGUSR1) != 0)
		log_msg("ERROR SENDING SIGNAL TO RECOVERY THREAD");
	}
	pthread_mutex_unlock(&recovery_lock);
}

int compare_time(struct timespec *t)
{
        if (t->tv_sec < ldap_ctime.tv_sec && \
            t->tv_nsec < ldap_ctime.tv_nsec)
                return 0;
        else
                return 1;
}

void set_reinit()
{
	/* MUST HAVE &ldap_lock MUTEX */
	if (reinit_status != NEED_REINIT)
	    reinit_status = NEED_REINIT;
}

void drop_privileges()
{
	struct passwd *pw;

	if ((pw = getpwnam("getpk")) == NULL)
	    log_die("getpk user not found.");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
	    log_syserr("cannot drop privileges");

#ifdef OPENBSD
	if (pledge("stdio rpath inet unix cpath fattr", NULL) == -1)
	    log_syserr("pledge failure %s", strerror(errno));
#endif
}

void sigterm_handler()
{
	terminate();
	exit(0);
}

void terminate()
{
	if (unlink(sock_path) < 0)
	    log_ret("Failed to unlink socket before termination:", errno);

	if (rmdir(sock_dir) == -1)
	   log_ret("Failed to remove sock dir", errno);
}

int call_accept(int lfd)
{
	struct sockaddr_in cliaddr;
	socklen_t clilen;
	int fd;

	if ((fd = accept(lfd, (SA *) &cliaddr, &clilen)) < 0) {
	    if (errno == ECONNABORTED) {
		log_ret("accept() error: %s", strerror(errno));
		return -1;
	    } else {
		log_ret("accept() error: %s", strerror(errno));
		return -1;
	    }

	} else
	    return fd;
}

int do_search_failure(struct thread_args *a)
{
#ifdef DEBUG
	log_msg("HANDLING SEARCH FAILURE");
#endif
	if (a->cfg->use_tls == TLS_TRUE) {
	    remove_list_head(a->ldap);
	    set_rec_status(a->rthread_id);
	    
	    pthread_mutex_lock(&ldap_lock);
	    set_reinit();
	    pthread_mutex_unlock(&ldap_lock);
                    
	    ldap_destroy(a->ldap);

	    if (reinit(a->cfg, &a->ldap) == 0)
		return 0;
	    else
		return -1;

	} else {
	    ldap_destroy(a->ldap);

	    pthread_rwlock_wrlock(&urilist_lock);
	    uri_setall_offline();
	    pthread_rwlock_unlock(&urilist_lock);

	    pthread_mutex_lock(&ldap_lock);
	    set_reinit();
	    pthread_mutex_unlock(&ldap_lock);
	    set_rec_status(a->rthread_id);

	    return -1;
	}
}

int do_result_failure(struct thread_args *a)
{
#ifdef DEBUG
	log_msg("HANDLING RESULT FAILURE");
#endif
	remove_list_head(a->ldap);
	set_rec_status(a->rthread_id);

	pthread_mutex_lock(&ldap_lock);
	set_reinit();
	pthread_mutex_unlock(&ldap_lock);	

	ldap_destroy(a->ldap);
	a->ldap == NULL;

	if (reinit(a->cfg, &a->ldap) == 0)
	    return 0;
	else
	    return -1;
}

int initialize(LDAP **l, struct configuration *c)
{
	/* MUST HAVE ldap_lock MUTEX */
	int r;	

	for (;;)
	{
	    if ((r = init_ldap_handle(l, c, c->uri_string)) != 0) {
		if (r == -5 && c->use_tls == TLS_TRUE) {
		    log_msg("Timeout error");
		    remove_list_head(*l);
		    ldap_destroy(*l);
		    set_rec_status(recthread_id);

		    pthread_rwlock_wrlock(&urilist_lock);
		    r = uri_build_string(c->uri_string);
		    pthread_rwlock_unlock(&urilist_lock);

		    if (r < 1)
			log_msg("Reinit failed: All servers offline");
		    else
			continue;

		} else {
		    pthread_rwlock_wrlock(&urilist_lock);
		    uri_setall_offline();
		    pthread_rwlock_unlock(&urilist_lock);
	
		    set_rec_status(recthread_id);

		    return(-1);
		}
	    } else {
		break;
	    }	  
	}
	return(0);
}
