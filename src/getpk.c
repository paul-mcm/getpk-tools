#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include "errorlog.h"

#define SA struct sockaddr

int debug = 0;

int main(int argc, char *argv[])
{
	int			sockfd;
	char			sock[] = "/tmp/getpkd/getpkd.sock";
	struct sockaddr_un	servaddr;
	char			key[2048];
	ssize_t			n_read, n_written;

#ifdef OPENBSD
	if (pledge("stdio unix", NULL) == -1)
	    log_syserr("pledge failure %s", strerror(errno));
#endif
	log_open(argv[0], LOG_PID, LOG_AUTH);

	if (argc != 2)
	    log_die("Wrong number of args to %s: %d", argv[0], argc);  

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;

#ifdef BSD
	strlcpy(servaddr.sun_path, sock, sizeof(servaddr.sun_path));
#elif LINUX
	strncpy(servaddr.sun_path, sock, strlen(sock) + 1);
#endif
	if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) < 0)
	    log_syserr("Error connecting to socket %s: %s\n", sock, strerror(errno));

	if ((n_written = write(sockfd, argv[1], strlen(argv[1]) + 1)) < 0)
	    log_syserr("Error writing to %s: %s\n", sock, strerror(errno));

	while ((n_read = read(sockfd, key, 1024)) > 0)
	    if (write(STDOUT_FILENO, key, n_read) < 0)
		log_syserr("Write error: %d %s", errno, strerror(errno));

	if (n_read < 0)
	    log_syserr("Error reading response from server to %s\n", sock, strerror(errno));
	
	exit(0);	    
}
