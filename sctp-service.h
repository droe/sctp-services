/*
 * Forking IPv4/IPv6 SCTP service framework for testing purposes.
 * Copyright (C) 2009, 2011 Daniel Roethlisberger <daniel@roe.ch>.
 * This program is free software; you may redistribute and/or modify it
 * under the same terms as Nmap or under the 2-Clause-BSD-License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>

#define SERVICE_USER	"nobody"
#define SERVICE_JAIL	"/var/empty"

#ifndef INFTIM
#define INFTIM -1
#endif

/*
 * Beware:  This is by no means production quality code!
 * Even though the service runs chrooted and as an unprivileged
 * user, expect the code to be exploitable or otherwise broken.
 */

int
drop_privs(const char *user, const char *jail)
{
	struct passwd *pw;
	int ret;

	ret = -1;
	if (user) {
		if (!(pw = getpwnam(user)))
			goto error;
		if (initgroups(user, pw->pw_gid) == -1)
			goto error;
	}
	if (jail) {
		if (chroot(jail) == -1)
			goto error;
		if (chdir("/") == -1)
			goto error;
	}
	if (user) {
		if (setgid(pw->pw_gid) == -1)
			goto error;
		if (setuid(pw->pw_uid) == -1)
			goto error;
	}
	ret = 0;
error:
	endpwent();
	return ret;
}

void
respond(int s, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int len, rc;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (len < 0) {
		perror("vasprintf()");
		close(s);
		exit(EXIT_FAILURE);
	}

	rc = write(s, buf, len);
	free(buf);
	if (rc == -1) {
		perror("write(s)");
		close(s);
		exit(EXIT_FAILURE);
	}
}

typedef int (*handler_t)(int, char *);

int
service(int argc, char *argv[], uint16_t port, handler_t handler)
{
	struct addrinfo *ai, *pai, hints;
	struct pollfd fds[2];
	nfds_t nfds;
	int e;
	char portstr[6];
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char hn[256];

	snprintf(portstr, sizeof(portstr), "%i", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_SCTP;
	if ((e = getaddrinfo(NULL, portstr, &hints, &ai)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}

	for (pai = ai, nfds = 0;
	     pai != NULL && nfds < sizeof(fds)/sizeof(fds[0]);
	     pai = pai->ai_next) {
		int opt = 1;

		if ((fds[nfds].fd = socket(pai->ai_family, pai->ai_socktype,
		                           pai->ai_protocol)) == -1) {
			perror("socket()");
			exit(EXIT_FAILURE);
		}

		if (setsockopt(fds[nfds].fd, SOL_SOCKET, SO_REUSEADDR,
		               &opt, sizeof(opt)) == -1) {
			perror("setsockopt(SO_REUSEADDR)");
			exit(EXIT_FAILURE);
		}

		if (bind(fds[nfds].fd, pai->ai_addr, pai->ai_addrlen) == -1) {
			if (errno == EADDRINUSE) {
				close(fds[nfds].fd);
				continue;
			}
			perror("bind()");
			exit(EXIT_FAILURE);
		}

		if (listen(fds[nfds].fd, SOMAXCONN) == -1) {
			perror("listen()");
			exit(EXIT_FAILURE);
		}

		if ((e = getnameinfo(pai->ai_addr, pai->ai_addrlen,
		                hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		                NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
			fprintf(stderr, "getnameinfo(): %s\n", gai_strerror(e));
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "Listening on [%s]:%s\n", hbuf, sbuf);

		fds[nfds].events = POLLIN;
		nfds++;
	}
	freeaddrinfo(ai);

	signal(SIGCHLD, SIG_IGN);

	if (drop_privs(SERVICE_USER, SERVICE_JAIL) == -1) {
		perror("drop_privs()");
		exit(EXIT_FAILURE);
	}

	if (gethostname(hn, sizeof(hn)) == -1) {
		perror("gethostname()");
		exit(EXIT_FAILURE);
	}

	while (1) {
		int n, i;

		n = poll(fds, nfds, INFTIM);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			perror("poll()");
			exit(EXIT_FAILURE);
		} else if (n == 0)
			continue;
		for (i = 0; i < nfds; i++) {
			struct sockaddr_storage sas;
			socklen_t sassz = sizeof(sas);
			pid_t pid;
			int s;

			if (!(fds[i].revents & POLLIN))
				continue;

			if ((s = accept(fds[i].fd, (struct sockaddr *)&sas,
			                &sassz)) == -1) {
				perror("accept()");
				exit(EXIT_FAILURE);
			}

			pid = fork();
			if (pid < 0) {
				perror("fork()");
				exit(EXIT_FAILURE);
			} else if (!pid) {
				if ((e = getnameinfo((struct sockaddr *)&sas,
				                sassz,
				                hbuf, sizeof(hbuf),
				                sbuf, sizeof(sbuf),
				                NI_NUMERICHOST |
				                NI_NUMERICSERV)) != 0) {
					fprintf(stderr, "getnameinfo(): %s\n",
					                gai_strerror(e));
					exit(EXIT_FAILURE);
				}
				for (i = 0; i < nfds; i++) {
					close(fds[i].fd);
				}
				fprintf(stderr, "[%s]:%s associated\n",
				                hbuf, sbuf);
				e = handler(s, hn);
				fprintf(stderr, "[%s]:%s disassociated\n",
				                hbuf, sbuf);
				close(s);
				exit(e);
			} else {
				close(s);
			}
		}
	}
}

/* vim: set sw=8 ts=8 noet: */

