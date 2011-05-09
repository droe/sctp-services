/*
 * Simple IPv4 SCTP client program for testing purposes.
 * Copyright (C) 2009 Daniel Roethlisberger <daniel@roe.ch>.
 * This program is free software; you may redistribute and/or modify it
 * under the same terms as Nmap or under the 2-Clause-BSD-License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	int sd, s;
	struct sockaddr_in sin;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ipv4_addr> <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	sin.sin_port = htons(atoi(argv[2]));

	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		perror("connect()");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Associated to %s:%i\n", inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port));

	while (1) {
		int nfds;
		fd_set fds;
		ssize_t n;
		char buf[1024];

		FD_ZERO(&fds);
		FD_SET(s, &fds);
		FD_SET(STDIN_FILENO, &fds);
		nfds = (s > STDIN_FILENO ? s : STDIN_FILENO) + 1;

		if (select(nfds, &fds, NULL, NULL, NULL) == -1) {
			perror("select()");
			exit(EXIT_FAILURE);
		}

		if (FD_ISSET(s, &fds)) {
			if ((n = read(s, buf, sizeof(buf))) == -1) {
				perror("read(s)");
				close(s);
				exit(EXIT_FAILURE);
			}
			if (n == 0) {
				close(s);
				exit(EXIT_SUCCESS);
			}
			if (write(STDOUT_FILENO, buf, n) == -1) {
				perror("write(stdout)");
				close(s);
				exit(EXIT_FAILURE);
			}
		}

		if (FD_ISSET(STDIN_FILENO, &fds)) {
			if ((n = read(STDIN_FILENO, buf, sizeof(buf))) == -1) {
				perror("read(stdin)");
				close(s);
				exit(EXIT_FAILURE);
			}
			if (n == 0) {
				close(s);
				exit(EXIT_SUCCESS);
			}
			if (write(s, buf, n) < 0) {
				perror("write(s)");
				close(s);
				exit(EXIT_FAILURE);
			}
		}
	}
}

