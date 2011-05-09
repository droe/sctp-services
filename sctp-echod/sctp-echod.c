/*
 * Forking IPv4/IPv6 SCTP echo service for testing purposes.
 * Copyright (C) 2009, 2011 Daniel Roethlisberger <daniel@roe.ch>.
 * This program is free software; you may redistribute and/or modify it
 * under the same terms as Nmap or under the 2-Clause-BSD-License.
 */

#include "../sctp-service.h"
#define PORT 7

/*
 * Beware:  This is by no means production quality code!
 * Even though the service runs chrooted and as an unprivileged
 * user, expect the code to be exploitable or otherwise broken.
 */

int
echo_service(int s, char *hn)
{
	char buf[256];
	ssize_t n;

	while ((n = read(s, buf, sizeof(buf))) > 0) {
		if (write(STDOUT_FILENO, buf, n) == -1) {
			perror("write(stdout)");
			break;
		}
		if (write(s, buf, n) == -1) {
			perror("write(s)");
			break;
		}
	}
	if (n < 0) {
		perror("read()");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
	return service(argc, argv, PORT, echo_service);
}

/* vim: set sw=8 ts=8 noet: */

