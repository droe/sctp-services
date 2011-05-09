/*
 * Forking IPv4/IPv6 SCTP fake HTTP service for testing purposes.
 * Copyright (C) 2009, 2011 Daniel Roethlisberger <daniel@roe.ch>.
 * This program is free software; you may redistribute and/or modify it
 * under the same terms as Nmap or under the 2-Clause-BSD-License.
 */

#include "../sctp-service.h"
#define PORT 80

/*
 * Beware:  This is by no means production quality code!
 * Even though the service runs chrooted and as an unprivileged
 * user, expect the code to be exploitable or otherwise broken.
 */

int
http_service(int s, char *hn)
{
	char buf[512];
	char *p;
	ssize_t n;
	int i;

	/* ugly read() loop -- we don't want to depend on
	 * SCTP message boundaries so we treat the SCTP
	 * association exactly like a TCP connection. */
	p = buf;
	while ((n = read(s, p, sizeof(buf) - (p - buf))) > 0) {
		n += (p - buf);

		if (n >= sizeof(buf)) {
			respond(s, "HTTP/1.0 500 Error\r\n"
				   "Server: %s\r\n"
				   "\r\n", __FILE__);
			break;
		}
		if (memmem(buf, n, "\r\n\r\n", 4) ||
		    memmem(buf, n, "\n\n", 2)) {
			respond(s, "HTTP/1.0 200 OK\r\n"
				   "Server: %s\r\n"
				   "Content-Type: text/plain\r\n"
				   "\r\n"
				   ". o .\r\n"
				   ". . o\r\n"
				   "o o o\r\n", __FILE__);
			break;
		}
		p = buf + n;
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
	return service(argc, argv, PORT, http_service);
}

/* vim: set sw=8 ts=8 noet: */

