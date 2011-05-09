/*
 * Forking IPv4/IPv6 SCTP fake SMTP service for testing purposes.
 * Copyright (C) 2009, 2011 Daniel Roethlisberger <daniel@roe.ch>.
 * This program is free software; you may redistribute and/or modify it
 * under the same terms as Nmap or under the 2-Clause-BSD-License.
 */

#include "../sctp-service.h"
#define PORT 25

/*
 * Beware:  This is by no means production quality code!
 * Even though the service runs chrooted and as an unprivileged
 * user, expect the code to be exploitable or otherwise broken.
 */

int
smtp_service(int s, char *hn)
{
	char buf[512];
	char *p;
	ssize_t n;
	int skipline, i;

	respond(s, "220 %s SMTP ready (%s)\r\n", hn, __FILE__);

	/* ugly read() loop -- we don't want to depend on
	 * SCTP message boundaries so we treat the SCTP
	 * association exactly like a TCP connection. */
	skipline = 0;
	p = buf;
	while ((n = read(s, p, sizeof(buf) - (p - buf))) > 0) {
		n += (p - buf);
		/* n is now the number of bytes in buf */

start:
		for (p = buf; p < buf + n; p++) {
			if (*p == '\n') {
				break;
			}
		}
		if (p >= buf + sizeof(buf)) {
			if (!skipline) {
				respond(s, "500 Line too long.\r\n");
				skipline = 1;
			}
			p = buf;
			continue;
		}
		if (p >= buf + n) {
			p = buf + n;
			continue;
		}
		if (n > 1 && *(p - 1) == '\r')
			*(p - 1) = '\0';
		else
			*p = '\0';
		p++;
		/* p now points to the first byte after '\n',
		 * and the command is null-terminated.
		 * (p - buf) is the command length. */

		if (skipline) {
			for (i = 0; i < n - (p - buf); i++)
				buf[i] = p[i];
			n -= (p - buf);
			skipline = 0;
			goto start;
		}

		if ((p - buf) < 5) {
			respond(s, "500 Syntax error.\r\n");
			p = buf;
			continue;
		}

		if (!memcmp(buf, "HELO", 4)) {
			respond(s, "250 Pleased to meet you.\r\n");
		} else if (!memcmp(buf, "NOOP", 4)) {
			respond(s, "250 OK.\r\n");
		} else if (!memcmp(buf, "RSET", 4)) {
			respond(s, "250 OK.\r\n");
		} else if (!memcmp(buf, "HELP", 4)) {
			respond(s, "211 Don't panic.\r\n");
		} else if (!memcmp(buf, "QUIT", 4)) {
			respond(s, "221 Bye.\r\n");
			break;
		} else {
			respond(s, "502 Command not implemented.\r\n");
		}

		for (i = 0; i < n - (p - buf); i++)
			buf[i] = p[i];
		n -= (p - buf);
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
	return service(argc, argv, PORT, smtp_service);
}

/* vim: set sw=8 ts=8 noet: */

