// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 * xscreensaver-pwcheck.c
 * External auth command for xscreensaver, 
 * authenticating through a pwcheckd socket.
 *
 * Copyright (C) 2007 SGDN/DCSSI
 * Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#define PWLEN 64

#define WARN(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

#ifdef PWCHECKD_SOCKET
#define _PWCHECKD_SOCKET TO_STR(PWCHECKD_SOCKET)
#else
#error
#define _PWCHECKD_SOCKET "/var/run/pwcheckd"
#endif

static void
usage(const char *prog)
{
	printf("usage: %s <service> <user>\n", prog);
}

static int
do_screensaver(void)
{
	char buf[PWLEN]; 
	char *ptr;
	struct sockaddr_un sau;
	ssize_t len;
	char c;
	int s, ret = -1;

	len = read(STDIN_FILENO, buf, PWLEN - 1);
	if (len < 0) {
		perror("read");
		return -1;
	}

	// let's not even try to authenticate users who enter an empty password
	if (len == 0)
	  return -1;

	buf[len] = '\0';
	ptr = strchr(buf, '\n'); 
	if (ptr)
		*ptr = '\0';

	sau.sun_family = AF_UNIX;
	snprintf(sau.sun_path, sizeof(sau.sun_path), "%s", _PWCHECKD_SOCKET);
	
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return ret;
	}
	
	if (connect(s, (struct sockaddr *)&sau, sizeof(struct sockaddr_un)) < 0) {
		perror("connect");
		goto out;
	}
	
	len = write(s, buf, (size_t)len);
	if (len < 0) {
		perror("write");
		goto out;
	}	

	if (read(s, &c, 1) < 0) {
		perror("read");
		goto out;
	}

	if (c == 'Y')
		ret = 0;
out:
	close(s);
	return ret;
}

int 
main(int argc, char *argv[])
{
	if (argc < 3) {
		usage(basename(argv[0]));
		return EXIT_FAILURE;
	}

	/* argv[2] unused (username) */
	if (!strcmp(argv[1], "xscreensaver")) {
		return do_screensaver();
	}

	WARN("Service '%s' is not supported\n", argv[1]);
	return EXIT_FAILURE;
}
		
