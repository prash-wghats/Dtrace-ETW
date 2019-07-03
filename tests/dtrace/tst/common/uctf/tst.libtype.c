/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 (c) Joyent, Inc. All rights reserved.
 */

/*
 * We're linked against libc which has types, though we do not.
 */
#ifdef windows
#include <windows.h>
#else
#include <unistd.h>
#endif

int
main(void)
{
	for (;;) {
#ifdef windows
		Sleep(1000*1000);
#else
		sleep(1000);
#endif
	}
	/*NOTREACHED*/
	return (0);
}
