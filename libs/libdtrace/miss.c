
#include <dtrace_misc.h>
#include <windows.h>
#include <stdio.h>
#include <Winbase.h>
#include <shlwapi.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys\stat.h>
#include <libproc.h>


/*	$OpenBSD: strlcpy.c,v 1.4 1999/05/01 18:56:41 millert Exp $	*/

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <string.h>

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(dst, src, siz)
char *dst;
const char *src;
size_t siz;
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';	/* NUL-terminate dst */
		while (*s++);
	}

	return (s - src - 1);	/* count does not include NUL */
}

/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>

char *
strndup(const char *str, size_t n)
{
	size_t len;
	char *copy;

	len = strnlen(str, n);
	if ((copy = malloc(len + 1)) == NULL)
		return (NULL);
	memcpy(copy, str, len);
	copy[len] = '\0';
	return (copy);
}



/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
char *strsep(stringp, delim)
char **stringp;
const char *delim;
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}



/////////////////
/*
 * Copyright (c) 1994 SigmaSoft, Th. Lockert <tholo@sigmasoft.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>

int
ftok(const char *path, int id)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return (int)-1;

	return (int)
	    ((id & 0xff) << 24 | (st.st_dev & 0xff) << 16 | (st.st_ino & 0xffff));
}
///////////


/*
 * time between jan 1, 1601 and jan 1, 1970 in units of 100 nanoseconds
 */
#define PTW32_TIMESPEC_TO_FILETIME_OFFSET \
	  ( ((int64_t) 27111902 << 32) + (int64_t) 3577643008u )

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


hrtime_t gethrestime(void)
{
	hrtime_t ret;
	FILETIME ft;
	LARGE_INTEGER tmp;

	GetSystemTimeAsFileTime(&ft);
	tmp.LowPart = ft.dwLowDateTime;
	tmp.HighPart = ft.dwHighDateTime;
	ret = ((tmp.QuadPart - PTW32_TIMESPEC_TO_FILETIME_OFFSET) * 100UL);

	return ret;

}

hrtime_t gethrtime(void)
{
	hrtime_t ret;
	LARGE_INTEGER Frequency;
	LARGE_INTEGER Time;
	static hrtime_t frequency = 0;
	if (frequency == 0) {
		LARGE_INTEGER Frequency;
		QueryPerformanceFrequency(&Frequency);
		frequency = NANOSEC/Frequency.QuadPart;
	}
	QueryPerformanceCounter(&Time);
	ret = Time.QuadPart * frequency;
	
	return ret;
}

FILE *tempfile(void)
{
	char n[L_tmpnam];
	int fd;
	FILE *fp;
	HANDLE hf;


	tmpnam(n);
	if (n[0] == '\\') {
		n[0] = '$';
		n[1] = '$';
	}
	fd = _sopen(n, _O_CREAT | _O_EXCL | _O_TEMPORARY | _O_RDWR | _O_TEXT,
	        _SH_DENYNO, _S_IREAD | _S_IWRITE);
	if (fd == -1) {
		return NULL;
	}
	fp = _fdopen(fd, "a+");

	if (fp == NULL) {
		return NULL;
	}
	return fp;
}


char *cleanddpath(char *str)
{
	int l;

	if (strncmp(str, "\\WINDOWS", 8) == 0) {
		l = strlen(str);
		memmove(str + 2, str, l + 1);
		strncpy(str, "C:", 2);
	} else if (strncmp(str, "\\??\\", 4) == 0) {
		l = strlen(str);
		memmove(str, str + 4, l + 1);
	} else if (strncmp(str, "\\SystemRoot", 11) == 0) {
		l = strlen(str);
		memmove(str, str + 1, l + 1);
		strncpy(str, "C:\\WINDOWS\\", 11);
	} else if (strncmp(str, "\\", 1) != 0) {
		l = strlen(str);
		memmove(str + 28, str, l + 1);
		strncpy(str, "C:\\WINDOWS\\system32\\Drivers\\", 28);
	}
	return str;
}


int gelf_getclass(const char *filen, uintptr_t mod)
{
	HANDLE file, map;
	LPVOID base;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_DATA_DIRECTORY ExcpDataDir;
	IMAGE_FILE_HEADER FileHeader;
	MEMORY_BASIC_INFORMATION mbi;
	int ret = 0;

	file = CreateFile(filen, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return 0;
	}


	if ((map = CreateFileMapping(file,NULL,PAGE_READONLY,0,0,NULL)) == NULL) {
		CloseHandle(file);
		return 0;
	}

	if ((base = MapViewOfFile(map,FILE_MAP_READ,0,0,0)) == NULL) {
		CloseHandle(map);
		return 0;
	}

	VirtualQuery(base, &mbi, sizeof(mbi));
	if (mbi.RegionSize < sizeof(IMAGE_FILE_HEADER)) {
		ret = 0;
		goto err;
	}

	DosHeader = (PIMAGE_DOS_HEADER) base;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE ) {
		nthdr =  (PIMAGE_NT_HEADERS) ((PUCHAR) DosHeader + DosHeader->e_lfanew);
		hdr = &nthdr->FileHeader;
	} else
		hdr = (PIMAGE_FILE_HEADER) base;

	switch(hdr->Machine) {
	case 0x14c:
		ret = ELFCLASS32;
		break;
	case 0x8664:
		ret = ELFCLASS64;
		break;
	default:
		ret = 0;
	}
	err:
	UnmapViewOfFile(base);
	CloseHandle(map);
	CloseHandle(file);

	return ret;
}

void update_errno()
{
	errno = GetLastError() & 0x0FFFFFFF;
}


int mkstemp(char *template)
{
	char *s = _mktemp(template);
	int fd;

	if (s == NULL)
		return -1;
	fd = _sopen(s, _O_CREAT | _O_EXCL | _O_RDWR | O_BINARY,
	        _SH_DENYNO, _S_IREAD | _S_IWRITE);
	return fd;
}



BOOL SetPrivilege(HANDLE token, LPCTSTR priv, BOOL enable)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid)) {
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (enable)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
	        (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL)) {
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		return FALSE;
	}

	return TRUE;
}


#define JMP_REL 5
int dt_fpid_return(unsigned char *text, int size, int i, int instsz)
{
	if  (text[i+instsz] == 0xcc) {
		int fail = 0;
		for (int j = 1; j < (JMP_REL-size); j++) {
			if (text[i+instsz] != text[i+instsz+j]) {
				return (0);
			}
		}
		
	} else {
		return (0);
	}

	return (1);
}

HANDLE dt_load_provider(char *provn, int(*attach)())
{
#if defined(STATIC)
	static int i = 1;
	int r = 0;

	r = attach();
	 
	 return (HANDLE) ++i;
#else
	return LoadLibrary(provn);
#endif;
}

char *setlibdir()
{
	static char exepath[_MAX_PATH+1];
	int r = 0;

	if ((r=GetModuleFileNameA(NULL, exepath, _MAX_PATH)) <= 0)
		return NULL;
	PathRemoveFileSpecA(exepath);
	
	return exepath;
}