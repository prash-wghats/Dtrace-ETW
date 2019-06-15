#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>

#if C_MUTEX
/* MUTEX */
void
wmutex_init(HANDLE *m)
{
	HANDLE h;

	h = CreateMutex(NULL, FALSE, NULL);
	*m = h;
}

void
wmutex_enter(HANDLE *m)
{
	DWORD r;
	HANDLE h = *m;
	r = WaitForSingleObject(h, INFINITE);
	if (r == WAIT_FAILED)
		r = GetLastError();
}

void
wmutex_exit(HANDLE *m)
{
	ReleaseMutex(*m);
}

void
wmutex_destroy(HANDLE *m)
{
	CloseHandle(*m);
}

int
wmutex_owned(HANDLE *m)
{
	DWORD r = WaitForSingleObject(*m, 0);
	if (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED) {
		ReleaseMutex(*m);
		return 1;
	}
	return 0;
}

#endif

#if C_MEM
/* memory */
void *
mem_zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p != NULL)
		ZeroMemory(p, size);

	return p;
}

void *
mem_alloc(size_t size)
{
	void *p;

	p = malloc(size);
	return p;
}

void
mem_free(void *buf)
{
	if (buf == NULL)
		return;
	free(buf);
}

#endif


#if C_DEBUG
int _m_debug = 0;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

void
dprintf(const char *format, ...)
{
	DWORD sz = 0;
	char *_name;
	static char *modulename = NULL;

	if (_m_debug) {
		va_list alist;
		if (modulename == NULL) {
			_name = (char *) malloc(256*2);
			sz = GetModuleFileNameA((HINSTANCE)&__ImageBase, _name, 256);
			modulename = strrchr(_name, '\\') + 1;
		}
		va_start(alist, format);
		//(void) fputs("%s DEBUG: ", stderr);
		(void) fprintf(stderr, "%s DEBUG: ", modulename);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

#endif

#if C_GCMP
int
guidcmp(const GUID *g0, const GUID *g1)
{
	return !memcmp(g0, g1, sizeof(GUID));
}
#endif

#if C_PRIV
BOOL
setpriv(LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE token = NULL;
	//LPCTSTR priv = SE_SYSTEM_PROFILE_NAME;
	BOOL enable = TRUE;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
		return FALSE;
	}
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

#endif

#if C_DBGHELP
BOOL CALLBACK
SymRegisterCallbackProc64(HANDLE hProcess, ULONG ActionCode,
    ULONG64 CallbackData, ULONG64 UserContext)
{
	UNREFERENCED_PARAMETER(hProcess);
	UNREFERENCED_PARAMETER(UserContext);

	PIMAGEHLP_CBA_EVENT evt;
	IMAGEHLP_DEFERRED_SYMBOL_LOAD64 *sym;
	CHAR *str = NULL;
	BOOL r = FALSE;
	//const CHAR *TEXT ="\r[#] Locating symbols for (%s)..\n\t      ";
	const CHAR *TEXT ="\r[#] Locating symbols for (%s)..\r";
	// If SYMOPT_DEBUG is set, then the symbol handler will pass
	// verbose information on its attempt to load symbols.
	// This information be delivered as text strings.

	if (CallbackData == NULL) {
		return FALSE;
	}
	switch (ActionCode) {
	/*case CBA_DEFERRED_SYMBOL_LOAD_CANCEL:
		sym = (IMAGEHLP_DEFERRED_SYMBOL_LOAD64 *) CallbackData;
		str = (CHAR *) UserContext;
		sprintf(str, TEXT, sym->FileName);
		fprintf(stderr, "\r");
		break;*/
	case CBA_DEFERRED_SYMBOL_LOAD_START:
		sym = (IMAGEHLP_DEFERRED_SYMBOL_LOAD64 *) CallbackData;
		fprintf(stderr, TEXT, sym->FileName);
		break;
	case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:
		fprintf(stderr, "%90s\r\t      ", "");
		break;
	case CBA_EVENT:
		//evt = (PIMAGEHLP_CBA_EVENT)CallbackData;
		//_tprintf(_T("%s"), (PTSTR)evt->desc);

		break;

		// CBA_DEBUG_INFO is the old ActionCode for symbol spew.
		// It still works, but we use CBA_EVENT in this example.
#if 0
	case CBA_DEBUG_INFO:
		_tprintf(_T("%s"), (PTSTR)CallbackData);
		break;
#endif

	default:
		// Return false to any ActionCode we don't handle
		// or we could generate some undesirable behavior.
		return FALSE;
	}
	/*if (str) {
				printf("%s", str);
	}*/
	return r;
}


HANDLE
init_symbols(HANDLE h, int inv, PSYMBOL_REGISTERED_CALLBACK64 cb)
{
	if ((SymInitialize(h, 0, inv) == FALSE)) {
		return (NULL);
	}
	if (cb == NULL) {
		cb = SymRegisterCallbackProc64;
	}
	if (SymRegisterCallback64(h, cb, NULL) == FALSE) {
		fprintf(stderr, "SymRegisterCallback64 failed: status (%d)\n",
		    GetLastError());
	}

	return (h);
}

#endif
#if C_RUNCMD
int
runcmd(char *cmd)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD exit_code;


	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);

	si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdInput = NULL;
	si.hStdError = NULL;
	si.hStdOutput = NULL;
	ZeroMemory( &pi, sizeof(pi) );

	// Start the child process.
	if(!CreateProcessA( NULL,   // No module name (use command line)
	        cmd,   // Command line
	        NULL,           // Process handle not inheritable
	        NULL,           // Thread handle not inheritable
	        FALSE,          // Set handle inheritance to FALSE
	        0,              // No creation flags
	        NULL,           // Use parent's environment block
	        NULL,           // Use parent's starting directory
	        &si,            // Pointer to STARTUPINFO structure
	        &pi )           // Pointer to PROCESS_INFORMATION structure
	) {
		dprintf("runcmd(), failed cmd (%s) (%x)\n", cmd, GetLastError());
		return (-1);
	}
	// Wait until child process exits.
	WaitForSingleObject( pi.hProcess, INFINITE );

	GetExitCodeProcess(pi.hProcess, &exit_code);

	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	return exit_code;
}

#endif
#if C_FILETYPE
#include <fcntl.h>
#include <sys\types.h>
#include <sys\stat.h>
//https://stackoverflow.com/questions/7031926/using-c-how-to-get-whether-my-machine-is-64bit-or-32bit
static int
DoesWin32MethodExist(char *oname, char *fn)
{
	HMODULE  mh = GetModuleHandle(oname);
	if (mh == NULL) {
		return 0;
	}
	return (GetProcAddress(mh, fn) != NULL);
}
int
is64bitos(BOOL *arch)
{
#if defined(_WIN64)
	return TRUE; // 64-bit programs run only on Win64
#elif defined(_WIN32)
// 32-bit programs run on both 32-bit and 64-bit Windows
	//BOOL f64bitOS = FALSE;
	*arch = 0;
	return ((DoesWin32MethodExist("kernel32.dll", "IsWow64Process") &&
	            IsWow64Process(GetCurrentProcess(), arch)) && *arch);
#endif
}
//http://forums.codeguru.com/showthread.php?424454-Check-if-DLL-is-managed-or-not
static DWORD
PtrFromRVA(IMAGE_SECTION_HEADER* pSectionHeader,
    IMAGE_NT_HEADERS *pNTHeaders, DWORD dwRVA)
{
	DWORD dwRet = 0;

	for(int j = 0; j < pNTHeaders->FileHeader.NumberOfSections; j++,pSectionHeader++) {
		DWORD cbMaxOnDisk
		    = min( pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData );

		DWORD startSectRVA,endSectRVA;

		startSectRVA = pSectionHeader->VirtualAddress;
		endSectRVA = startSectRVA + cbMaxOnDisk;

		if ( (dwRVA >= startSectRVA) && (dwRVA < endSectRVA)) {
			dwRet =  (pSectionHeader->PointerToRawData ) + (dwRVA - startSectRVA);
			break;
		}

	}

	return dwRet;
}

int
filetype(char *name, int *arch, int *isnet)
{
	int fd;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_OPTIONAL_HEADER64 ohdr64;
	PIMAGE_OPTIONAL_HEADER32 ohdr32;

	int r, sz = 0, type = 0, parch = 0;
	char *buf;
	struct stat st;

	*isnet = 0;
	*arch = 0;

	fd = _open(name, _O_RDONLY|_O_BINARY, 0);
	if (fd == -1) {
		return (-1);
	}


	if (fstat(fd, &st) ==  -1) {
		return (-1);
	}
	sz = st.st_size;

	if (sz < sizeof(PIMAGE_DOS_HEADER)) {
		return (-1);
	}

	if ((buf = malloc(sz)) == NULL) {
		return (-1);
	}

	if ((r = read(fd, buf, sz)) != sz) {
		goto c_err;
	}

	dos = (PIMAGE_DOS_HEADER) buf;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		if (dos->e_lfanew + sizeof(IMAGE_FILE_HEADER) > sz) {
			goto c_err;
		}
		nthdr = (PIMAGE_NT_HEADERS) (buf + dos->e_lfanew);
		if (nthdr->Signature != IMAGE_NT_SIGNATURE) {
			goto c_err;
		}
		hdr = &nthdr->FileHeader;
		if (hdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
			type = 0;
		else if (hdr->Characteristics & IMAGE_FILE_DLL)
			type = 1;
		else
			type = -1;

		if (hdr->Machine == IMAGE_FILE_MACHINE_I386) {
			*arch = 1;
			ohdr32 = &nthdr->OptionalHeader;
		} else if (hdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
			*arch = 0;
			ohdr64 = &nthdr->OptionalHeader;
		} else
			*arch = -1;
		DWORD netloc = arch == 1 ?
		    ((PIMAGE_NT_HEADERS32) nthdr)->OptionalHeader.DataDirectory
		    [IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress:
		    ((PIMAGE_NT_HEADERS64) nthdr)->OptionalHeader.DataDirectory
		    [IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
		if (netloc) {
			IMAGE_COR20_HEADER* nethdr = (IMAGE_COR20_HEADER*)((BYTE*)dos +
			        PtrFromRVA((IMAGE_SECTION_HEADER*)((BYTE*) nthdr + sizeof(IMAGE_NT_HEADERS)),
			            nthdr, netloc));
			if (nethdr) {
				if (hdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
					*isnet = 1; // 64 bit mode
				} else if ((nethdr->Flags & COMIMAGE_FLAGS_32BITREQUIRED) == 0) {
					//AnyCPU
					if (is64bitos(&parch)) {
						*isnet = 1;
					} else {
						*isnet = 2;	// 32 bit mode
					}
				} else {
					*isnet = 2;
				}
			}
		}

	}
	c_err:
	free(buf);

	return (type);
}
#endif

#if C_NGENEXE

static char *str_netver[][2] = {
	{
		"\\Microsoft.NET\\Framework64\\v2.0.50727\\ngen.exe",
		"\\Microsoft.NET\\Framework\\v2.0.50727\\ngen"
	},
	{
		"\\Microsoft.NET\\Framework64\\v4.0.30319\\ngen",
		"\\Microsoft.NET\\Framework\\v4.0.30319\\ngen"
	},
	{"", ""}
};

int
ngenpath(char *path, int len, int ver, int arch)
{
	int n = 0;

	if ((n=GetWindowsDirectoryA(path, len)) == 0) {
		dprintf("net_ngened(), failed to get Windows directory (%x)\n", GetLastError());
		return (-1);
	}

	strncpy(path+n, str_netver[ver][arch], (len-n));
	n = strlen(path);

	return n;
}
#endif

#if C_ISGUIDEQ

/*
 * Return 1 if guids are equal
 */
int
isguideq(GUID *g0, GUID *g1)
{
	RPC_STATUS status;

	//return memcmp(g0, g1, sizeof(GUID));

	int r = UuidEqual(g0, g1, &status);
	if (status == RPC_S_OK && r)
		return (1);
	return (0);

}
#endif

#if DBG_PATH

#define SYMBOLS_PATH "srv*c:\\symbols*http://msdl.microsoft.com/download/symbols"
#define MSSYMSERVER "http://msdl.microsoft.com/download/symbols"
#define SYMS_ENV "_NT_SYMBOL_PATH"
/*
 * Set dbghelp symbol resolution envinonment variable.
 * If not set, setup one in the system drive X:\Symbols;
 * Also set the MS server path
 */
char *
set_syms_path(char *path)
{
	int n = 0;
	static char buf[MAX_PATH];
	char tbuf[MAX_PATH], nvar[8] = {0};
	char *envs = getenv(SYMS_ENV);
	int mserver = 1;

	if ((n=GetWindowsDirectoryA(buf, MAX_PATH)) == 0) {
		dprintf("set_syms_path(), failed to get Windows directory (%x)\n",
		    GetLastError());
	} else {
		_splitpath(buf, nvar, NULL, NULL, NULL, NULL);
	}

	if (envs == NULL) {
		if (path) {
			sprintf(tbuf, "srv*%s*%s", path, MSSYMSERVER);
		} else {

			n = strlen(nvar);
			sprintf(tbuf, "%s%s\\%s%s", "srv*", nvar,
			    "Symbols*", MSSYMSERVER);
		}
	} else {
		if (strstr(envs, MSSYMSERVER) != NULL)
			mserver = 0;

		if (path) {
			if (mserver)
				sprintf(tbuf, "%s;%s", envs, path);
			else
				sprintf(tbuf, "%s;srv*%s*%s", envs, path, MSSYMSERVER);
		} else if (mserver) {
			sprintf(tbuf, "%s;srv*%s\\*%s", envs, nvar, MSSYMSERVER);
		} else {
			return envs;
		}
	}
	sprintf(buf, "%s=%s", SYMS_ENV, tbuf);
	_putenv(buf);
	return (buf);
}
#endif