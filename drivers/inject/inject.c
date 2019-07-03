#define	WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include "inject.h"

dt_pipe_t *
ExampleFunc(dt_pipe_t *pipe)
{
	dt_pmsg_t *msg = (dt_pmsg_t *) pipe->hmap;
	dt_pmsg_t rmsg = {0};

	switch (msg->id) {
	default:
		rmsg.id = PIPE_DONE;
		rmsg.size = sizeof (dt_pmsg_t);
		memcpy((void *) pipe->hmap, &rmsg, rmsg.size);
		break;
	}

	return (pipe);
}

dt_pipe_t *
dt_create_pipe(DWORD pid, int size, dt_pipe_t * (*func)(dt_pipe_t *))
{
	HANDLE hfile;
	dt_pipe_t *pip;
	char name[256], strs[128], strc[128];
	int isserver;
	void *addr;

	pip = (dt_pipe_t *) malloc(sizeof (dt_pipe_t));
	if (pip == NULL) {
		return (NULL);
	}
	if (pid == 0) {
		pid = GetProcessId(GetCurrentProcess());
		isserver = 0;
	} else {
		isserver = 1;
	}

	sprintf(name, "pid_%d", pid);
	hfile = CreateFileMapping(
        INVALID_HANDLE_VALUE,	/* use paging file */
        NULL,				/* default security */
        PAGE_READWRITE,		/* read/write access */
        0,					/* maximum object size high DWORD */
        size,				/* low-order DWORD */
        name);				/* name of mapping object */
    if (hfile == NULL) {
    	return (NULL);
	}
	
    addr = MapViewOfFile(hfile, FILE_MAP_ALL_ACCESS,
        0, 0, size);

	if (addr == NULL) {
		CloseHandle(hfile);
		return (NULL);
	}
	

	sprintf(strs, "%s_Server",name);
	sprintf(strc, "%s_Client",name);
	
	HANDLE evh = CreateEvent(NULL, FALSE, FALSE, isserver ? strs: strc);
	if (evh == NULL) {
		UnmapViewOfFile(addr);
		CloseHandle(hfile);
		return (NULL);
	}
	HANDLE evp = CreateEvent(NULL, FALSE, FALSE, !isserver ? strs: strc);
		
	if (evp == NULL) {
		UnmapViewOfFile(addr);
		CloseHandle(hfile);
		CloseHandle(evh);
		return (NULL);
	}

	pip->hfile = hfile;
	pip->hmap = (uintptr_t) addr;
	pip->evh = evh;
	pip->evp = evp;
	pip->size = size;
	pip->pfunc_data = func == NULL ? ExampleFunc:func;

	return (pip);
}

dt_pmsg_t *dt_pipe_sndrcv(dt_pipe_t *pipe, dt_pmsg_t *msg)
{
	DWORD msec = INFINITE, st;

	memcpy((void *) pipe->hmap, msg, msg->size);

	assert(WAIT_TIMEOUT == WaitForSingleObject(pipe->evh, 0));
	st = SignalObjectAndWait(pipe->evh, pipe->evp, msec, FALSE);

	return (st == WAIT_OBJECT_0) ? (dt_pmsg_t *) pipe->hmap: NULL;
}

void dt_unload_msg(dt_pipe_t *pipe)
{
	SetEvent(pipe->evh);
}

DWORD WINAPI msg_proc(LPVOID data)
{
	dt_pipe_t *pipe = (dt_pipe_t *) data;

	while (WaitForSingleObject(pipe->evp, INFINITE) == WAIT_OBJECT_0) {
		if (pipe->pfunc_data(pipe) != NULL) {
			SetEvent(pipe->evh);
		} else {
			fprintf(stderr, "msg_proc, unknown message!!\n");
			break;
		}
	}

	return (0);
}

HANDLE dt_pipe_wait(dt_pipe_t *pipe)
{
	HANDLE td = CreateThread(NULL, 0, msg_proc, pipe, 0, NULL);
	pipe->htd = td;
	
	return (td);
}

void dt_pipe_destroy(dt_pipe_t *pipe)
{
	UnmapViewOfFile(pipe->hmap);
	CloseHandle(pipe->hfile);
	CloseHandle(pipe->evh);
	CloseHandle(pipe->evp);
	CloseHandle(pipe->htd);
}

#if !defined(AGENTDLL)
#include <dbghelp.h>
int
dt_injectdll(DWORD pid, wchar_t *dllpath)
{
	HANDLE hthread, hprocess, hkernel32, hkernel320;
	void*  plibremote = 0;	
	DWORD  hlibmodule = 0, err = 0, len;
	
	len = (wcslen(dllpath)+1) * sizeof(wchar_t);

	hprocess = OpenProcess(PROCESS_CREATE_THREAD |
	    PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
	    PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);

	hkernel32 = GetRemoteModuleHandle(hprocess, "Kernel32");

	/* Allocate memory in the remote process for dllpath */
	plibremote = VirtualAllocEx(hprocess, NULL, len, MEM_COMMIT, PAGE_READWRITE);
	if(plibremote == NULL) {
		fprintf(stderr, "dt_injectdll, failed to allocate memory in,"
			" pid (%d) status (%d)\n", pid, GetLastError());
		return (0);
	}
	
	/* Write dllpath to the allocated memory */
	WriteProcessMemory(hprocess, plibremote, (void*) dllpath, len, NULL);

	/* Load dll into the remote process */
	FARPROC proc = GetRemoteProcAddress(hprocess, hkernel32,"LoadLibraryW", 0, 0);
	hthread = CreateRemoteThread(hprocess, NULL, 0,
	    (LPTHREAD_START_ROUTINE) proc,
	    plibremote, 0, NULL);

	if(hthread == NULL) {
		fprintf(stderr, "dt_injectdll, failed to create remote thread in,"
			" pid (%d) status (%d)\n", pid, GetLastError());
		goto JUMP;
	}

	WaitForSingleObject(hthread, INFINITE);

	/* Get handle of loaded module */
	GetExitCodeThread(hthread, &hlibmodule);
	CloseHandle(hthread);

JUMP:
	VirtualFreeEx(hprocess, plibremote, 0, MEM_RELEASE);
	if(hlibmodule == NULL) {
		fprintf(stderr, "dt_injectdll, failed inject tracing dll,"
			" pid (%d) status (%d)\n", pid, GetLastError());
		return (0);
	}

	return (1);
}

//https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded
HMODULE WINAPI
GetRemoteModuleHandle(HANDLE hProcess, LPCSTR lpModuleName)
{
	HMODULE* ModuleArray = NULL;
	DWORD ModuleArraySize = 100;
	DWORD NumModules = 0;
	CHAR lpModuleNameCopy[MAX_PATH] = {0};
	CHAR ModuleNameBuffer[MAX_PATH] = {0};

	/* Make sure we didn't get a NULL pointer for the module name */
	if(lpModuleName == NULL)
		goto GRMH_FAIL_JMP;

	/* Convert lpModuleName to all lowercase so the comparison isn't case sensitive */
	for (size_t i = 0; lpModuleName[i] != '\0'; ++i) {
		if (lpModuleName[i] >= 'A' && lpModuleName[i] <= 'Z')
			lpModuleNameCopy[i] = lpModuleName[i] + 0x20; // 0x20 is the difference between uppercase and lowercase
		else
			lpModuleNameCopy[i] = lpModuleName[i];

		lpModuleNameCopy[i+1] = '\0';
	}

	/* Allocate memory to hold the module handles */
	ModuleArray = (HMODULE *) malloc(sizeof(HMODULE) * ModuleArraySize); //new HMODULE[ModuleArraySize];

	/* Check if the allocation failed */
	if(ModuleArray == NULL)
		goto GRMH_FAIL_JMP;

	/* Get handles to all the modules in the target process */
	if(!EnumProcessModulesEx(hProcess, ModuleArray,
	        ModuleArraySize * sizeof(HMODULE), &NumModules, LIST_MODULES_ALL)) {
		printf("GetRemoteModuleHandle err %d\n", GetLastError());
		goto GRMH_FAIL_JMP;
	}

	/* We want the number of modules not the number of bytes */
	NumModules /= sizeof(HMODULE);

	/* Did we allocate enough memory for all the module handles? */
	if(NumModules > ModuleArraySize) {
		free(ModuleArray); // Deallocate so we can try again
		ModuleArray = NULL; // Set it to NULL se we can be sure if the next try fails
		ModuleArray = (HMODULE *) malloc(sizeof(HMODULE) * NumModules); // new HMODULE[NumModules]; // Allocate the right amount of memory

		/* Check if the allocation failed */
		if(ModuleArray == NULL)
			goto GRMH_FAIL_JMP;

		ModuleArraySize = NumModules; // Update the size of the array

		/* Get handles to all the modules in the target process */
		if( !EnumProcessModulesEx(hProcess, ModuleArray,
		        ModuleArraySize * sizeof(HMODULE), &NumModules, LIST_MODULES_ALL) )
			goto GRMH_FAIL_JMP;

		/* We want the number of modules not the number of bytes */
		NumModules /= sizeof(HMODULE);
	}

	/* Iterate through all the modules and see if the names match the one we are looking for */
	for(DWORD i = 0; i <= NumModules; ++i) {
		/* Get the module's name */
		GetModuleBaseName(hProcess, ModuleArray[i],
		    ModuleNameBuffer, sizeof(ModuleNameBuffer));

		/* Convert ModuleNameBuffer to all lowercase so the comparison isn't case sensitive */
		for (size_t j = 0; ModuleNameBuffer[j] != '\0'; ++j) {
			if (ModuleNameBuffer[j] >= 'A' && ModuleNameBuffer[j] <= 'Z')
				ModuleNameBuffer[j] += 0x20; // 0x20 is the difference between uppercase and lowercase
		}

		/* Does the name match? */
		if(strstr(ModuleNameBuffer, lpModuleNameCopy) != NULL) {
			/* Make a temporary variable to hold return value*/
			HMODULE TempReturn = ModuleArray[i];

			/* Give back that memory */
			free(ModuleArray);

			/* Success */
			return TempReturn;
		}

		/* Wrong module let's try the next... */
	}

	/* Uh Oh... */
	GRMH_FAIL_JMP:

	/* If we got to the point where we allocated memory we need to give it back */
	if(ModuleArray != NULL)
		free(ModuleArray);

	/* Failure... */
	return NULL;
}

FARPROC WINAPI
GetRemoteProcAddress (HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName, UINT Ordinal, BOOL UseOrdinal)
{
	BOOL Is64Bit = FALSE;
	MODULEINFO RemoteModuleInfo = {0};
	UINT_PTR RemoteModuleBaseVA = 0;
	IMAGE_DOS_HEADER DosHeader = {0};
	DWORD Signature = 0;
	IMAGE_FILE_HEADER FileHeader = {0};
	IMAGE_OPTIONAL_HEADER64 OptHeader64 = {0};
	IMAGE_OPTIONAL_HEADER32 OptHeader32 = {0};
	IMAGE_DATA_DIRECTORY ExportDirectory = {0};
	IMAGE_EXPORT_DIRECTORY ExportTable = {0};
	UINT_PTR ExportFunctionTableVA = 0;
	UINT_PTR ExportNameTableVA = 0;
	UINT_PTR ExportOrdinalTableVA = 0;
	DWORD* ExportFunctionTable = NULL;
	DWORD* ExportNameTable = NULL;
	WORD* ExportOrdinalTable = NULL;

	/* Temporary variables not used until much later but easier
	/* to define here than in all the the places they are used */
	CHAR TempChar;
	BOOL Done = FALSE;

	/* Check to make sure we didn't get a NULL pointer for the name unless we are searching by ordinal */
	if(lpProcName == NULL && !UseOrdinal)
		goto GRPA_FAIL_JMP;

	/* Get the base address of the remote module along with some other info we don't need */
	if(!GetModuleInformation(hProcess, hModule,&RemoteModuleInfo, sizeof(RemoteModuleInfo)))
		goto GRPA_FAIL_JMP;
	RemoteModuleBaseVA	= (UINT_PTR)RemoteModuleInfo.lpBaseOfDll;

	/* Read the DOS header and check it's magic number */
	if(!ReadProcessMemory(hProcess, (LPCVOID)RemoteModuleBaseVA, &DosHeader,
	        sizeof(DosHeader), NULL) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		goto GRPA_FAIL_JMP;

	/* Read and check the NT signature */
	if(!ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew),
	        &Signature, sizeof(Signature), NULL) || Signature != IMAGE_NT_SIGNATURE)
		goto GRPA_FAIL_JMP;

	/* Read the main header */
	if(!ReadProcessMemory(hProcess,
	        (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature)),
	        &FileHeader, sizeof(FileHeader), NULL))
		goto GRPA_FAIL_JMP;

	/* Which type of optional header is the right size? */
	if(FileHeader.SizeOfOptionalHeader == sizeof(OptHeader64))
		Is64Bit = TRUE;
	else if(FileHeader.SizeOfOptionalHeader == sizeof(OptHeader32))
		Is64Bit = FALSE;
	else
		goto GRPA_FAIL_JMP;

	if(Is64Bit) {
		/* Read the optional header and check it's magic number */
		if(!ReadProcessMemory(hProcess,
		        (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)),
		        &OptHeader64, FileHeader.SizeOfOptionalHeader, NULL)
		    || OptHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			goto GRPA_FAIL_JMP;
	} else {
		/* Read the optional header and check it's magic number */
		if(!ReadProcessMemory(hProcess,
		        (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)),
		        &OptHeader32, FileHeader.SizeOfOptionalHeader, NULL)
		    || OptHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			goto GRPA_FAIL_JMP;
	}

	/* Make sure the remote module has an export directory and if it does save it's relative address and size */
	if(Is64Bit && OptHeader64.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1) {
		ExportDirectory.VirtualAddress = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
		ExportDirectory.Size = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
	} else if(OptHeader32.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1) {
		ExportDirectory.VirtualAddress = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
		ExportDirectory.Size = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
	} else
		goto GRPA_FAIL_JMP;

	/* Read the main export table */
	if(!ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportDirectory.VirtualAddress),
	        &ExportTable, sizeof(ExportTable), NULL))
		goto GRPA_FAIL_JMP;

	/* Save the absolute address of the tables so we don't need to keep adding the base address */
	ExportFunctionTableVA = RemoteModuleBaseVA + ExportTable.AddressOfFunctions;
	ExportNameTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNames;
	ExportOrdinalTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNameOrdinals;

	/* Allocate memory for our copy of the tables */
	ExportFunctionTable	= (DWORD *) malloc(sizeof(DWORD) * ExportTable.NumberOfFunctions);// new DWORD[ExportTable.NumberOfFunctions];
	ExportNameTable		= (DWORD *) malloc(sizeof(DWORD) * ExportTable.NumberOfNames);//new DWORD[ExportTable.NumberOfNames];
	ExportOrdinalTable	= (WORD *) malloc(sizeof(WORD) * ExportTable.NumberOfNames);//new WORD[ExportTable.NumberOfNames];

	/* Check if the allocation failed */
	if(ExportFunctionTable == NULL || ExportNameTable == NULL || ExportOrdinalTable == NULL)
		goto GRPA_FAIL_JMP;

	/* Get a copy of the function table */
	if(!ReadProcessMemory(hProcess, (LPCVOID)ExportFunctionTableVA,
	        ExportFunctionTable, ExportTable.NumberOfFunctions * sizeof(DWORD), NULL))
		goto GRPA_FAIL_JMP;

	/* Get a copy of the name table */
	if(!ReadProcessMemory(hProcess, (LPCVOID)ExportNameTableVA,
	        ExportNameTable, ExportTable.NumberOfNames * sizeof(DWORD), NULL))
		goto GRPA_FAIL_JMP;

	/* Get a copy of the ordinal table */
	if(!ReadProcessMemory(hProcess, (LPCVOID)ExportOrdinalTableVA,
	        ExportOrdinalTable, ExportTable.NumberOfNames * sizeof(WORD), NULL))
		goto GRPA_FAIL_JMP;

	/* If we are searching for an ordinal we do that now */
	if(UseOrdinal) {
		/* NOTE:
		/* Microsoft's PE/COFF specification does NOT say we need to subtract the ordinal base
		/* from our ordinal but it seems to always give the wrong function if we don't */

		/* Make sure the ordinal is valid */
		if(Ordinal < ExportTable.Base || (Ordinal - ExportTable.Base) >= ExportTable.NumberOfFunctions)
			goto GRPA_FAIL_JMP;

		UINT FunctionTableIndex = Ordinal - ExportTable.Base;

		/* Check if the function is forwarded and if so get the real address*/
		if(ExportFunctionTable[FunctionTableIndex] >= ExportDirectory.VirtualAddress &&
		    ExportFunctionTable[FunctionTableIndex] <= ExportDirectory.VirtualAddress + ExportDirectory.Size) {
			Done = FALSE;
			char TempForwardString[MAX_SYM_NAME];
			int len = 0;
			//TempForwardString.clear(); // Empty the string so we can fill it with a new name

			/* Get the forwarder string one character at a time because we don't know how long it is */
			for(UINT_PTR i = 0; !Done; ++i) {
				/* Get next character */
				if(!ReadProcessMemory(hProcess,
				        (LPCVOID)(RemoteModuleBaseVA + ExportFunctionTable[FunctionTableIndex] + i),
				        &TempChar, sizeof(TempChar), NULL))
					goto GRPA_FAIL_JMP;

				TempForwardString[len++] = TempChar; // Add it to the string

				/* If it's NUL we are done */
				if(TempChar == (CHAR)'\0')
					Done = TRUE;
			}

			/* Find the dot that seperates the module name and the function name/ordinal */
			//size_t Dot = TempForwardString.find('.');
			char *cfnd = strchr(TempForwardString, '.');
			if(cfnd == NULL)
				goto GRPA_FAIL_JMP;

			/* Temporary variables that hold parts of the forwarder string */
			char *RealModuleName, *RealFunctionId;
			*cfnd = '\0';
			//RealModuleName = TempForwardString.substr(0, Dot - 1);
			//RealFunctionId = TempForwardString.substr(Dot + 1, stringnpos);
			RealModuleName = TempForwardString;
			RealFunctionId = ++cfnd;

			HMODULE RealModule = GetRemoteModuleHandle(hProcess, RealModuleName);
			FARPROC TempReturn;// Make a temporary variable to hold return value

			/* Figure out if the function was exported by name or by ordinal */
			if(RealFunctionId[0] == '#') { // Exported by ordinal
				UINT RealOrdinal = 0;
				//RealFunctionId.erase(0, 1); // Remove '#' from string
				RealFunctionId++;
				/* My version of atoi() because I was too lazy to use the real one... */
				for(size_t i = 0; i < strlen(RealFunctionId); ++i) {
					if(RealFunctionId[i] >= '0' && RealFunctionId[i] <= '9') {
						RealOrdinal *= 10;
						RealOrdinal += RealFunctionId[i] - '0';
					} else
						break;
				}

				/* Recursively call this function to get return value */
				TempReturn = GetRemoteProcAddress(hProcess, RealModule, NULL, RealOrdinal, TRUE);
			} else { // Exported by name
				/* Recursively call this function to get return value */
				TempReturn = GetRemoteProcAddress(hProcess, RealModule, RealFunctionId, 0, FALSE);
			}

			/* Give back that memory */
			free(ExportFunctionTable); //delete[] ExportFunctionTable;
			free(ExportNameTable); //delete[] ExportNameTable;
			free(ExportOrdinalTable); //delete[] ExportOrdinalTable;

			/* Success!!! */
			return TempReturn;
		} else { // Not Forwarded

			/* Make a temporary variable to hold return value*/
			FARPROC TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[FunctionTableIndex]);

			/* Give back that memory */
			free(ExportFunctionTable); //delete[] ExportFunctionTable;
			free(ExportNameTable); //delete[] ExportNameTable;
			free(ExportOrdinalTable); //delete[] ExportOrdinalTable;

			/* Success!!! */
			return TempReturn;
		}
	}

	/* Iterate through all the names and see if they match the one we are looking for */
	for(DWORD i = 0; i < ExportTable.NumberOfNames; ++i)	{
		char TempFunctionName[MAX_SYM_NAME] = {0};
		int len = 0;

		Done = FALSE;// Reset for next name
		//TempFunctionName.clear(); // Empty the string so we can fill it with a new name

		/* Get the function name one character at a time because we don't know how long it is */
		for(UINT_PTR j = 0; !Done; ++j) {
			/* Get next character */
			if(!ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportNameTable[i] + j),
			        &TempChar, sizeof(TempChar), NULL))
				goto GRPA_FAIL_JMP;

			TempFunctionName[len++] = TempChar; // Add it to the string

			/* If it's NUL we are done */
			if(TempChar == (CHAR)'\0')
				Done = TRUE;
		}

		/* Does the name match? */
		//if(TempFunctionName.find(lpProcName) != stringnpos) {
		if (strstr(TempFunctionName, lpProcName) != NULL) {
			/* NOTE:
			/* Microsoft's PE/COFF specification says we need to subtract the ordinal base
			/*from the value in the ordinal table but that seems to always give the wrong function */

			/* Check if the function is forwarded and if so get the real address*/
			if(ExportFunctionTable[ExportOrdinalTable[i]] >= ExportDirectory.VirtualAddress &&
			    ExportFunctionTable[ExportOrdinalTable[i]] <= ExportDirectory.VirtualAddress + ExportDirectory.Size) {
				Done = FALSE;
				char TempForwardString[MAX_SYM_NAME] = {0};
				int lenf = 0;
				//TempForwardString.clear(); // Empty the string so we can fill it with a new name

				/* Get the forwarder string one character at a time because we don't know how long it is */
				for(UINT_PTR j = 0; !Done; ++j) {
					/* Get next character */
					if(!ReadProcessMemory(hProcess,
					        (LPCVOID)(RemoteModuleBaseVA + ExportFunctionTable[i] + j),
					        &TempChar, sizeof(TempChar), NULL))
						goto GRPA_FAIL_JMP;

					//TempForwardString.push_back(TempChar); // Add it to the string
					TempForwardString[lenf++] = TempChar;
					/* If it's NUL we are done */
					if(TempChar == (CHAR)'\0')
						Done = TRUE;
				}

				/* Find the dot that seperates the module name and the function name/ordinal */
				//size_t Dot = TempForwardString.find('.');
				char *cfnd = strchr(TempForwardString, '.');
				if(cfnd == NULL)
					goto GRPA_FAIL_JMP;

				/* Temporary variables that hold parts of the forwarder string */
				char *RealModuleName, *RealFunctionId;
				*cfnd = '\0';
				//RealModuleName = TempForwardString.substr(0, Dot);
				//RealFunctionId = TempForwardString.substr(Dot + 1, stringnpos);
				RealModuleName = TempForwardString;
				RealFunctionId = ++cfnd;

				HMODULE RealModule = GetRemoteModuleHandle(hProcess, RealModuleName);
				FARPROC TempReturn;// Make a temporary variable to hold return value


				/* Figure out if the function was exported by name or by ordinal */
				if(RealFunctionId[0] == '#') { // Exported by ordinal
					UINT RealOrdinal = 0;
					//RealFunctionId.erase(0, 1); // Remove '#' from string
					RealFunctionId++;
					/* My version of atoi() because I was to lazy to use the real one... */
					for(size_t i = 0; i < strlen(RealFunctionId); ++i) {
						if(RealFunctionId[i] >= '0' && RealFunctionId[i] <= '9') {
							RealOrdinal *= 10;
							RealOrdinal += RealFunctionId[i] - '0';
						} else
							break;
					}

					/* Recursively call this function to get return value */
					TempReturn = GetRemoteProcAddress(hProcess, RealModule, NULL, RealOrdinal, TRUE);
				} else { // Exported by name
					/* Recursively call this function to get return value */
					TempReturn = GetRemoteProcAddress(hProcess, RealModule, RealFunctionId, 0, FALSE);
				}

				/* Give back that memory */
				free(ExportFunctionTable);
				free(ExportNameTable);
				free(ExportOrdinalTable);

				/* Success!!! */
				return TempReturn;
			} else { // Not Forwarded

				/* Make a temporary variable to hold return value*/
				FARPROC TempReturn;

				/* NOTE:
				/* Microsoft's PE/COFF specification says we need to subtract the ordinal base
				/*from the value in the ordinal table but that seems to always give the wrong function */
				//TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i] - ExportTable.Base]);

				/* So we do it this way instead */
				TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i]]);

				/* Give back that memory */
				free(ExportFunctionTable);
				free(ExportNameTable);
				free(ExportOrdinalTable);

				/* Success!!! */
				return TempReturn;
			}
		}

		/* Wrong function let's try the next... */
	}

	/* Uh Oh... */
	GRPA_FAIL_JMP:

	/* If we got to the point where we allocated memory we need to give it back */
	if(ExportFunctionTable != NULL)
		free(ExportFunctionTable);
	if(ExportNameTable != NULL)
		free(ExportNameTable);
	if(ExportOrdinalTable != NULL)
		free(ExportOrdinalTable);

	/* Falure... */
	return NULL;
}
#endif