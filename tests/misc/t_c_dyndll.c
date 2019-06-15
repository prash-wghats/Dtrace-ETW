//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

//cl /DMAIN /Zi ..\..\internal\loopsdll.c
//cl /DLOOPSDLL0 /LD /Zi ..\..\internal\loopsdll.c /link /out:loopsdll0.dll ???



#if defined(MAIN)

#define LOOPS 1000
#define MAX_THREADS 4


int  loopsdll_1(int d)
{
	int i;
	i = 1000;
	//Sleep(i);

	//printf("call_10\n");
	return 0;
}

void call_2(void)
{

	//Sleep(1030);
	int i = 9;
	i = i + 6;
	//printf("call_2\n");
}
void call_3(void)
{
	//Sleep(100);
	//printf("call_3\n");
	int i = 9;
	i = i + 6;

}

typedef int (*funcptr)();
DWORD WINAPI MyThreadFunction( LPVOID lpParam )
{
	int i = (int) lpParam;
	int j = LOOPS;
	HINSTANCE dll;
	funcptr fptr;
	
	if (i == 0) {

		dll = LoadLibrary("t_c_dyndll0.dll");
		fptr = (funcptr) GetProcAddress(dll, "loopsdll0");
		//Sleep(2000);
	} else if (i == 1) {
		dll = LoadLibrary("t_c_dyndll1.dll");
		fptr = (funcptr) GetProcAddress(dll, "loopsdll1");
	} else if (i == 2) {
		dll = LoadLibrary("t_c_dyndll2.dll");
		fptr = (funcptr) GetProcAddress(dll, "loopsdll2");
	} else if (i == 3) {
		dll = (funcptr) LoadLibrary("t_c_dyndll3.dll");
		fptr = (funcptr)  GetProcAddress(dll, "loopsdll3");
	}
	printf("dll %p fptr %p %d i\n", dll, fptr, i);
	
	while (j--) {
			fptr();
		}
	return 0;
}



int main()
{
	int i = LOOPS;
	HANDLE  hThreadArray[MAX_THREADS];
	DWORD   dwThreadIdArray[MAX_THREADS];
	for( int i=0; i<MAX_THREADS; i++ ) {
		hThreadArray[i] =	CreateThread(
		        NULL,                   // default security attributes
		        0,                      // use default stack size
		        MyThreadFunction,       // thread function name
		        i,          // argument to thread function
		        0,                      // use default creation flags
		        &dwThreadIdArray[i]);   // returns the thread identifier
	}

	while(i) {
		loopsdll_1(1);
		//Sleep(1000);
		call_2();
		//Sleep(1000);
		call_3();
		//Sleep(1000);
		i--;
	}

	WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

	// Close all thread handles and free memory allocations.

	for(int i=0; i<MAX_THREADS; i++) {
		CloseHandle(hThreadArray[i]);
	}
	return 0;
}

#endif

#if defined(LOOPSDLL0)

__declspec(dllexport) int loopsdll0()
{
	int a = 0, b = 1;
	a = b + 4;
	
	return a;
}

#endif

#if defined(LOOPSDLL1)

__declspec(dllexport) int loopsdll1()
{
	int a = 0, b = 1;
	a = b + 4;
	
	return a;
}

#endif

#if defined(LOOPSDLL2)

__declspec(dllexport) int loopsdll2()
{
	int a = 0, b = 1;
	a = b + 4;
	
	return a;
}

#endif

#if defined(LOOPSDLL3)

__declspec(dllexport) int loopsdll3()
{
	int a = 0, b = 1;
	a = b + 4;
	
	return a;
}

#endif