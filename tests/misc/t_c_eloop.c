//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

#define LOOPS 1000
#define MAX_THREADS 5


int  call_1(int d)
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

DWORD WINAPI MyThreadFunction( LPVOID lpParam )
{
	int i = LOOPS;
	while(i) {
		call_1(1);
		//Sleep(1000);
		call_2();
		//Sleep(1000);
		call_3();
		//Sleep(1000);
		i--;
	}
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
		        NULL,          // argument to thread function
		        0,                      // use default creation flags
		        &dwThreadIdArray[i]);   // returns the thread identifier
	}

	while(i) {
		call_1(1);
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