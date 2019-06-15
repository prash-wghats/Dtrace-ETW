//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

#define LOOPS 10000
#define MAX_THREADS 50
#define SLEEP 100

ULONG c1, c2, c3;

int  call_1(int d)
{
	int i;
	i = 1000;
	//Sleep(SLEEP);
	InterlockedIncrement(&c1);
	//printf("call_10\r");
	return 0;
}

void call_2(void)
{

	//Sleep(SLEEP);
	int i = 9;
	i = i + 6;
	//printf("call_2\r");
	InterlockedIncrement(&c2);
}
void call_3(void)
{
	//Sleep(SLEEP);
	//printf("call_3\r");
	int i = 9;
	i = i + 6;
	InterlockedIncrement(&c3);
}

DWORD WINAPI MyThreadFunction( LPVOID lpParam )
{
	int i = LOOPS;
	while(i) {
		call_1(1);
		//Sleep(SLEEP);
		call_2();
		//Sleep(SLEEP);
		call_3();
		//Sleep(SLEEP);
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
		//Sleep(SLEEP);
		call_2();
		//Sleep(SLEEP);
		call_3();
		//Sleep(SLEEP);
		i--;
	}

	WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

	// Close all thread handles and free memory allocations.

	for(int i=0; i<MAX_THREADS; i++) {
		CloseHandle(hThreadArray[i]);
	}
	printf("call_1 %d call_2 %d call_3 %d\n", c1, c2, c3);
	return 0;
}