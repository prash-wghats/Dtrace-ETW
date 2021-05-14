//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c
#if 0
// thread example
#include <iostream>       // std::cout
#include <thread>         // std::thread


#define LOOPS 100
#define MAX_THREADS 10


int icall1 = 0, icall2 = 0, icall3 = 0;
int
call_1(int d)
{
	int i;
	i = 1000;
	//Sleep(i);

	//printf("call_10\n");
	return 0;
}

void
call_2(void)
{

	//Sleep(1030);
	int i = 9;
	i = i + 6;
	
	//printf("call_2\n");
}
void
call_3(void)
{
	//Sleep(100);
	//printf("call_3\n");
	int i = 9;
	i = i + 6;
	
}
void
foo()
{
	// do stuff...
}

void
bar(int x)
{
	int i = LOOPS;

	while(i) {
		call_1(0);
		call_2();
		call_3();
		i--;
	}
}

int
main()
{
	std::thread *threads[MAX_THREADS];
	for (int i = 0; i < MAX_THREADS; i++) {
		threads[i] = new std::thread(bar, 0);
	}


	std::cout << "main, foo and bar now execute concurrently...\n";

	// synchronize threads:
	for (int i = 0; i < MAX_THREADS; i++) {
		threads[i]->join();
	}

	std::cout << "foo and bar completed.\n";

	return 0;
}
#endif
#if 1
#include <stdio.h>
#include <windows.h>

#define LOOPS 1000
#define MAX_THREADS 1

int icall1 = 0, icall2 = 0, icall3 = 0;
int
call_1(int d)
{
	InterlockedIncrement(&icall1);

	return d;
}

void
call_2(void)
{
	int i = 9;
	i = i + 6;
	InterlockedIncrement(&icall2);
}

void
call_3(void)
{
	int i = 9;
	i = i + 6;
	InterlockedIncrement(&icall3);
}

DWORD WINAPI
MyThreadFunction( LPVOID lpParam )
{
	int i = LOOPS;
	int j = (int) lpParam;
	while(i) {
		//if (j == 0)
			call_1(1);
		//if (j == 1)
			call_2();
		//if (j > 1)
			call_3();
		i--;
	}
}



int
main()
{
	int i = LOOPS, j = 0;
	HANDLE  hThreadArray[MAX_THREADS];
	DWORD   dwThreadIdArray[MAX_THREADS];
	printf("t_c_eloop : main tid %d\n", GetCurrentThreadId());
	for( int i = 0; i < MAX_THREADS; i++ ) {
		hThreadArray[i] =	CreateThread(
		    NULL,                   // default security attributes
		    0,                      // use default stack size
		    MyThreadFunction,       // thread function name
		    j++,          // argument to thread function
		    0,                      // use default creation flags
		    &dwThreadIdArray[i]);   // returns the thread identifier
		printf("t_c_eloop : tid %d\n", GetThreadId(hThreadArray[i]));
	}
	printf("\n");
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

	for(int i = 0; i < MAX_THREADS; i++) {
		CloseHandle(hThreadArray[i]);
	}

	fprintf(stderr, "t_c_eloop : call_1 %d call_2 %d call_3 %d\n", icall1, icall2, icall3);
	return 0;
}
#endif