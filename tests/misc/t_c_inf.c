//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

#define LOOPS 0



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
	printf("PID %d\n", GetCurrentProcessId());
	
	while(1) {
		call_1(1);
		Sleep(1000);
		call_2();
		Sleep(1000);
		call_3();
		Sleep(1000);
		printf("%d\r", i);
		i++;
	}
}

#define MAX_THREADS 10

int main()
{
	int i = LOOPS;
	printf("PID %d\n", GetCurrentProcessId());
	while(1) {
		call_1(1);
		Sleep(1000);
		call_2();
		Sleep(1000);
		call_3();
		Sleep(1000);
		printf("%d\r", i);
		i++;
	}

	
	return 0;
}