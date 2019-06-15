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


#define SLOW 300
#define FAST 1
int main()
{
	int i = 10;
	

	while(i) {
		call_1(1);
		Sleep(SLOW);
		call_2();
		Sleep(SLOW);
		call_3();
		Sleep(SLOW);
		i--;
	}
	printf("FAST");

	i = 10000;
	while(i) {
		call_1(1);
		//Sleep(FAST);
		call_2();
		//Sleep(FAST);
		call_3();
		//Sleep(FAST);
		i--;
	}
	printf("DONE");
	return 0;
}