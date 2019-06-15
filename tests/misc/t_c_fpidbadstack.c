//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

#define LOOPS 1000
#define MAX_THREADS 5

void call_3(void)
{
	//Sleep(100);
	//printf("call_3\n");
	int i = 9;
	i = i + 6;

}

void call_2(void)
{
	call_3();
	//Sleep(1030);
	int i = 9;
	i = i + 6;
	
	//printf("call_2\n");
}


int  call_1(int d)
{
	int i;
	i = 1000;
	//Sleep(i);
	call_2();
	//printf("call_10\n");
	return 0;
}

int main()
{
	int i = 2;
	

	while(i) {
		call_1(1);
		//Sleep(1000);
		call_2();
		//Sleep(1000);
		call_3();
		//Sleep(1000);
		i--;
	}


	return 0;
}