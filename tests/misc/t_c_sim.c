//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

#define LOOPS 2

void call_3(void)
{
	int i = 9;
	i = i + 6;

}

void call_2(void)
{
	int i = 9;
	i = i + 6;
	call_3();
}


int  call_1(int d)
{
	int i;
	i = 1000;

	call_2();
	return 0;
}

int main()
{
	int i = LOOPS;
	

	while(i) {
		call_1(1);
		call_2();
		call_3();
		i--;
	}


	return 0;
}