//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>

int  call_1(int d)
{
	int i;
	i = 1000;

	return 0;
}

void call_2(void)
{
	int i = 9;
	i = i + 6;
}
void call_3(void)
{
	int i = 9;
	i = i + 6;
}

int main()
{
	int i = 0;
	printf("PID %d\n", GetCurrentProcessId());
	while(1) {
		call_1(1);
		Sleep(1000);
		call_2();
		Sleep(1000);
		call_3();
		Sleep(1000);

		i++;
	}

	return 0;
}