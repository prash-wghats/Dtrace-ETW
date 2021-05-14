//.\debug\amd64\bin\dtrace.exe -s .\tests\misc\t_user_ctf.d -c .\debug\amd64\obj\t_c_sim.exe

#include <stdio.h>
#include <windows.h>

#define LOOPS 2

typedef struct dummy_struct {
	int arr[2][2][3];
	char ca[20];
	float f;
	double dd;
	short sh;
	char c;
} dummy_struct_t;

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

int dummyfunc(char *dummy)
{
	return 0;
}
int arrayfunc(int arr[1][2][3], dummy_struct_t *dummys)
{
	return 0;
}

int main()
{
	int i = LOOPS;
	char buffer[4096] = {0};
	int arr[2][2][3] = {
		{{1,2,3}, {4,5,6}},
		{{1,2,3}, {4,5,6}}
	};
	dummy_struct_t st = {
		{
		{{1,2,3}, {4,5,6}},
		{{1,2,3}, {4,5,6}}
	}, "hello world", 9.9, 99.9, 1024, 'c'
	};
	while(i) {
		call_1(1);
		call_2();
		call_3();
		i--;
	}

	dummyfunc(buffer);
	arrayfunc(arr, &st);

	Sleep(100);

	return 0;
}