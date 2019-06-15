#include <stdio.h>

char *s0 = "Hello World";
wchar_t *ws0 = L"Hello World";

wchar_t *str(char *s, wchar_t *ws)
{
	printf("%s %S\r", s, ws);
	return ws0;
}

int args(int a, int b, int c, int d, int e)
{
	int f;
	f = a + b + c + d + e;

	return f;
}

int main()
{
	int r, l = 1;

	while(l) {
		str(s0, ws0);
		r = args(1,2,3,4,5);
		l--;
	}

	return 0;
}