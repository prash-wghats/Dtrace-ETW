#include <stdio.h>

struct magic;
typedef struct magic {
	int a;
	int b;
	int d;
	char *h;
	char f[10];
	wchar_t c[10];
} magic_t;

typedef struct foo {
        struct foo *foo_next;
        int foo_value;
} foo_t;

int magic_func(magic_t *mag)
{
	return 0;
}
void print_head(foo_t *mad)
{
	return;
}

int main()
{
	struct magic mag = {3, 4, 5, "initialize", "Hello", L"Hello"};
	foo_t a, b,c;
	a.foo_value = 1;
	b.foo_value = 2;
	c.foo_value = 3;
	a.foo_next = &b;
	b.foo_next = &c;
	c.foo_next = 0;
	
	print_head(&a);
	magic_func(&mag);
	
	return 0;
}